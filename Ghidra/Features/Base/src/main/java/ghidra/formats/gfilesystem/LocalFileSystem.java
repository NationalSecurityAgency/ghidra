/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.formats.gfilesystem;

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.*;
import java.nio.file.*;
import java.util.*;

import org.apache.commons.collections4.map.ReferenceMap;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.FileByteProvider;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemFactory;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryIgnore;
import ghidra.formats.gfilesystem.fileinfo.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link GFileSystem} implementation giving access to the user's operating system's
 * local file system.
 * <p>
 * This implementation does not have a {@link GFileSystemFactory} as
 * this class will be used as the single root filesystem.
 * <p>
 * Closing() this filesystem does nothing.
 */
@FileSystemInfo(type = LocalFileSystem.FSTYPE, description = "Local filesystem", factory = GFileSystemFactoryIgnore.class)
public class LocalFileSystem implements GFileSystem, GFileHashProvider {
	public static final String FSTYPE = "file";

	/**
	 * Create a new instance
	 *
	 * @return new {@link LocalFileSystem} instance using {@link #FSTYPE} as its FSRL type.
	 */
	public static LocalFileSystem makeGlobalRootFS() {
		return new LocalFileSystem(FSRLRoot.makeRoot(FSTYPE));
	}

	private final List<GFile> emptyDir = List.of();
	private final FSRLRoot fsFSRL;
	private final FileSystemRefManager refManager = new FileSystemRefManager(this);
	private final ReferenceMap<FileFingerprintRec, String> fileFingerprintToMD5Map =
		new ReferenceMap<>();

	private LocalFileSystem(FSRLRoot fsrl) {
		this.fsFSRL = fsrl;
	}

	boolean isSameFS(FSRL fsrl) {
		return fsFSRL.equals(fsrl.getFS());
	}

	/**
	 * Creates a new file system instance that is a sub-view limited to the specified directory.
	 * 
	 * @param fsrl {@link FSRL} that must be a directory in this local filesystem 
	 * @return new {@link LocalFileSystemSub} instance
	 * @throws IOException if bad FSRL
	 */
	public LocalFileSystemSub getSubFileSystem(FSRL fsrl) throws IOException {
		if (isLocalSubdir(fsrl)) {
			File localDir = getLocalFile(fsrl);
			return new LocalFileSystemSub(localDir, this);
		}
		return null;
	}

	/**
	 * Returns true if the {@link FSRL} is a local filesystem subdirectory.
	 *
	 * @param fsrl {@link FSRL} to test.
	 * @return boolean true if local filesystem directory.
	 */
	public boolean isLocalSubdir(FSRL fsrl) {
		if (!isSameFS(fsrl)) {
			return false;
		}
		File localFile = new File(fsrl.getPath());
		return localFile.isDirectory();
	}

	/**
	 * Convert a FSRL that points to this file system into a java {@link File}.
	 * 
	 * @param fsrl {@link FSRL}
	 * @return {@link File}
	 * @throws IOException if FSRL does not point to this file system
	 */
	public File getLocalFile(FSRL fsrl) throws IOException {
		if (!isSameFS(fsrl)) {
			throw new IOException("FSRL does not specify local file: " + fsrl);
		}
		File localFile = new File(fsrl.getPath());
		return localFile;
	}

	/**
	 * Converts a {@link File} into a {@link FSRL}.
	 * <p>
	 * NOTE: The given {@link File}'s absolute path will be used.
	 * 
	 * @param f The {@link File} to convert to an {@link FSRL}
	 * @return The {@link FSRL}
	 */
	public FSRL getLocalFSRL(File f) {
		return fsFSRL.withPath(FSUtilities.normalizeNativePath(f.getAbsolutePath()));
	}

	@Override
	public String getName() {
		return "Root Filesystem";
	}

	@Override
	public void close() {
		// nada
	}

	@Override
	public boolean isStatic() {
		return false;
	}

	@Override
	public List<GFile> getListing(GFile directory) {
		List<GFile> results = new ArrayList<>();

		if (directory == null) {
			for (File f : File.listRoots()) {
				FSRL rootElemFSRL = fsFSRL.withPath(FSUtilities.normalizeNativePath(f.getName()));
				results.add(GFileImpl.fromFSRL(this, null, rootElemFSRL, f.isDirectory(), -1));
			}
		}
		else {
			File localDir = new File(directory.getPath());
			if (!localDir.isDirectory() || Files.isSymbolicLink(localDir.toPath())) {
				return emptyDir;
			}

			File[] files = localDir.listFiles();
			if (files == null) {
				return emptyDir;
			}

			for (File f : files) {
				if (f.isFile() || f.isDirectory()) {
					FSRL newFileFSRL = directory.getFSRL().appendPath(f.getName());
					results.add(GFileImpl.fromFSRL(this, directory, newFileFSRL, f.isDirectory(),
						f.length()));
				}
			}
		}

		return results;
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		File f = new File(file.getPath());
		return getFileAttributes(f);
	}

	/**
	 * Create a {@link FileAttributes} container with info about the specified local file.
	 * 
	 * @param f {@link File} to query
	 * @return {@link FileAttributes} instance
	 */
	public FileAttributes getFileAttributes(File f) {
		Path p = f.toPath();
		FileType fileType = fileToFileType(p);
		Path symLinkDest = null;
		try {
			symLinkDest = fileType == FileType.SYMBOLIC_LINK ? Files.readSymbolicLink(p) : null;
		}
		catch (IOException e) {
			// ignore and continue with symLinkDest == null
		}
		return FileAttributes.of(
			FileAttribute.create(NAME_ATTR, f.getName()),
			FileAttribute.create(FILE_TYPE_ATTR, fileType),
			FileAttribute.create(SIZE_ATTR, f.length()),
			FileAttribute.create(MODIFIED_DATE_ATTR, new Date(f.lastModified())),
			symLinkDest != null
					? FileAttribute.create(SYMLINK_DEST_ATTR, symLinkDest.toString())
					: null);
	}

	private static FileType fileToFileType(Path p) {
		if (Files.isSymbolicLink(p)) {
			return FileType.SYMBOLIC_LINK;
		}
		if (Files.isDirectory(p)) {
			return FileType.DIRECTORY;
		}
		if (Files.isRegularFile(p)) {
			return FileType.FILE;
		}
		return FileType.UNKNOWN;
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsFSRL;
	}

	@Override
	public GFile lookup(String path) throws IOException {
		File f = lookupFile(null, path, null);
		return f != null ? GFileImpl.fromPathString(this,
			FSUtilities.normalizeNativePath(f.getPath()), null, f.isDirectory(), f.length()) : null;
	}

	@Override
	public boolean isClosed() {
		return false;
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}

	@Override
	public InputStream getInputStream(GFile file, TaskMonitor monitor) throws IOException {
		return getInputStream(file.getFSRL(), monitor);
	}

	InputStream getInputStream(FSRL fsrl, TaskMonitor monitor) throws IOException {
		return new FileInputStream(getLocalFile(fsrl));
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) throws IOException {
		return getByteProvider(file.getFSRL(), monitor);
	}

	ByteProvider getByteProvider(FSRL fsrl, TaskMonitor monitor) throws IOException {
		File f = getLocalFile(fsrl);
		return new FileByteProvider(f, fsrl, AccessMode.READ);
	}

	@Override
	public String toString() {
		return "Local file system " + fsFSRL;
	}

	@Override
	public String getMD5Hash(GFile file, boolean required, TaskMonitor monitor)
			throws CancelledException, IOException {
		return getMD5Hash(file.getFSRL(), required, monitor);
	}

	synchronized String getMD5Hash(FSRL fsrl, boolean required, TaskMonitor monitor)
			throws CancelledException, IOException {
		File f = getLocalFile(fsrl);
		if ( !f.isFile() ) {
			return null;
		}
		
		FileFingerprintRec fileFingerprintRec = new FileFingerprintRec(f.getPath(), f.lastModified(), f.length());
		String md5 = fileFingerprintToMD5Map.get(fileFingerprintRec);
		if (md5 == null && required) {
			md5 = FSUtilities.getFileMD5(f, monitor);
			fileFingerprintToMD5Map.put(fileFingerprintRec, md5);
		}
		
		return md5;
	}

	//-----------------------------------------------------------------------------------

	private record FileFingerprintRec(String path, long timestamp, long length) {
	}

	//--------------------------------------------------------------------------------------------
	/**
	 * Looks up a file, by its string path, using a custom comparator.
	 * <p>
	 * If any element of the path, or the filename are not found, returns a null.
	 * <p>
	 * A null custom comparator avoids testing each element of the directory path and instead
	 * relies on the native local file system's name matching.
	 * 
	 * @param baseDir optional directory to start lookup at 
	 * @param path String path
	 * @param nameComp optional {@link Comparator} that will compare filenames, or {@code null} 
	 * to use native local file system lookup (eg. case-insensitive on windows)
	 * @return File that points to the requested path, or null if file was not present on the
	 * local filesystem (because it doesn't exist, or the name comparison function rejected it)
	 */
	public static File lookupFile(File baseDir, String path, Comparator<String> nameComp) {
		// TODO: if path is in unc format "//server/share/path", linux jvm's will normalize the
		// leading double slashes to a single "/".  Should the path be rejected immediately in a
		// non-windows jvm?
		path = Objects.requireNonNullElse(path, "/");
		File f = new File(baseDir, path); // null baseDir is okay
		if (!f.isAbsolute()) {
			Msg.debug(LocalFileSystem.class,
				"Non-absolute path encountered in LocalFileSystem lookup: " + path);
			// TODO: this would be better to throw an exception, but because some relative filenames
			// have leaked into some FSRLs, resolving those paths (even if it produces an incorrect
			// result) seems preferable.
			f = f.getAbsoluteFile();
		}
		try {
			if (nameComp == null || f.getParentFile() == null) {
				// If not using a comparator, or if the requested path is a 
				// root element (eg "/", or "c:\\"), don't do per-directory-path lookups.

				// On windows, getCanonicalFile() will return a corrected path using the case of 
				// the file element on the file system (eg. "c:/users" -> "c:/Users"), if the
				// element exists.
				return f.exists() ? f.getCanonicalFile() : null;
			}

			if (f.exists()) {
				// try to short-cut by comparing the entire path string 
				File canonicalFile = f.getCanonicalFile();
				if (nameComp.compare(path,
					FSUtilities.normalizeNativePath((canonicalFile.getPath()))) == 0) {
					return canonicalFile;
				}
			}

			// For path "/subdir/file", pathParts will contain, in reverse order:
			// [/subdir/file, /subdir, /]
			// The root element ("/", or "c:/") will never be subjected to the name comparator
			// The case of each element will be what was specified in the path parameter.
			// Lookup each element in its parent directory, using the comparator to find the file
			// in the full listing of each directory.
			// If requested path has "." and ".." elements, findInDir() will not find them, 
			// avoiding path traversal issues.
			// TODO: shouldn't use findInDir on the server and share parts of a UNC path "//server/share"
			List<File> pathParts = getFilePathParts(f);

			for (int i = pathParts.size() - 2 /*skip root ele*/; i >= 0; i--) {
				File parentDir = pathParts.get(i + 1);
				File part = pathParts.get(i);
				File foundFile = findInDir(parentDir, part.getName(), nameComp);
				if (foundFile == null) {
					return null;
				}
				pathParts.set(i, foundFile);
			}
			return pathParts.get(0);
		}
		catch (IOException e) {
			Msg.warn(LocalFileSystem.class, "Error resolving path: " + path, e);
			return null;
		}
	}

	static File findInDir(File dir, String name, Comparator<String> nameComp) {
		// Searches for "name" in the list of files found in the directory.
		// Because a case-insensitive comparator could match on several files in the same directory,
		// query for all the files before picking a match: either an exact string match, or
		// if there are several candidates, the first in the list after sorting.
		File[] files = dir.listFiles();
		List<File> candidateMatches = new ArrayList<>();
		if (files != null) {
			for (File f : files) {
				String foundFilename = f.getName();
				if (nameComp.compare(name, foundFilename) == 0) {
					if (name.equals(foundFilename)) {
						return f;
					}
					candidateMatches.add(f);
				}
			}
		}
		Collections.sort(candidateMatches);
		return !candidateMatches.isEmpty() ? candidateMatches.get(0) : null;
	}

	static List<File> getFilePathParts(File f) {
		// return a list of the parts of the specified file:
		// "/subdir/file" -> "/subidr/file", "/subdir", "/"
		// "c:/subdir/file" -> "c:/subdir/file", "c:/subdir", "c:/"
		// "//uncserver/share/path" -> "//uncserver/share/path", "//uncserver/share", "//uncserver", "//" 
		//         (windows jvm only, unix jvm will normalize a path's leading "//" to be "/"
		List<File> results = new ArrayList<File>();
		while (f != null) {
			results.add(f);
			f = f.getParentFile();
		}
		return results;
	}

}
