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
import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.FileByteProvider;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemFactory;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryIgnore;
import ghidra.formats.gfilesystem.fileinfo.*;
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
	 * 
	 * @param f {@link File}
	 * @return {@link FSRL}
	 */
	public FSRL getLocalFSRL(File f) {
		return fsFSRL
				.withPath(FSUtilities.appendPath("/", FilenameUtils.separatorsToUnix(f.getPath())));
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
				results.add(GFileImpl.fromFSRL(this, null, fsFSRL.withPath(f.getName()),
					f.isDirectory(), -1));
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
					results.add(GFileImpl.fromFSRL(this, directory,
						directory.getFSRL().appendPath(f.getName()), f.isDirectory(), f.length()));
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
	public GFileImpl lookup(String path) throws IOException {
		File f = new File(path);
		GFileImpl gf = GFileImpl.fromPathString(this, FilenameUtils.separatorsToUnix(f.getPath()),
			null, f.isDirectory(), f.length());
		return gf;
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

	private static class FileFingerprintRec {
		final String path;
		final long timestamp;
		final long length;

		FileFingerprintRec(String path, long timestamp, long length) {
			this.path = path;
			this.timestamp = timestamp;
			this.length = length;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + (int) (length ^ (length >>> 32));
			result = prime * result + ((path == null) ? 0 : path.hashCode());
			result = prime * result + (int) (timestamp ^ (timestamp >>> 32));
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (!(obj instanceof FileFingerprintRec)) {
				return false;
			}
			FileFingerprintRec other = (FileFingerprintRec) obj;
			if (length != other.length) {
				return false;
			}
			if (path == null) {
				if (other.path != null) {
					return false;
				}
			}
			else if (!path.equals(other.path)) {
				return false;
			}
			if (timestamp != other.timestamp) {
				return false;
			}
			return true;
		}
	}
}
