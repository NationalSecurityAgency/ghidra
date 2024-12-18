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

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link GFileSystem} interface to a part of the user's local / native file system.
 * <p>
 * This class is a sub-view of the {@link LocalFileSystem}, and returns hybrid GFile objects
 * that have fully specified FSRL paths that are valid in the Root filesystem, but relative
 * GFile paths.
 * <p>
 * This class's name doesn't end with "FileSystem" to ensure it will not be auto-discovered
 * by the FileSystemFactoryMgr.
 *
 */
public class LocalFileSystemSub implements GFileSystem, GFileHashProvider {
	private final FSRLRoot fsFSRL;
	private final LocalFileSystem rootFS;
	private File localfsRootDir;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);
	private GFileLocal rootGFile;

	public LocalFileSystemSub(File rootDir, LocalFileSystem rootFS) throws IOException {
		this.rootFS = rootFS;
		this.localfsRootDir = rootDir.getCanonicalFile();

		FSRL containerFSRL = rootFS.getLocalFSRL(localfsRootDir);
		this.fsFSRL = FSRLRoot.nestedFS(containerFSRL, rootFS.getFSRL().getProtocol());
		this.rootGFile = new GFileLocal(localfsRootDir, "/", containerFSRL, this, null);
	}

	@Override
	public String getType() {
		return rootFS.getType();
	}

	@Override
	public String getDescription() {
		return "Local filesystem subdirectory";
	}

	@Override
	public void close() {
		refManager.onClose();
		localfsRootDir = null;
	}

	@Override
	public boolean isClosed() {
		return localfsRootDir == null;
	}

	@Override
	public boolean isStatic() {
		return false;
	}

	private File getFileFromGFile(GFile gf) throws IOException {
		if (gf == null) {
			return localfsRootDir;
		}
		if (!(gf instanceof GFileLocal)) {
			throw new IOException("Unexpected GFile class: " + gf.getClass());
		}
		return ((GFileLocal) gf).getLocalFile();
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		if (directory == null) {
			directory = rootGFile;
		}
		if (!directory.isDirectory()) {
			return List.of();
		}
		File localDir = getFileFromGFile(directory);
		if (FSUtilities.isSymlink(localDir)) {
			return List.of();
		}

		File[] localFiles = localDir.listFiles();

		if (localFiles == null) {
			return List.of();
		}

		List<GFile> tmp = new ArrayList<>(localFiles.length);
		FSRL dirFSRL = directory.getFSRL();
		String relPath = FSUtilities.normalizeNativePath(directory.getPath());

		for (File f : localFiles) {
			boolean isSymlink = FSUtilities.isSymlink(f); // check this manually to allow broken symlinks to appear in listing
			if (!(isSymlink || f.isFile() || f.isDirectory())) {
				// skip non-file things
				continue;
			}
			// construct a GFile with split personality... a relative GFile pathname but
			// an absolute FSRL path
			String name = f.getName();
			GFileLocal gf = new GFileLocal(f, FSUtilities.appendPath(relPath, name),
				dirFSRL.appendPath(name), this, directory);
			tmp.add(gf);
		}
		return tmp;
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		try {
			File localFile = getFileFromGFile(file);
			return rootFS.getFileAttributes(localFile);
		}
		catch (IOException e) {
			// fail and return empty
		}
		return FileAttributes.EMPTY;
	}

	@Override
	public String getName() {
		return "Subdir " + localfsRootDir.getPath();
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsFSRL;
	}

	@Override
	public GFile getRootDir() {
		return rootGFile;
	}

	@Override
	public GFile lookup(String path) throws IOException {
		File f = LocalFileSystem.lookupFile(localfsRootDir, path, null);
		if ( f == null ) {
			return null;
		}
		GFile result = getGFile(f);
		return result;
	}

	private GFile getGFile(File f) throws IOException {
		List<File> parts = LocalFileSystem.getFilePathParts(f); // [/subdir/subroot/file, /subdir/subroot, /subdir, /]
		int rootDirIndex = findRootDirIndex(parts);
		if (rootDirIndex < 0) {
			throw new IOException("Invalid directory " + f);
		}
		GFile current = rootGFile;
		for (int i = rootDirIndex - 1; i >= 0; i--) {
			File part = parts.get(i);
			FSRL childFSRL = current.getFSRL().appendPath(part.getName());
			String childPath = FSUtilities.appendPath(current.getPath(), part.getName());
			current = new GFileLocal(part, childPath, childFSRL, this, current);
		}
		return current;
	}

	private int findRootDirIndex(List<File> dirList) {
		for (int i = 0; i < dirList.size(); i++) {
			if (localfsRootDir.equals(dirList.get(i))) {
				return i;
			}
		}
		return -1;
	}

	@Override
	public InputStream getInputStream(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		return rootFS.getInputStream(file.getFSRL(), monitor);
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}

	@Override
	public String toString() {
		return getName();
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		return rootFS.getByteProvider(file.getFSRL(), monitor);
	}

	@Override
	public String getMD5Hash(GFile file, boolean required, TaskMonitor monitor)
			throws CancelledException, IOException {
		return rootFS.getMD5Hash(file.getFSRL(), required, monitor);
	}

	@Override
	public GFile resolveSymlinks(GFile file) throws IOException {
		File f = getFileFromGFile(file);
		File canonicalFile = f.getCanonicalFile();
		if (f.equals(canonicalFile)) {
			return file;
		}
		return getGFile(canonicalFile);
	}
}
