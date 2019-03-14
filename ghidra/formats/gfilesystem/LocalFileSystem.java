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
import java.nio.file.Files;
import java.util.*;

import org.apache.commons.io.FilenameUtils;

import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemFactory;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryIgnore;
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
public class LocalFileSystem implements GFileSystem {
	public static final String FSTYPE = "file";

	/**
	 * Create a new instance
	 *
	 * @return new {@link LocalFileSystem} instance using {@link #FSTYPE} as its FSRL type.
	 */
	public static LocalFileSystem makeGlobalRootFS() {
		return new LocalFileSystem(FSRLRoot.makeRoot(FSTYPE));
	}

	private final List<GFile> emptyDir = Collections.emptyList();
	private final FSRLRoot fsFSRL;
	private final FileSystemRefManager refManager = new FileSystemRefManager(this);

	private LocalFileSystem(FSRLRoot fsrl) {
		this.fsFSRL = fsrl;
	}

	private boolean isSameFS(FSRL fsrl) {
		return fsFSRL.equals(fsrl.getFS());
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

	public File getLocalFile(FSRL fsrl) throws IOException {
		if (!isSameFS(fsrl)) {
			throw new IOException("FSRL does not specify local file: " + fsrl);
		}
		File localFile = new File(fsrl.getPath());
		return localFile;
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
	public String getInfo(GFile file, TaskMonitor monitor) {
		File localFile = new File(file.getPath());

		StringBuilder buffer = new StringBuilder();
		buffer.append("Name: " + localFile.getName() + "\n");
		buffer.append("Size: " + localFile.length() + "\n");
		buffer.append("Date: " + new Date(localFile.lastModified()).toString() + "\n");
		return buffer.toString();
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
	public InputStream getInputStream(GFile file, TaskMonitor monitor) throws IOException {
		File f = new File(file.getPath());
		return new FileInputStream(f);
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
	public String toString() {
		return "Local file system " + fsFSRL;
	}
}
