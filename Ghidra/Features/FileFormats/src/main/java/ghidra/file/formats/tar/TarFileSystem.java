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
package ghidra.file.formats.tar;

import java.io.*;
import java.util.*;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;

import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TAR file system implementation.
 * <p>
 * The factory supports detecting both compressed (gz) and uncompressed tar files,
 * and keys both on the tar filename extension as well as the data in the file.
 * <p>
 */
@FileSystemInfo(type = "tar", description = "TAR", priority = FileSystemInfo.PRIORITY_HIGH, factory = TarFileSystemFactory.class)
public class TarFileSystem implements GFileSystem {

	private static class TarMetadata {
		TarArchiveEntry tarArchiveEntry;
		int fileNum;

		TarMetadata(TarArchiveEntry tae, int fileNum) {
			this.tarArchiveEntry = tae;
			this.fileNum = fileNum;
		}
	}

	private FSRLRoot fsrl;
	private FileSystemService fsService;
	private File containerFile;
	private FileSystemIndexHelper<TarMetadata> fsih;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);
	private int fileCount;

	/**
	 * Creates a new TarFileSystem instance.
	 *
	 * @param file uncompressed tar file to open.
	 * @param fsrl {@link FSRLRoot} of the new filesystem.
	 * @param fsService reference to the {@link FileSystemService}.
	 */
	public TarFileSystem(File file, FSRLRoot fsrl, FileSystemService fsService) {
		this.fsrl = fsrl;
		this.fsih = new FileSystemIndexHelper<>(this, fsrl);
		this.containerFile = file;
		this.fsService = fsService;
	}

	void mount(boolean precache, TaskMonitor monitor) throws IOException, CancelledException {
		try (TarArchiveInputStream tarInput =
			new TarArchiveInputStream(new FileInputStream(containerFile))) {
			TarArchiveEntry tarEntry;
			while ((tarEntry = tarInput.getNextTarEntry()) != null) {
				monitor.setMessage(tarEntry.getName());
				monitor.checkCanceled();

				GFileImpl newFile =
					fsih.storeFile(tarEntry.getName(), fileCount, tarEntry.isDirectory(),
						tarEntry.getSize(), new TarMetadata(tarEntry, fileCount));
				fileCount++;

				if (precache) {
					FileCacheEntry fce = fsService.addFileToCache(newFile, tarInput, monitor);
					newFile.setFSRL(newFile.getFSRL().withMD5(fce.md5));
				}
			}
		}
	}

	public File getRawContainerFile() {
		return containerFile;
	}

	@Override
	public String getName() {
		return fsrl.getContainer().getName();
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		fsih.clear();
		containerFile = null;
	}

	@Override
	public boolean isClosed() {
		return containerFile == null;
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsrl;
	}

	@Override
	public int getFileCount() {
		return fileCount;
	}

	public Map<String, String> getInfoMap(TarArchiveEntry blob) {
		Map<String, String> info = new LinkedHashMap<>();
		info.put("Name", blob.getName());
		info.put("Mode", Integer.toUnsignedString(blob.getMode(), 8));
		info.put("Size", Long.toString(blob.getSize()));
		info.put("Date", blob.getLastModifiedDate().toString());
		info.put("User/Group", blob.getUserName() + " / " + blob.getGroupName());
		info.put("UserId/GroupId", blob.getUserId() + " / " + blob.getGroupId());
		return info;
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return fsih.lookup(path);
	}

	@Override
	public InputStream getInputStream(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {

		TarMetadata tmd = fsih.getMetadata(file);
		if (tmd == null) {
			throw new IOException("Unknown file " + file);
		}

		// Open a new instance of the tar file, seek to the requested embedded file,
		// and return the inputstream to the caller, who will close it when done.
		TarArchiveInputStream tarInput =
			new TarArchiveInputStream(new FileInputStream(containerFile));

		int fileNum = 0;
		TarArchiveEntry tarEntry;
		while ((tarEntry = tarInput.getNextTarEntry()) != null) {
			if (fileNum == tmd.fileNum) {
				if (!tmd.tarArchiveEntry.getName().equals(tarEntry.getName())) {
					throw new IOException("Mismatch between filenum and tarEntry for " + file);
				}
				return tarInput;
			}
			fileNum++;
		}
		throw new IOException("Could not find requested file " + file);
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsih.getListing(directory);
	}

	@Override
	public String getInfo(GFile file, TaskMonitor monitor) {
		TarMetadata tmd = fsih.getMetadata(file);
		return (tmd != null) ? FSUtilities.infoMapToString(getInfoMap(tmd.tarArchiveEntry)) : null;
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}
}
