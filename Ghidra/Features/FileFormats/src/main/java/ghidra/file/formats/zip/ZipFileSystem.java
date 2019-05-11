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
package ghidra.file.formats.zip;

import java.io.*;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "zip", description = "ZIP", factory = ZipFileSystemFactory.class, priority = FileSystemInfo.PRIORITY_HIGH)
public class ZipFileSystem implements GFileSystem {

	private FileSystemIndexHelper<ZipEntry> fsIndexHelper;
	private FSRLRoot fsrl;
	private ZipFile zipFile;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);

	public ZipFileSystem(FSRLRoot fsrl) {
		this.fsrl = fsrl;
		this.fsIndexHelper = new FileSystemIndexHelper<>(this, fsrl);
	}

	@Override
	public String getName() {
		return fsrl.getContainer().getName();
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		if (zipFile != null) {
			zipFile.close();
			zipFile = null;
		}
		fsIndexHelper.clear();
	}

	@Override
	public boolean isClosed() {
		return zipFile == null;
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsrl;
	}

	@Override
	public int getFileCount() {
		return fsIndexHelper.getFileCount();
	}

	public void mount(File f, TaskMonitor monitor) throws CancelledException, IOException {
		this.zipFile = new ZipFile(f);

		Enumeration<? extends ZipEntry> entries = zipFile.entries();
		while (entries.hasMoreElements()) {
			monitor.checkCanceled();
			ZipEntry currentEntry = entries.nextElement();
			fsIndexHelper.storeFile(currentEntry.getName(), -1, currentEntry.isDirectory(),
				currentEntry.getSize(), currentEntry);
		}
	}

	public Map<String, String> getInfoMap(ZipEntry blob) {
		Map<String, String> info = new HashMap<>();
		info.put("Name", blob.getName());
		info.put("Comment", blob.getComment());
		info.put("Compressed Size", "0x" + Long.toHexString(blob.getCompressedSize()));
		info.put("Uncompressed Size", "0x" + Long.toHexString(blob.getSize()));
		info.put("CRC", "0x" + Long.toHexString(blob.getCrc()));
		info.put("Compression Method", "0x" + Integer.toHexString(blob.getMethod()));
		info.put("Time", new Date(blob.getTime()).toString());
		info.put("Extra Bytes",
			(blob.getExtra() == null ? "null" : Arrays.toString(blob.getExtra())));
		return info;
	}

	@Override
	public String toString() {
		return "ZipFilesystem [ fsrl=" + fsrl + ", filename=" + zipFile.getName() + " ]";
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return fsIndexHelper.lookup(path);
	}

	@Override
	public InputStream getInputStream(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		ZipEntry zipEntry = fsIndexHelper.getMetadata(file);
		return (zipEntry != null) ? zipFile.getInputStream(zipEntry) : null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsIndexHelper.getListing(directory);
	}

	@Override
	public String getInfo(GFile file, TaskMonitor monitor) {
		ZipEntry zipEntry = fsIndexHelper.getMetadata(file);
		return (zipEntry != null) ? FSUtilities.infoMapToString(getInfoMap(zipEntry)) : null;
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}
}
