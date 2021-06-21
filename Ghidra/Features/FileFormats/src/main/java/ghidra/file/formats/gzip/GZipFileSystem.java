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
package ghidra.file.formats.gzip;

import java.io.*;
import java.util.*;

import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.apache.commons.compress.compressors.gzip.GzipParameters;

import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.UnknownProgressWrappingTaskMonitor;

/**
 * A pseudo-filesystem that contains a single file that represents the decompressed
 * contents of the Gzip file.
 * <p>
 * If the filename can be recovered from the embedded metadata, it will be used as the
 * name of the singleton file, otherwise the name "gzip_decompressed" will be used.
 * <p>
 *
 */
@FileSystemInfo(type = "gzip", description = "GZIP", priority = FileSystemInfo.PRIORITY_LOW, factory = GZipFileSystemFactory.class)
public class GZipFileSystem implements GFileSystem {
	public static final String GZIP_PAYLOAD_FILENAME = "gzip_decompressed";

	private final FSRLRoot fsFSRL;
	private final FSRL containerFSRL;
	private final FileSystemRefManager refManager = new FileSystemRefManager(this);
	private final SingleFileSystemIndexHelper fsIndex;
	private final FileSystemService fsService;

	private String origFilename;
	private String payloadKey;
	private String origComment;
	private long origDate;
	private long containerSize;

	public GZipFileSystem(FSRL containerFSRL, FSRLRoot fsFSRL, File containerFile,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {
		this.fsFSRL = fsFSRL;
		this.containerFSRL = containerFSRL;
		this.fsService = fsService;

		readGzipMetadata(containerFile, monitor);
		FileCacheEntry fce = getPayloadFileCacheEntry(monitor);
		this.fsIndex =
			new SingleFileSystemIndexHelper(this, fsFSRL, origFilename, fce.file.length(), fce.md5);
	}

	private void readGzipMetadata(File containerFile, TaskMonitor monitor) throws IOException {
		this.containerSize = containerFile.length();
		try (GzipCompressorInputStream gzcis =
			new GzipCompressorInputStream(new FileInputStream(containerFile))) {
			GzipParameters metaData = gzcis.getMetaData();
			origFilename = metaData.getFilename();
			if (origFilename == null) {
				origFilename = GZIP_PAYLOAD_FILENAME;
			}
			else {
				origFilename = FSUtilities.getSafeFilename(origFilename);
			}
			this.origComment = metaData.getComment();

			// NOTE: the following line does not work in apache-commons-compress 1.8
			// Apache has a bug where the computed date value is truncated to 32 bytes before
			// being saved to its 64 bit field.
			// Bug not present in 1.13 (latest ver as of now)
			this.origDate = metaData.getModificationTime();

			this.payloadKey = "uncompressed " + origFilename;
		}
	}

	private FileCacheEntry getPayloadFileCacheEntry(TaskMonitor monitor)
			throws CancelledException, IOException {
		UnknownProgressWrappingTaskMonitor upwtm =
			new UnknownProgressWrappingTaskMonitor(monitor, containerSize);
		FileCacheEntry derivedFile = fsService.getDerivedFile(containerFSRL, payloadKey,
			(srcFile) -> new GzipCompressorInputStream(new FileInputStream(srcFile)), upwtm);
		return derivedFile;
	}

	public GFile getPayloadFile() {
		return fsIndex.getPayloadFile();
	}

	@Override
	public String getName() {
		return fsFSRL.getContainer().getName();
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsFSRL;
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		fsIndex.clear();
	}

	@Override
	public boolean isClosed() {
		return fsIndex.isClosed();
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return fsIndex.lookup(path);
	}

	@Override
	public InputStream getInputStream(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (fsIndex.isPayloadFile(file)) {
			FileCacheEntry fce = getPayloadFileCacheEntry(monitor);
			return new FileInputStream(fce.file);
		}
		return null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsIndex.getListing(directory);
	}

	@Override
	public String getInfo(GFile file, TaskMonitor monitor) {
		if (fsIndex.isPayloadFile(file)) {
			return FSUtilities.infoMapToString(getInfoMap());
		}
		return null;
	}

	public Map<String, String> getInfoMap() {
		GFile payload = fsIndex.getPayloadFile();
		Map<String, String> info = new LinkedHashMap<>();
		info.put("Name", payload.getName());
		info.put("Size", Long.toString(payload.getLength()));
		info.put("Compressed Size", Long.toString(containerSize));
		info.put("Date", (origDate != 0) ? new Date(origDate).toString() : "unknown");
		info.put("Comment", (origComment != null) ? origComment : "unknown");
		info.put("MD5", payload.getFSRL().getMD5());
		return info;
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}
}
