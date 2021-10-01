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

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.IOException;
import java.util.*;

import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.apache.commons.compress.compressors.gzip.GzipParameters;
import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
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
	private final FileSystemRefManager refManager = new FileSystemRefManager(this);
	private final SingleFileSystemIndexHelper fsIndex;
	private final FileSystemService fsService;
	private ByteProvider container;
	private ByteProvider payloadProvider;

	private String payloadFilename;
	private String payloadKey;
	private String origComment;
	private long origDate;

	public GZipFileSystem(ByteProvider container, FSRLRoot fsFSRL, FileSystemService fsService,
			TaskMonitor monitor) throws IOException, CancelledException {
		this.fsFSRL = fsFSRL;
		this.fsService = fsService;
		this.container = container;

		readGzipMetadata(monitor);
		payloadProvider = getPayloadByteProvider(monitor);
		this.fsIndex = new SingleFileSystemIndexHelper(this, fsFSRL, payloadFilename,
			payloadProvider.length(), payloadProvider.getFSRL().getMD5());
	}

	private void readGzipMetadata(TaskMonitor monitor) throws IOException {
		try (GzipCompressorInputStream gzcis =
			new GzipCompressorInputStream(container.getInputStream(0))) {
			GzipParameters metaData = gzcis.getMetaData();
			payloadFilename = metaData.getFilename();
			if (payloadFilename == null) {
				String containerName = fsFSRL.getContainer().getName();
				if (containerName.toLowerCase().endsWith(".gz")) {
					payloadFilename = FilenameUtils.removeExtension(containerName);
				}
				else {
					payloadFilename = GZIP_PAYLOAD_FILENAME;
				}
			}
			else {
				payloadFilename = FSUtilities.getSafeFilename(payloadFilename);
			}
			this.origComment = metaData.getComment();
			this.origDate = metaData.getModificationTime();

			this.payloadKey = "uncompressed " + payloadFilename;
		}
	}

	private ByteProvider getPayloadByteProvider(TaskMonitor monitor)
			throws CancelledException, IOException {
		UnknownProgressWrappingTaskMonitor upwtm =
			new UnknownProgressWrappingTaskMonitor(monitor, container.length());
		return fsService.getDerivedByteProvider(container.getFSRL(), null, payloadKey, -1,
			() -> new GzipCompressorInputStream(container.getInputStream(0)), upwtm);
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
		if (container != null) {
			container.close();
			container = null;
		}
		if (payloadProvider != null) {
			payloadProvider.close();
			payloadProvider = null;
		}
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
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (fsIndex.isPayloadFile(file)) {
			return new ByteProviderWrapper(payloadProvider, file.getFSRL());
		}
		return null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsIndex.getListing(directory);
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		long compSize = 0;
		long payloadSize = 0;
		try {
			compSize = container.length();
			payloadSize = payloadProvider.length();
		}
		catch (IOException e) {
			// ignore
		}
		GFile payload = fsIndex.getPayloadFile();

		FileAttributes result = new FileAttributes();
		result.add(NAME_ATTR, payload.getName());
		result.add(SIZE_ATTR, payloadSize);
		result.add(COMPRESSED_SIZE_ATTR, compSize);
		result.add(MODIFIED_DATE_ATTR, origDate != 0 ? new Date(origDate) : null);
		result.add(COMMENT_ATTR, origComment);
		result.add("MD5", payload.getFSRL().getMD5());
		return result;
	}

	public Map<String, String> getInfoMap() {
		long compSize = 0;
		long payloadSize = 0;
		try {
			compSize = container.length();
			payloadSize = payloadProvider.length();
		}
		catch (IOException e) {
			// ignore
		}
		GFile payload = fsIndex.getPayloadFile();
		Map<String, String> info = new LinkedHashMap<>();
		info.put("Name", payload.getName());
		info.put("Size", FSUtilities.formatSize(payloadSize));
		info.put("Compressed Size", FSUtilities.formatSize(compSize));
		info.put("Date", FSUtilities.formatFSTimestamp(origDate != 0 ? new Date(origDate) : null));
		info.put("Comment", Objects.requireNonNullElse(origComment, "unknown"));
		info.put("MD5", payload.getFSRL().getMD5());
		return info;
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}
}
