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
import java.util.Date;

import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.apache.commons.compress.compressors.gzip.GzipParameters;
import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly;
import ghidra.formats.gfilesystem.fileinfo.FileAttribute;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.UnknownProgressWrappingTaskMonitor;

public class GZipFileSystemFactory
		implements GFileSystemFactoryByteProvider<GZipFileSystem>, GFileSystemProbeBytesOnly {

	public static final int PROBE_BYTES_REQUIRED = GZipConstants.MAGIC_BYTES_COUNT;
	public static final String GZIP_PAYLOAD_FILENAME = "gzip_decompressed";

	@Override
	public GZipFileSystem create(FSRLRoot targetFSRL, ByteProvider provider,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {

		try {
			String containerName = targetFSRL.getContainer().getName();
			FileAttributes payloadAttrs = getGZFileAttributes(provider, containerName);
			String payloadName = payloadAttrs.get(NAME_ATTR, String.class, GZIP_PAYLOAD_FILENAME);

			UnknownProgressWrappingTaskMonitor upwtm =
				new UnknownProgressWrappingTaskMonitor(monitor, provider.length());

			ByteProvider payloadProvider = fsService.getDerivedByteProvider(provider.getFSRL(),
				null, "uncompressed " + payloadName, -1,
				() -> new GzipCompressorInputStream(provider.getInputStream(0)), upwtm);

			payloadAttrs.add(SIZE_ATTR, payloadProvider.length());

			GZipFileSystem fs =
				new GZipFileSystem(targetFSRL, payloadProvider, payloadName, payloadAttrs);
			return fs;
		}
		finally {
			FSUtilities.uncheckedClose(provider, null);
		}
	}

	private FileAttributes getGZFileAttributes(ByteProvider provider, String containerName)
			throws IOException {
		String payloadFilename = GZIP_PAYLOAD_FILENAME;
		String origComment = null;
		long origDate = 0;
		try (GzipCompressorInputStream gzcis =
			new GzipCompressorInputStream(provider.getInputStream(0))) {
			GzipParameters metaData = gzcis.getMetaData();
			payloadFilename = metaData.getFileName();
			if (payloadFilename == null) {
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
			origComment = metaData.getComment();
			origDate = metaData.getModificationTime();
		}
		return FileAttributes.of( // attrs
			FileAttribute.create(NAME_ATTR, payloadFilename),
			FileAttribute.create(COMPRESSED_SIZE_ATTR, provider.length()),
			FileAttribute.create(MODIFIED_DATE_ATTR, origDate != 0 ? new Date(origDate) : null),
			FileAttribute.create(COMMENT_ATTR, origComment));
	}

	@Override
	public int getBytesRequired() {
		return PROBE_BYTES_REQUIRED;
	}

	@Override
	public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes) {
		return GZipUtil.isGZip(startBytes);
	}

}
