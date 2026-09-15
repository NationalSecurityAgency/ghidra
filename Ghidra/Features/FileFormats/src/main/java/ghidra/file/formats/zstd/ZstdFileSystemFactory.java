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
package ghidra.file.formats.zstd;

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.*;
import java.util.Arrays;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.file.cliwrapper.*;
import ghidra.file.cliwrapper.ArchiverCliToolWrapper.Entry;
import ghidra.file.formats.sevenzip.SevenZipCliToolWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.*;
import ghidra.formats.gfilesystem.fileinfo.FileAttribute;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * File system factory for zstd compressed files.
 */
public class ZstdFileSystemFactory
		implements GFileSystemFactoryByteProvider<ZstdFileSystem>, GFileSystemProbeBytesOnly {
	private static final byte[] MAGIC = NumericUtilities.convertStringToBytes("28b52ffd");

	private CliToolWrapper cliTool;

	public ZstdFileSystemFactory() {
	}

	@Override
	public int getBytesRequired() {
		return MAGIC.length;
	}

	@Override
	public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes) {
		return Arrays.equals(startBytes, 0, MAGIC.length, MAGIC, 0, MAGIC.length);
	}

	@Override
	public GFileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {
		try {
			ensureTool(monitor);

			String containerName = targetFSRL.getContainer().getName();
			String payloadFilename = containerName.endsWith(".zstd")
					? containerName.substring(0, containerName.length() - ".zstd".length())
					: containerName + ".uncompressed";

			ByteProvider payloadProvider = extract(byteProvider, fsService, monitor);

			FileAttributes fileAttrs = FileAttributes.of( // attrs
				FileAttribute.create(COMPRESSED_SIZE_ATTR, byteProvider.length()),
				FileAttribute.create(SIZE_ATTR, payloadProvider.length()));
			ZstdFileSystem fs =
				new ZstdFileSystem(targetFSRL, payloadProvider, payloadFilename, fileAttrs);
			return fs;
		}
		finally {
			byteProvider.close();
		}
	}

	ByteProvider extract(ByteProvider byteProvider, FileSystemService fsService,
			TaskMonitor monitor) throws CancelledException, IOException {
		return fsService.getDerivedByteProviderPush(byteProvider.getFSRL(), null,
			"zstd decompressed", -1, os -> {
				if (cliTool instanceof StreamDecompressorCliToolWrapper decompTool) {
					try (InputStream is = byteProvider.getInputStream(0)) {
						decompTool.decompressStream(is, os, monitor);
						return; // success
					}
				}
				else if (cliTool instanceof ArchiverCliToolWrapper archiverTool) {
					File f = fsService.getFileIfAvailable(byteProvider);
					File tmpFile = f == null
							? fsService.createPlaintextTempFile(byteProvider, "zstd_tmp_", monitor)
							: null;
					File archiveFile = f != null ? f : tmpFile;
					try {
						List<Entry> listing = archiverTool.getListing(archiveFile, monitor);
						if (listing.size() == 1) {
							archiverTool.extract(archiveFile, listing.get(0), os, monitor);
							return; // success
						}
					}
					finally {
						if (tmpFile != null) {
							tmpFile.delete();
						}
					}
				}
				throw new IOException("Failed to extract " + byteProvider.getFSRL());
			}, monitor);
	}

	private void ensureTool(TaskMonitor monitor) throws IOException {
		if (cliTool == null) {
			cliTool = ZstdCliToolWrapper.findTool(monitor);
		}
		if (cliTool == null) {
			cliTool = SevenZipCliToolWrapper.findTool(monitor);
		}
		if (cliTool == null) {
			throw new FileSystemFactoryDependencyException("No zstd or 7z cli tool found in PATH");
		}
	}

}
