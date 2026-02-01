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
package ghidra.file.formats.lzfse;

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.*;
import ghidra.formats.gfilesystem.fileinfo.FileAttribute;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Factory to identify and create instances of a {@link LzfseFileSystem}
 * 
 * @see <a href="https://github.com/lzfse/lzfse">lzfse reference implementation</a> 
 */
public class LzfseFileSystemFactory
		implements GFileSystemFactoryByteProvider<LzfseFileSystem>, GFileSystemProbeBytesOnly {

	private static final int START_BYTES_REQUIRED = 4;

	private static final int LZFSE_ENDOFSTREAM_BLOCK_MAGIC = 0x24787662;    // bvx$ (end of stream)
	private static final int LZFSE_UNCOMPRESSED_BLOCK_MAGIC = 0x2d787662;   // bvx- (raw data)
	private static final int LZFSE_COMPRESSEDV1_BLOCK_MAGIC = 0x31787662;   // bvx1 (lzfse compressed, uncompressed tables)
	private static final int LZFSE_COMPRESSEDV2_BLOCK_MAGIC = 0x32787662;   // bvx2 (lzfse compressed, compressed tables)
	private static final int LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC = 0x6e787662; // bvxn (lzvn compressed)

	private LzfseCliToolWrapper cliTool;

	@Override
	public int getBytesRequired() {
		return START_BYTES_REQUIRED;
	}

	@Override
	public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes) {
		int startValue = ByteBuffer.wrap(startBytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
		return switch (startValue) {
			case LZFSE_ENDOFSTREAM_BLOCK_MAGIC:
			case LZFSE_UNCOMPRESSED_BLOCK_MAGIC:
			case LZFSE_COMPRESSEDV1_BLOCK_MAGIC:
			case LZFSE_COMPRESSEDV2_BLOCK_MAGIC:
			case LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC:
				yield true;
			default:
				yield false;
		};
	}

	@Override
	public GFileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {
		try {
			ensureTool(monitor);
			ByteProvider payloadProvider = fsService.getDerivedByteProviderPush(
				byteProvider.getFSRL(), null, "lzfse_decompressed", -1, os -> {
					try (InputStream is = byteProvider.getInputStream(0)) {
						cliTool.decompressStream(is, os, monitor);
					}
				}, monitor);

			FileAttributes fileAttrs = FileAttributes.of( // attrs
				FileAttribute.create(COMPRESSED_SIZE_ATTR, byteProvider.length()),
				FileAttribute.create(SIZE_ATTR, payloadProvider.length()));

			LzfseFileSystem fs =
				new LzfseFileSystem(targetFSRL, payloadProvider, "lzfse_decompressed", fileAttrs);
			return fs;
		}
		finally {
			FSUtilities.uncheckedClose(byteProvider, null);
		}
	}

	private void ensureTool(TaskMonitor monitor) throws IOException {
		if (cliTool == null) {
			cliTool = LzfseCliToolWrapper.findTool(monitor);
		}
		if (cliTool == null) {
			throw new FileSystemFactoryDependencyException("lzfse native decompressor not present");
		}
	}
}
