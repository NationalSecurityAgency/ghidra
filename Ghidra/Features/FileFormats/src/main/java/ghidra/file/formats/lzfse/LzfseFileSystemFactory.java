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

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly;
import ghidra.framework.Application;
import ghidra.framework.OperatingSystem;
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
	private static final String LZFSE_NATIVE_BINARY_NAME = "lzfse";
	private static final String LZFSE_TEMP_PREFIX = "lzfse";
	private static final int LZFSE_NATIVE_TIMEOUT_SECONDS = 10;

	private static final int LZFSE_ENDOFSTREAM_BLOCK_MAGIC = 0x24787662;    // bvx$ (end of stream)
	private static final int LZFSE_UNCOMPRESSED_BLOCK_MAGIC = 0x2d787662;   // bvx- (raw data)
	private static final int LZFSE_COMPRESSEDV1_BLOCK_MAGIC = 0x31787662;   // bvx1 (lzfse compressed, uncompressed tables)
	private static final int LZFSE_COMPRESSEDV2_BLOCK_MAGIC = 0x32787662;   // bvx2 (lzfse compressed, compressed tables)
	private static final int LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC = 0x6e787662; // bvxn (lzvn compressed)

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
		
		File compressedFile = null;
		File decompressedFile = null;
		try {
			compressedFile =
				fsService.createPlaintextTempFile(byteProvider, LZFSE_TEMP_PREFIX, monitor);
			decompressedFile = lzfseDecompress(compressedFile);
			return new LzfseFileSystem(targetFSRL, decompressedFile, fsService, monitor);
		}
		finally {
			byteProvider.close();
			if (compressedFile != null && compressedFile.exists()) {
				compressedFile.delete();
			}
			if (decompressedFile != null && decompressedFile.exists()) {
				decompressedFile.delete();
			}
		}
	}

	/**
	 * Uses the native lzfse decompressor to decompress the given compressed file
	 * 
	 * @param compressedFile The lzfse-compressed {@link File file} to decompress
	 * @return The lzfse-decompressed {@link File}
	 * @throws IOException If there was an IO-related error
	 */
	private File lzfseDecompress(File compressedFile) throws IOException {
		String lzfseName = LZFSE_NATIVE_BINARY_NAME;
		if (OperatingSystem.CURRENT_OPERATING_SYSTEM.equals(OperatingSystem.WINDOWS)) {
			lzfseName += ".exe";
		}
		File lzfseNativeBinary = Application.getOSFile(lzfseName);

		File decompressedFile = Application.createTempFile(LZFSE_TEMP_PREFIX,
			Long.toString(System.currentTimeMillis()));

		List<String> command = new ArrayList<>();
		command.add(lzfseNativeBinary.getPath());
		command.add("-decode");
		command.add("-i");
		command.add(compressedFile.getPath());
		command.add("-o");
		command.add(decompressedFile.getPath());
		Process p = new ProcessBuilder(command).start();
		boolean success = false;
		try {
			if (!p.waitFor(LZFSE_NATIVE_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
				p.destroyForcibly();
				throw new IOException("lzfse native decompressor timed out");
			}
			if (p.exitValue() != 0) {
				throw new IOException(
					"lzfse native decompressor failed with exit code: " + p.exitValue());
			}
			success = true;
			return decompressedFile;
		}
		catch (InterruptedException e) {
			throw new IOException(e);
		}
		finally {
			if (!success) {
				decompressedFile.delete();
			}
		}
	}
}
