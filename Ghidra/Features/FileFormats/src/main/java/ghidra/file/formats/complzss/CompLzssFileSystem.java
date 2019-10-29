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
package ghidra.file.formats.complzss;

import java.io.*;
import java.util.*;

import ghidra.app.util.bin.ByteProvider;
import ghidra.file.formats.lzss.LzssCodec;
import ghidra.file.formats.lzss.LzssConstants;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "lzss", description = "LZSS Compression", factory = GFileSystemBaseFactory.class)
public class CompLzssFileSystem extends GFileSystemBase {

	private static final String NAME = "lzss_decompressed";

	private GFileImpl decompressedFile;
	private byte[] decompressedBytes;

	public CompLzssFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public void close() throws IOException {
		decompressedFile = null;
		decompressedBytes = null;
	}

	@Override
	protected InputStream getData(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException, CryptoException {
		if (file != null && file.equals(decompressedFile)) {
			return new ByteArrayInputStream(decompressedBytes);
		}
		return null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return (directory == null || directory.equals(root)) ? Arrays.asList(decompressedFile)
				: Collections.emptyList();
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		byte[] compressionBytes = provider.readBytes(0, 4);
		byte[] lzssBytes = provider.readBytes(4, 4);

		return Arrays.equals(compressionBytes, LzssConstants.SIGNATURE_COMPRESSION_BYTES) &&
			Arrays.equals(lzssBytes, LzssConstants.SIGNATURE_LZSS_BYTES);
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {
		monitor.setMessage("Decompressing LZSS...");
		byte[] compressedBytes = provider.readBytes(LzssConstants.HEADER_LENGTH,
			provider.length() - LzssConstants.HEADER_LENGTH);
		ByteArrayOutputStream decompressedBOS = new ByteArrayOutputStream();
		LzssCodec.decompress(decompressedBOS, new ByteArrayInputStream(compressedBytes));
		decompressedBytes = decompressedBOS.toByteArray();
		decompressedFile =
			GFileImpl.fromFilename(this, root, NAME, false, decompressedBytes.length, null);
		debug(decompressedBytes, NAME);
	}

}
