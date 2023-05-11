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
package ghidra.file.formats.dump.apport;

import java.io.*;
import java.nio.file.AccessMode;
import java.nio.file.Files;
import java.nio.file.attribute.*;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Set;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import aQute.lib.io.IO;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.FileByteProvider;
import ghidra.file.formats.dump.DumpFile;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DecodedProvider implements ByteProvider {

	private String name;
	private ApportHeader fileHeader;
	private long decompressedLength;
	private FileByteProvider tempProvider;
	private byte compressionMethod;
	private byte compressionHeaderFlags;
	private Object compressionTimeStamp;
	private byte compressionFlags;
	private byte compressionOS;

	public DecodedProvider(DumpFile df, ByteProvider provider, TaskMonitor monitor)
			throws CancelledException, IOException {
		Apport pt = (Apport) df;
		fileHeader = pt.getFileHeader();
		name = provider.getName() + "(decoded)";
		init(monitor);
	}
	
	private void init(TaskMonitor monitor) throws CancelledException, IOException {
		FileAttribute<Set<PosixFilePermission>> permissions = PosixFilePermissions
				.asFileAttribute(PosixFilePermissions.fromString("rw-------"));
		File tempFile = Files.createTempFile("decode", ".dat", permissions).toFile();
		boolean success = false;
   		try {
			try (OutputStream out = IO.outputStream(tempFile)) {
				Decoder decoder = Base64.getDecoder();
				Inflater inflater = new Inflater(true);
				byte[] decompressed = new byte[0x10000000];
				monitor.setMessage("Decompressing data");
				monitor.initialize(decompressedLength);
				int written = 0;
				byte[] header = decoder.decode(fileHeader.getBlob(0).trim());
				parseHeader(header);
				for (int i = 1; i < fileHeader.getBlobCount(); i++) {
					monitor.checkCancelled();
					byte[] decode = decoder.decode(fileHeader.getBlob(i).trim());
					inflater.setInput(decode, 0, decode.length);
					int nDecompressed = inflater.inflate(decompressed);
					out.write(decompressed, 0, nDecompressed);
					written += nDecompressed;
					monitor.setProgress(written);
				}
				decompressedLength = written;
			}
			tempProvider = new FileByteProvider(tempFile, null, AccessMode.READ);
			success = true;
		}
		catch (DataFormatException e) {
			throw new IOException("apport decompress failure", e);
		}
		finally {
			if (!success) {
				tempFile.delete();
			}
		}
	}

	private void parseHeader(byte[] header) {
		compressionMethod = header[2];
		compressionHeaderFlags = header[3];
		compressionTimeStamp = (((header[4] << 8) | header[5]) << 8 | header[6]) << 8 | header[7];
		compressionFlags = header[8];
		compressionOS = header[9];
	}

	@Override
	public File getFile() {
		return null;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getAbsolutePath() {
		return null;
	}

	@Override
	public long length() {
		if (decompressedLength <= 0) {
			throw new RuntimeException("Decompressed length = "+decompressedLength);
		}
		return decompressedLength; 
	}

	@Override
	public boolean isValidIndex(long index) {
		return index < length();
	}

	@Override
	public void close() throws IOException {
		File tempFile = tempProvider.getFile();
		tempProvider.close();
		tempFile.delete();
	}

	@Override
	public byte readByte(long index) throws IOException {
		return readBytes(index,1)[0];
	}

	@Override
	public byte[] readBytes(long index, long length) throws IOException {
		try {
			return tempProvider.readBytes(index, length);
		} catch (IOException e) {
			return new byte[(int) length];
		}
	}

	public byte getCompressionMethod() {
		return compressionMethod;
	}

	public byte getCompressionHeaderFlags() {
		return compressionHeaderFlags;
	}

	public Object getCompressionTimeStamp() {
		return compressionTimeStamp;
	}

	public byte getCompressionFlags() {
		return compressionFlags;
	}

	public byte getCompressionOS() {
		return compressionOS;
	}

}
