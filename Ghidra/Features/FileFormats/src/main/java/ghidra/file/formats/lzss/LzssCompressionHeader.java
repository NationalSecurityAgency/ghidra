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
package ghidra.file.formats.lzss;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

public class LzssCompressionHeader implements StructConverter {

	public static final int PROBE_BYTES_NEEDED = 8; // sizeof(signature) + sizeof(compressionType)

	/**
	 * Returns true if the bytes have the magic signature of a LzssCompressionHeader.
	 * 
	 * @param startBytes byte array
	 * @return boolean true if the signature of a LzssCompressionHeader appears at the beginning
	 * the byte array
	 */
	public static boolean probe(byte[] startBytes) {
		try {
			if (startBytes.length < PROBE_BYTES_NEEDED) {
				return false;
			}
			BinaryReader reader = new BinaryReader(new ByteArrayProvider(startBytes), false);

			int signature = reader.readNextInt();
			int compressionType = reader.readNextInt();
			return signature == LzssConstants.SIGNATURE_LZSS &&
				compressionType == LzssConstants.SIGNATURE_COMPRESSION;
		}
		catch (IOException e) {
			return false;
		}
	}

	private int signature;
	private int compressionType;
	private int checksum;
	private int decompressedLength;
	private int compressedLength;
	private byte[] padding;

	public LzssCompressionHeader(ByteProvider provider) throws IOException {
		BinaryReader reader = new BinaryReader(provider, false);

		signature          =  reader.readNextInt();
		compressionType    =  reader.readNextInt();
		checksum           =  reader.readNextInt();
		decompressedLength =  reader.readNextInt();
		compressedLength   =  reader.readNextInt();
		padding            =  reader.readNextByteArray( LzssConstants.PADDING_LENGTH );
	}

	public int getSignature() {
		return signature;
	}
	public int getCompressionType() {
		return compressionType;
	}
	public int getChecksum() {
		return checksum;
	}
	public int getDecompressedLength() {
		return decompressedLength;
	}
	public int getCompressedLength() {
		return compressedLength;
	}
	public byte[] getPadding() {
		return padding;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(this);
	}
}
