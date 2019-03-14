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
package ghidra.file.formats.ios.png;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PNGChunk implements StructConverter {

	private int length;
	private int chunkID;
	private byte[] data;
	private int crc32;
	private int totalLength;

	/**
	 * Reads in the bytes of a PNG chunk from a given
	 * BinaryReader
	 * @param reader
	 * @throws IOException
	 */
	public PNGChunk(BinaryReader reader) throws IOException {
		length = reader.readNextInt();
		chunkID = reader.readNextInt();
		data = reader.readNextByteArray(length);
		crc32 = reader.readNextInt();

		totalLength += (CrushedPNGConstants.GENERIC_CHUNK_SIZE + data.length);
	}

	public int getLength() {
		return length;
	}

	public byte[] getLengthBytes() {
		return ByteBuffer.allocate(4).putInt(length).array();
	}

	public void setLength(int length) {
		this.length = length;
	}

	public int getChunkID() {
		return chunkID;
	}

	public byte[] getChunkIDBytes() {
		return ByteBuffer.allocate(4).putInt(chunkID).array();
	}

	public void setChunkID(int chunkID) {
		this.chunkID = chunkID;
	}

	public byte[] getData() {
		return data;
	}

	public void setData(byte[] data) {
		this.data = data;
	}

	public int getCrc32() {
		return crc32;
	}

	public byte[] getCrc32Bytes() {
		return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(crc32).array();
	}

	public void setCrc32(int crc32) {
		this.crc32 = crc32;
	}

	public int getTotalLength() {
		return totalLength;
	}

	public byte[] getChunkBytes() {
		return ByteBuffer.allocate(totalLength).putInt(length).putInt(chunkID).put(data).putInt(
			crc32).array();
	}

	public String getIDString() {
		ByteBuffer byteBuffer = ByteBuffer.allocate(4);
		byteBuffer.putInt(chunkID);
		byte[] bArr = byteBuffer.array();

		return new String(bArr);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struc = new StructureDataType("iOS Crushed PNG", 0);

		struc.add(BYTE, "Length", "Length of the chunk data field");
		struc.add(BYTE, "Chunk ID", "The name of the chunk");
		struc.add(new ArrayDataType(BYTE, data.length, 1), "Data", "Chunk data");
		struc.add(BYTE, "CRC32", "Chunk CRC32");

		return struc;
	}

	@Override
	public String toString() {
		StringBuffer buff = new StringBuffer();

		buff.append("Length: 0x" + Integer.toHexString(length) + "\n");
		buff.append("Chunk ID: " + getIDString() + "\n");
		buff.append("Chunk Data:" + new String(data) + "\n");
		buff.append("CRC32: 0x" + crc32 + "\n");

		return buff.toString();
	}
}
