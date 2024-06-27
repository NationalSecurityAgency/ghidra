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
package ghidra.app.util.bin.format.omf;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * A generic OMF record
 */
public abstract class OmfRecord implements StructConverter {

	protected int recordType;
	protected int recordLength;
	protected byte checkSum;

	protected long recordOffset;

	/**
	 * Reads the record header (type and length fields)
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the record
	 * @throws IOException if an IO-related problem occurred
	 */
	public void readRecordHeader(BinaryReader reader) throws IOException {
		recordOffset = reader.getPointerIndex();
		recordType = reader.readNextUnsignedByte();
		recordLength = reader.readNextUnsignedShort();
	}

	/**
	 * Reads the record checksum
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the record checksum
	 * @throws IOException if an IO-related problem occurred
	 */
	public void readCheckSumByte(BinaryReader reader) throws IOException {
		checkSum = reader.readNextByte();
	}

	/**
	 * {@return the record type}
	 */
	public int getRecordType() {
		return recordType;
	}

	/**
	 * {@return the record length}
	 */
	public int getRecordLength() {
		return recordLength;
	}

	/**
	 * {@return the record offset}
	 */
	public long getRecordOffset() {
		return recordOffset;
	}

	/**
	 * Computes the record's checksum
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of record
	 * @return The record's checksum
	 * @throws IOException if an IO-related error occurred
	 */
	public byte calcCheckSum(BinaryReader reader) throws IOException {
		byte res = reader.readNextByte();
		res += reader.readNextByte();
		res += reader.readNextByte();		// Sum the record header bytes
		for (int i = 0; i < recordLength; ++i) {
			res += reader.readNextByte();
		}
		return res;
	}

	/**
	 * Validates the record's checksum
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the record
	 * @return True if the checksum is valid; otherwise, false
	 * @throws IOException if an IO-related error occurred
	 */
	public boolean validCheckSum(BinaryReader reader) throws IOException {
		if (checkSum == 0) {
			// Some compilers just set this to zero
			return true;
		}
		return (calcCheckSum(reader) == 0);
	}

	/**
	 * {@return true if this record has big fields; otherwise, false}
	 */
	public boolean hasBigFields() {
		return ((recordType & 1) != 0);
	}

	@Override
	public abstract DataType toDataType() throws DuplicateNameException, IOException;

	@Override
	public String toString() {
		return String.format("type: 0x%x, offset: 0x%x, length: 0x%x", recordType, recordOffset,
			recordLength);
	}
}
