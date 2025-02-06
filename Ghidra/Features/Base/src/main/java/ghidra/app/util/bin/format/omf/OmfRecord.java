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
	protected byte[] data;
	protected byte checkSum;

	protected long recordOffset;
	protected BinaryReader dataReader;
	protected long dataEnd;

	public OmfRecord() {
		// nothing to do
	}

	/**
	 * Creates a new {@link OmfRecord}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the record
	 * @throws IOException if there was an IO-related error
	 */
	public OmfRecord(BinaryReader reader) throws IOException {
		this.recordOffset = reader.getPointerIndex();
		
		this.recordType = reader.readNextUnsignedByte();
		this.recordLength = reader.readNextUnsignedShort();
		this.data = reader.readNextByteArray(recordLength - 1);
		this.checkSum = reader.readNextByte();

		this.dataReader = reader.clone(recordOffset + 3);
		this.dataEnd = recordOffset + 3 + recordLength - 1;
	}

	/**
	 * Parses this {@link OmfRecord}'s type-spefic data
	 * 
	 * @throws IOException if there was an IO-related error
	 * @throws OmfException if there was a problem with the OMF specification
	 */
	public abstract void parseData() throws IOException, OmfException;

	@Override
	public abstract DataType toDataType() throws DuplicateNameException, IOException;

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

	public byte getRecordChecksum() {
		return checkSum;
	}

	public byte[] getData() {
		return data;
	}

	/**
	 * Computes the record's checksum
	 * 
	 * @return The record's checksum
	 * @throws IOException if an IO-related error occurred
	 */
	public byte calcCheckSum() throws IOException {
		byte sum = (byte) recordType;
		sum += (byte) recordLength + (byte) (recordLength >> 8);
		for (byte b : data) {
			sum += b;
		}
		sum += checkSum;
		return sum;
	}

	/**
	 * Validates the record's checksum
	 * 
	 * @return True if the checksum is valid; otherwise, false
	 * @throws IOException if an IO-related error occurred
	 */
	public boolean validCheckSum() throws IOException {
		if (checkSum == 0) {
			// Some compilers just set this to zero
			return true;
		}
		return (calcCheckSum() == 0);
	}

	/**
	 * {@return true if this record has big fields; otherwise, false}
	 */
	public boolean hasBigFields() {
		return ((recordType & 1) != 0);
	}

	@Override
	public String toString() {
		return String.format("type: 0x%x, offset: 0x%x, length: 0x%x", recordType, recordOffset,
			recordLength);
	}
}
