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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import ghidra.util.NumericUtilities;

/**
 * PDB C13 Module File Checksum for one file.
 */
public class C13FileChecksum {
	private long offsetFilename; // unsigned 32-bit
	private int length;
	private int checksumTypeValue;
	private byte[] bytes;

	static int getBaseRecordSize() {
		return 6;
	}

	C13FileChecksum(PdbByteReader reader) throws PdbException {
		offsetFilename = reader.parseUnsignedIntVal();
		length = reader.parseUnsignedByteVal();
		checksumTypeValue = reader.parseUnsignedByteVal();
		bytes = reader.parseBytes(length);
		reader.align4();
	}

	/**
	 * Returns of offset of the filename within the filename list
	 * @return the offset of the filename
	 */
	public long getOffsetFilename() {
		return offsetFilename;
	}

	/**
	 * Returns the number of bytes of the checksum field
	 * @return the number of bytes of the checksum field
	 */
	public long getLength() {
		return length;
	}

	/**
	 * Returns the ID value of the checksum type use
	 * @return the ID of the checksum type
	 */
	public int getChecksumTypeValue() {
		return checksumTypeValue;
	}

	/**
	 * Returns the checksum bytes
	 * @return the checksum bytes
	 */
	public byte[] getChecksumBytes() {
		return bytes;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append(String.format("0x%08x, 0x%02x %s(%02x): ", offsetFilename, length,
			C13ChecksumType.fromValue(checksumTypeValue), checksumTypeValue));
		builder.append(NumericUtilities.convertBytesToString(bytes));
		return builder.toString();
	}
}
