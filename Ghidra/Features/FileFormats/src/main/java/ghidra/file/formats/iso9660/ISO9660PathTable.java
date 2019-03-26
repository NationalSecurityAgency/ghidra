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
package ghidra.file.formats.iso9660;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class ISO9660PathTable implements StructConverter {

	private byte dirIdentifierLength;
	private byte extendedAttributeRecordLength;
	private int locationOfExtent;
	private short directoryNumberPathIndex;
	private byte[] directoryIdentifier;
	private byte paddingField;
	private boolean paddingFieldPresent;
	private long volumeIndex;
	private boolean littleEndian;

	public ISO9660PathTable(BinaryReader reader, boolean littleEndian) throws IOException {
		reader.setLittleEndian(littleEndian);
		this.littleEndian = littleEndian;
		volumeIndex = reader.getPointerIndex();
		dirIdentifierLength = reader.readNextByte();
		extendedAttributeRecordLength = reader.readNextByte();
		locationOfExtent = reader.readNextInt();
		directoryNumberPathIndex = reader.readNextShort();
		directoryIdentifier = reader.readNextByteArray(dirIdentifierLength);

		//The padding field is only present if the directoryIdentifierLength
		//is odd, otherwise it is not used.
		if (dirIdentifierLength % 2 != 0) {
			paddingField = reader.readNextByte();
			paddingFieldPresent = true;
		}
		else {
			paddingFieldPresent = false;
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struc;
		if (littleEndian) {
			struc = new StructureDataType("ISO9660TypeLPathTable", 0);
		}
		else {
			struc = new StructureDataType("ISO9660TypeMPathTable", 0);
		}

		struc.add(BYTE, "Directory Identifier Length", "Length of Directory Identifier");
		struc.add(BYTE, "Extended Attribute Record Length", "Length of Extended Attribute Record");
		struc.add(DWORD, "Location of Extent", "Location of Extent in Little-endian format");
		struc.add(WORD, "Directory Number",
			"Number of parent directory (an index in to the path table)");
		struc.add(new ArrayDataType(BYTE, directoryIdentifier.length, 1), "Directory Identifier",
			"Directory Identifier");
		if (paddingFieldPresent) {
			struc.add(BYTE, "Padding Field", "Padding Field");
		}
		return struc;
	}

	/**
	 * Creates a string representation of this class filling in field specifics
	 * when applicable. 
	 * @return the string representation of this class
	 */
	@Override
	public String toString() {
		StringBuffer buff = new StringBuffer();

		buff.append("Directory Identifier Length: 0x" + Integer.toHexString(dirIdentifierLength) +
			"\n");
		buff.append("Extended Attribute Record Length: " +
			Integer.toHexString(extendedAttributeRecordLength) + "\n");
		buff.append("Location of Extent (LBA): 0x" + Integer.toHexString(locationOfExtent) + "\n");
		buff.append("Directory Number: 0x" + Integer.toHexString(directoryNumberPathIndex) + "\n");
		buff.append("Directory Identifier: " + new String(directoryIdentifier).trim() + "\n");
		if (paddingFieldPresent) {
			buff.append("PaddingF ield: 0x" + Integer.toHexString(paddingField) + "\n");
		}

		return buff.toString();
	}

	public byte getDirIdentifierLength() {
		return dirIdentifierLength;
	}

	public byte getExtendedAttributeRecordLength() {
		return extendedAttributeRecordLength;
	}

	public int getLocationOfExtent() {
		return locationOfExtent;
	}

	public short getDirectoryNumberPathIndex() {
		return directoryNumberPathIndex;
	}

	public byte[] getDirectoryIdentifier() {
		return directoryIdentifier;
	}

	public byte getPaddingField() {
		return paddingField;
	}

	public boolean isPaddingFieldPresent() {
		return paddingFieldPresent;
	}

	public long getVolumeIndex() {
		return volumeIndex;
	}

	public boolean isLittleEndian() {
		return littleEndian;
	}

}
