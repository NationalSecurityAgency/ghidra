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

/**
 * Parent class used for all other types of volume descriptors 
 */
public class ISO9660BaseVolume implements StructConverter {

	private long volumeIndex;
	private byte typeCode;
	private byte[] identifier;
	private byte version;

	public ISO9660BaseVolume(BinaryReader reader) throws IOException {
		volumeIndex = reader.getPointerIndex();
		typeCode = reader.readNextByte();
		identifier = reader.readNextByteArray(ISO9660Constants.MAGIC_BYTES.length);
		version = reader.readNextByte();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struc = new StructureDataType("ISO9660VolumeDescriptor", 0);

		struc.add(BYTE, "Type Code", "Type of volume descriptor");
		struc.add(new ArrayDataType(BYTE, identifier.length, 1), "Standard Identifier",
			"Always 'CD001'");
		struc.add(BYTE, "Version", "Always 0x01");

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

		buff.append("Type Code: 0x" + Integer.toHexString(typeCode) + " => " + getTypeCodeString() +
			"\n");
		buff.append("Standard Identifier: " + new String(identifier).trim() + "\n");
		buff.append("Version: 0x" + Integer.toHexString(version) + "\n");

		return buff.toString();
	}

	public String getTypeCodeString() {

		switch (typeCode) {
			case ISO9660Constants.VOLUME_DESC_BOOT_RECORD:
				return "Boot Record";
			case ISO9660Constants.VOLUME_DESC_PRIMARY_VOLUME_DESC:
				return "Primary Volume Descriptor";
			case ISO9660Constants.VOLUME_DESC_SUPPL_VOLUME_DESC:
				return "Supplementary Volume Descriptor";
			case ISO9660Constants.VOLUME_PARTITION_DESC:
				return "Volume Partition Descriptor";
			case ISO9660Constants.VOLUME_DESC_SET_TERMINATOR:
				return "Volume Descriptor Set Terminator";
			default:
				return "";

		}
	}

	public byte getTypeCode() {
		return typeCode;
	}

	public byte[] getIdentifier() {
		return identifier;
	}

	public byte getVersion() {
		return version;
	}

	public long getVolumeIndex() {
		return volumeIndex;
	}
}
