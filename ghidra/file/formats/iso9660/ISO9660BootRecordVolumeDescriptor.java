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
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class ISO9660BootRecordVolumeDescriptor extends ISO9660BaseVolume {

	private byte[] bootSystemIdentifier;// Length 0x20
	private byte[] bootIdentifier;		// Length 0x20
	private byte[] bootSystemUse;		// Length 0x7b9;

	public ISO9660BootRecordVolumeDescriptor(BinaryReader reader) throws IOException {
		super(reader);
		bootSystemIdentifier = reader.readNextByteArray(ISO9660Constants.IDENTIFIER_LENGTH_32);
		bootIdentifier = reader.readNextByteArray(ISO9660Constants.IDENTIFIER_LENGTH_32);
		bootSystemUse = reader.readNextByteArray(ISO9660Constants.BOOT_SYSTEM_USE_LENGTH);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struc = new StructureDataType("ISO9600BootRecord", 0);

		struc.add(BYTE, "Type", "Volume Descriptor Type");
		struc.add(new ArrayDataType(BYTE, super.getIdentifier().length, 1), "Identifier",
			"Identifier");
		struc.add(BYTE, "Version", "Volume Descriptor Version");
		struc.add(new ArrayDataType(BYTE, bootSystemIdentifier.length, 1),
			"Boot System Identifier", "ID of the system which can act on and boot the system");
		struc.add(new ArrayDataType(BYTE, bootIdentifier.length, 1), "Boot Identifier",
			"Identification of the boot system");
		struc.add(new ArrayDataType(BYTE, bootSystemUse.length, 1), "Boot System Use",
			"Custom - used by the boot system");

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

		buff.append("Type: 0x" + Integer.toHexString(super.getTypeCode()) + " => " +
			getTypeCodeString() + "\n");
		buff.append("Identifier: " + new String(super.getIdentifier()).trim() + "\n");
		buff.append("Version: 0x" + Integer.toHexString(super.getVersion()) + "\n");
		buff.append("Boot System Identifier: " + new String(bootSystemIdentifier).trim() + "\n");
		buff.append("Boot Identifier: " + new String(bootIdentifier).trim() + "\n");

		return buff.toString();
	}

	public byte[] getBootSystemIdentifier() {
		return bootSystemIdentifier;
	}

	public byte[] getBootIdentifier() {
		return bootIdentifier;
	}

	public byte[] getBootSystemUse() {
		return bootSystemUse;
	}

}
