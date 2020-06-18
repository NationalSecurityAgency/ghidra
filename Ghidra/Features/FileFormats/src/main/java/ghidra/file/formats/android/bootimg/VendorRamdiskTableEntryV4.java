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
package ghidra.file.formats.android.bootimg;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class VendorRamdiskTableEntryV4 implements StructConverter {

	private int ramdisk_size;
	private int ramdisk_offset;
	private int ramdisk_type;
	private String ramdisk_name;

	private int[] board_id;

	public VendorRamdiskTableEntryV4(BinaryReader reader) throws IOException {
		ramdisk_size = reader.readNextInt();
		ramdisk_offset = reader.readNextInt();
		ramdisk_type = reader.readNextInt();
		ramdisk_name = reader.readNextAsciiString(BootImageConstants.VENDOR_RAMDISK_NAME_SIZE);
		board_id =
			reader.readNextIntArray(BootImageConstants.VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE);
	}

	/**
	 * Size in bytes for the ramdisk image
	 * @return ramdisk size
	 */
	public int getRamdiskSize() {
		return ramdisk_size;
	}

	/**
	 * Offset to the ramdisk image in vendor ramdisk section
	 * @return ramdisk offset
	 */
	public int getRamdiskOffset() {
		return ramdisk_offset;
	}

	/**
	 * Type of the ramdisk
	 * @return ramdisk type
	 */
	public int getRamdiskType() {
		return ramdisk_type;
	}

	/**
	 * Ascii ramdisk name
	 * @return the ascii ramdisk name
	 */
	public String getRamdiskName() {
		return ramdisk_name;
	}

	/**
	 * Hardware identifiers describing the board, soc or platform 
	 * which this ramdisk is intended to be loaded on.
	 * @return the board ID
	 */
	public int[] getBoardID() {
		return board_id;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("vendor_ramdisk_table_entry_v4", 0);
		structure.add(DWORD, "ramdisk_size", null);
		structure.add(DWORD, "ramdisk_offset", null);
		structure.add(DWORD, "ramdisk_type", null);
		structure.add(UTF8, BootImageConstants.VENDOR_RAMDISK_NAME_SIZE, "ramdisk_name", null);
		for (int i = 0; i < BootImageConstants.VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE; ++i) {
			structure.add(DWORD, "board_id_" + i, null);
		}
		return structure;
	}

}
