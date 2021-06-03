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
package ghidra.app.util.bin.format.macho;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a relocation_info and scattered_relocation_info structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-7195.81.3/EXTERNAL_HEADERS/mach-o/reloc.h.auto.html">mach-o/reloc.h</a> 
 */
public class RelocationInfo implements StructConverter {

	/**
	 * Mask to be applied to the r_address field of a relocation_info structure to tell that it is 
	 * really a scattered_relocation_info structure
	 */
	private static int R_SCATTERED = 0x80000000;

	/**
	 * 1=scattered, 0=non-scattered
	 */
	private int r_scattered;

	/**
	 * Offset in the section to what is being relocated.  The r_address is not really the address 
	 * as its name indicates but an offset.
	 */
	private int r_address;

	/**
	 * Symbol index if r_extern == 1 or section ordinal if r_extern == 0
	 */
	private int r_value;

	/**
	 * Was relocated PC relative already
	 */
	private int r_pcrel;

	/**
	 * 0=byte, 1=word, 2=long, 3=quad
	 */
	private int r_length;

	/**
	 * If r_extern is zero then r_symbolnum is an ordinal for the segment the symbol being relocated
	 * is in
	 */
	private int r_extern;

	/**
	 * If not 0, machine specific relocation type
	 */
	private int r_type;

	public static RelocationInfo createRelocationInfo(FactoryBundledWithBinaryReader reader)
			throws IOException {
		RelocationInfo relocationInfo =
			(RelocationInfo) reader.getFactory().create(RelocationInfo.class);
		relocationInfo.initRelocationInfo(reader);
		return relocationInfo;
	}

	public RelocationInfo() {
	}

	private void initRelocationInfo(FactoryBundledWithBinaryReader reader) throws IOException {

		int i1 = reader.readNextInt();
		int i2 = reader.readNextInt();

		if ((i1 & R_SCATTERED) != 0) {
			r_scattered = 1;
			r_extern = 1;
			r_address = i1 & 0xffffff;
			r_type = (i1 >> 24) & 0xf;
			r_length = (i1 >> 28) & 0x3;
			r_pcrel = (i1 >> 30) & 0x1;
			r_value = i2;
		}
		else {
			r_scattered = 0;
			r_address = i1;
			r_value = i2 & 0xffffff;
			r_pcrel = (i2 >> 24) & 0x1;
			r_length = (i2 >> 25) & 0x3;
			r_extern = (i2 >> 27) & 0x1;
			r_type = (i2 >> 28) & 0xf;
		}
	}

	public int getAddress() {
		return r_address;
	}

	public int getValue() {
		return r_value;
	}

	public boolean isPcRelocated() {
		return r_pcrel == 1;
	}

	public int getLength() {
		return r_length;
	}

	public boolean isExternal() {
		return r_extern == 1;
	}

	public boolean isScattered() {
		return r_scattered == 1;
	}

	public int getType() {
		return r_type;
	}

	/**
	 * Returns the values array for storage into the program's relocation table.
	 * @return the values array for storage into the program's relocation table
	 */
	public long[] toValues() {
		return new long[] { 0,//zero indicates that it is not a scattered relocation
			r_address & 0xffffffffL, r_value & 0xffffffffL, r_pcrel & 0xffffffffL,
			r_length & 0xffffffffL, r_extern & 0xffffffffL, r_type & 0xffffffffL };
	}

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append("Address:      " + Long.toHexString(r_address));
		buffer.append('\n');
		buffer.append("Value:        " + Integer.toHexString(r_value));
		buffer.append('\n');
		buffer.append("Scattered:    " + isScattered());
		buffer.append('\n');
		buffer.append("PC Relocated: " + isPcRelocated());
		buffer.append('\n');
		buffer.append("Length:       " + Integer.toHexString(r_length) + getLengthString());
		buffer.append('\n');
		buffer.append("External:     " + isExternal());
		buffer.append('\n');
		buffer.append("Type:         " + Integer.toHexString(r_type));
		buffer.append('\n');
		return buffer.toString();
	}

	private String getLengthString() {
		switch (r_length) {
			case 0:
				return " (1 byte)";
			case 1:
				return " (2 bytes)";
			case 2:
				return " (4 bytes)";
			case 3:
				return " (8 bytes)";
		}
		return "";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct;
		if (isScattered()) {
			struct = new StructureDataType("scattered_relocation_info", 0);
			try {
				struct.insertBitFieldAt(0, DWORD.getLength(), 0, DWORD, 24, "r_address", "");
				struct.insertBitFieldAt(0, DWORD.getLength(), 24, DWORD, 4, "r_type", "");
				struct.insertBitFieldAt(0, DWORD.getLength(), 28, DWORD, 2, "r_length", "");
				struct.insertBitFieldAt(0, DWORD.getLength(), 30, DWORD, 1, "r_pcrel", "");
				struct.insertBitFieldAt(0, DWORD.getLength(), 31, DWORD, 1, "r_scattered", "");
			}
			catch (InvalidDataTypeException e) {				
				struct.add(DWORD, "r_mask", "{r_address,r_type,r_length,r_pcrel,r_scattered}");
			}
			struct.add(DWORD, "r_value", null);
		}
		else {
			struct = new StructureDataType("relocation_info", 0);
			struct.add(DWORD, "r_address", null);
			try {
				struct.insertBitFieldAt(4, DWORD.getLength(), 0, DWORD, 24, "r_symbolnum", "");
				struct.insertBitFieldAt(4, DWORD.getLength(), 24, DWORD, 1, "r_pcrel", "");
				struct.insertBitFieldAt(4, DWORD.getLength(), 25, DWORD, 2, "r_length", "");
				struct.insertBitFieldAt(4, DWORD.getLength(), 27, DWORD, 1, "r_extern", "");
				struct.insertBitFieldAt(4, DWORD.getLength(), 28, DWORD, 4, "r_type", "");
			}
			catch (InvalidDataTypeException e) {
				struct.add(DWORD, "r_mask", "{r_symbolnum,r_pcrel,r_length,r_extern,r_type}");
			}
		}
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
