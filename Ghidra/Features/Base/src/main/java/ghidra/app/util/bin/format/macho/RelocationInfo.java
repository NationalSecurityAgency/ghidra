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
 * Represents a relocation_info structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/reloc.h.auto.html">mach-o/reloc.h</a> 
 */
public class RelocationInfo implements StructConverter {
    protected int r_address   = -1;
	protected int r_symbolnum = -1;
	protected int r_pcrel     = -1;
	protected int r_length    = -1;
	protected int r_extern    = -1;
	protected int r_type      = -1;

	public static RelocationInfo createRelocationInfo(
            FactoryBundledWithBinaryReader reader) throws IOException {
	    RelocationInfo relocationInfo = (RelocationInfo) reader.getFactory().create(RelocationInfo.class);
	    relocationInfo.initRelocationInfo(reader);
	    return relocationInfo;
    }

	public RelocationInfo() {		
	}

	private void initRelocationInfo(FactoryBundledWithBinaryReader reader) throws IOException {
		r_address           = reader.readNextInt();

		int value           = reader.readNextInt();

		if (reader.isLittleEndian()) {
			r_symbolnum     = (value & 0x00ffffff);
			r_pcrel         = (value & 0x01000000) >> 24;
			r_length        = (value & 0x06000000) >> 25;
			r_extern        = (value & 0x08000000) >> 27;
			r_type          = (value & 0xf0000000) >> 28;
		}
		else {
			r_symbolnum     = (value & 0xffffff00) >> 8;
			r_pcrel         = (value & 0x00000080) >> 7;
			r_length        = (value & 0x00000060) >> 5;
			r_extern        = (value & 0x00000010) >> 4;
			r_type          = (value & 0x0000000f);
		}
	}

	public int getAddress() {
		return r_address;
	}
	
	public int getSymbolIndex() {
		return r_symbolnum;
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

	public int getType() {
		return r_type;
	}

	/**
	 * Returns the values array for storage into the program's relocation table.
	 * @return the values array for storage into the program's relocation table
	 */
	public long [] toValues() {
		return new long[] { 0,//zero indicates that it is not a scattered relocation
							r_address   & 0xffffffffL,
							r_symbolnum & 0xffffffffL,
							r_pcrel     & 0xffffffffL,
							r_length    & 0xffffffffL,
							r_extern    & 0xffffffffL,
							r_type      & 0xffffffffL};
	}

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append("Address:      "+Long.toHexString(r_address));
		buffer.append('\n');
		buffer.append("Symbol Index: "+Integer.toHexString(r_symbolnum));
		buffer.append('\n');
		buffer.append("PC Relocated: "+isPcRelocated());
		buffer.append('\n');
		buffer.append("Length:       "+Integer.toHexString(r_length)+getLengthInBytes());
		buffer.append('\n');
		buffer.append("External:     "+isExternal());
		buffer.append('\n');
		buffer.append("Type:         "+Integer.toHexString(r_type));
		buffer.append('\n');
		return buffer.toString();
	}

	protected String getLengthInBytes() {
		switch (r_length) {
			case 0 : return " (1 byte)";
			case 1 : return " (2 bytes)";
			case 2 : return " (3 bytes)";
			case 3 : return " (4 bytes)";
		}
		return "";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
	    StructureDataType struct = new StructureDataType("relocation_info", 0);
    	struct.add(DWORD, "r_address", null);
	    struct.add(DWORD, "r_mask", "{r_symbolnum,r_pcrel,r_length,r_extern,r_type}");
	    struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
	    return struct;
	}
}

