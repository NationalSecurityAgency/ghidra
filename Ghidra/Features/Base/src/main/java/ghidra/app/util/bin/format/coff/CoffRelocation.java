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
package ghidra.app.util.bin.format.coff;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class CoffRelocation implements StructConverter {
	private final static int SIZEOF2 = 4 + 4 + 2 + 2;
	private final static int SIZEOF  = 4 + 4 + 2;

	private int    r_vaddr;  // address of relocation
	private int    r_symndx; // symbol being relocated
	private short  r_exa;    // for COFF1 files: reserved
                             // for COFF2 files: additional byte used for 
	                         // extended address calculations
	private short  r_type;   // relocation type

	private CoffFileHeader _header;

	CoffRelocation(BinaryReader reader, CoffFileHeader header) throws IOException {
		this._header = header;

		r_vaddr   = reader.readNextInt();
		r_symndx  = reader.readNextInt();

		if (header.getMagic() == CoffMachineType.TICOFF2MAGIC) {
			r_exa = reader.readNextShort();
		}

		r_type    = reader.readNextShort();
	}

	public int sizeof() {
		if (_header.getMagic() == CoffMachineType.TICOFF2MAGIC ||
			_header.getMagic() == CoffMachineType.TICOFF1MAGIC) {
			return SIZEOF2;
		}
		return SIZEOF;
	}

	/**
	 * Returns the address where the relocation 
	 * should be performed.
	 * @return the relocation address
	 */
	public long getAddress() {
		return r_vaddr;
	}

	/**
	 * Returns the symbol being relocated.
	 * @return the symbol being relocated
	 */
	public long getSymbolIndex() {
		return r_symndx;
	}

	/**
	 * Returns the extended address value.
	 * This is only used for COFF2.
	 * @return the extended address value
	 */
	public short getExtendedAddress() {
		return r_exa;
	}

	/**
	 * Returns the relocation type.
	 * @return the relocation type
	 */
	public short getType() {
		return r_type;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(StructConverterUtil.parseName(CoffRelocation.class), 0);
		struct.add(DWORD, "r_vaddr", null);
		struct.add(DWORD, "r_symndx", null);
		if (_header.getMagic() == CoffMachineType.TICOFF2MAGIC ||
			_header.getMagic() == CoffMachineType.TICOFF1MAGIC) {
			struct.add(WORD, "r_exa", null);
		}
		struct.add(WORD, "r_type", null);
		return struct;
	}
}
