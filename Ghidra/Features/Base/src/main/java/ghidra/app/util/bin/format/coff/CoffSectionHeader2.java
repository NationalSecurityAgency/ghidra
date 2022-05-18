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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.*;

/**
 * A 0x30 byte COFF section header
 */
class CoffSectionHeader2 extends CoffSectionHeader {

	CoffSectionHeader2(BinaryReader reader, CoffFileHeader header) throws IOException {
		super();

		this._header = header;

		readName(reader);

		s_paddr    = reader.readNextInt();
		s_vaddr    = reader.readNextInt();
		s_size     = reader.readNextInt();
		s_scnptr   = reader.readNextInt();
		s_relptr   = reader.readNextInt();
		s_lnnoptr  = reader.readNextInt();
		s_nreloc   = reader.readNextInt();
		s_nlnno    = reader.readNextInt();
		s_flags    = reader.readNextInt();
		s_reserved = reader.readNextShort();
		s_page     = reader.readNextShort();
	}

	@Override
	public DataType toDataType() throws IOException {
		Structure struct = new StructureDataType(StructConverterUtil.parseName(getClass()), 0);
		struct.add(new ArrayDataType(ASCII, CoffConstants.SECTION_NAME_LENGTH, ASCII.getLength()),
			"s_name", null);
		struct.add(DWORD, "s_paddr", null);
		struct.add(DWORD, "s_vaddr", null);
		struct.add(DWORD, "s_size", null);
		struct.add(DWORD, "s_scnptr", null);
		struct.add(DWORD, "s_relptr", null);
		struct.add(DWORD, "s_lnnoptr", null);
		struct.add(DWORD, "s_nreloc", null);
		struct.add(DWORD, "s_nlnno", null);
		struct.add(DWORD, "s_flags", null);
		struct.add(WORD, "s_reserved", null);
		struct.add(WORD, "s_page", null);
		return struct;
	}

}
