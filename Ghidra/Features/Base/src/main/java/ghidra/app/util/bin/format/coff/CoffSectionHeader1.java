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

/**
 * A 0x28 byte COFF section header
 */
class CoffSectionHeader1 extends CoffSectionHeader {

	CoffSectionHeader1(BinaryReader reader, CoffFileHeader header) throws IOException {
		super();

		this._header = header;

		readName(reader);

		s_paddr    = reader.readNextInt();
		s_vaddr    = reader.readNextInt();
		s_size     = reader.readNextInt();
		s_scnptr   = reader.readNextInt();
		s_relptr   = reader.readNextInt();
		s_lnnoptr  = reader.readNextInt();
		s_nreloc   = reader.readNextShort() & 0xffff;
		s_nlnno    = reader.readNextShort() & 0xffff;
		s_flags    = reader.readNextShort() & 0xffff;
		s_reserved = reader.readNextByte();
		s_page     = reader.readNextByte();
	}

}
