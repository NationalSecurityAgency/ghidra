/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.xcoff;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public final class XCoffSectionHeader implements StructConverter {
	private final static char NL = '\n';

	private byte [] s_name;  // section name
	private long s_paddr;    // physical address, aliased s_nlib
	private long s_vaddr;    // virtual address
	private long s_size;     // section size
	private long s_scnptr;   // file pointer to raw data for section
	private long s_relptr;   // file pointer to relocation
	private long s_lnnoptr;  // file pointer to line numbers
	private int  s_nreloc;   // number of relocation entries
	private int  s_nlnno;    // number of line number entries
	private int  s_flags;    // flags

	private int _sizeof = -1;

	XCoffSectionHeader(BinaryReader reader, XCoffFileHeader header) throws IOException {
		s_name        = reader.readNextByteArray(8);

		if (XCoffFileHeaderMagic.is32bit(header)) {
			s_paddr   = reader.readNextInt() & 0xffffffffL;
			s_vaddr   = reader.readNextInt() & 0xffffffffL;
			s_size    = reader.readNextInt() & 0xffffffffL;
			s_scnptr  = reader.readNextInt() & 0xffffffffL;
			s_relptr  = reader.readNextInt() & 0xffffffffL;
			s_lnnoptr = reader.readNextInt() & 0xffffffffL;
			s_nreloc  = reader.readNextShort() & 0xffff;
			s_nlnno   = reader.readNextShort() & 0xffff;
			s_flags   = reader.readNextShort() & 0xffff;

			_sizeof = 40;
		}
		else if (XCoffFileHeaderMagic.is64bit(header)) {
			s_paddr   = reader.readNextLong();
			s_vaddr   = reader.readNextLong();
			s_size    = reader.readNextLong();
			s_scnptr  = reader.readNextLong();
			s_relptr  = reader.readNextLong();
			s_lnnoptr = reader.readNextLong();
			s_nreloc  = reader.readNextInt();
			s_nlnno   = reader.readNextInt();
			s_flags   = reader.readNextInt();

			_sizeof = 72;
		}
	}

	public int sizeof() {
		return _sizeof;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(XCoffSectionHeader.class);
	}

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append("SECTION HEADER VALUES").append(NL);
		buffer.append(new String(s_name)).append(NL);
		buffer.append("s_paddr = ").append(s_paddr).append(NL);
		buffer.append("s_vaddr = ").append(s_vaddr).append(NL);
		buffer.append("s_size = ").append(s_size).append(NL);
		buffer.append("s_scnptr = ").append(s_scnptr).append(NL);
		buffer.append("s_relptr = ").append(s_relptr).append(NL);
		buffer.append("s_lnnoptr = ").append(s_lnnoptr).append(NL);
		buffer.append("s_nreloc = ").append(s_nreloc).append(NL);
		buffer.append("s_nlnno = ").append(s_nlnno).append(NL);
		buffer.append("s_flags = ").append(s_flags).append(NL);
		return buffer.toString();
	}
}
