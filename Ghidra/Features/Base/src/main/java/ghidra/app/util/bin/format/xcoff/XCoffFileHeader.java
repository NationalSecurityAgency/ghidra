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
import java.text.DateFormat;
import java.util.Date;

/**
 * XCOFF File Header.
 * Handles both 32 and 64 bit cases.
 */
public class XCoffFileHeader implements StructConverter {
	private final static char NL = '\n';

	public final static int SIZEOF = 20;

	private short f_magic;   // bytes: magic number
	private short f_nscns;   // number of sections: 2 bytes
	private int   f_timdat;  // time & date stamp
	private long  f_symptr;  // file pointer to symbol table
	private int   f_nsyms;   // number of symbol table entries
	private short f_opthdr;  // size of optional header
	private short f_flags;   // flags

	private XCoffOptionalHeader _optionalHeader;

	public XCoffFileHeader(ByteProvider provider) throws IOException, XCoffException {
		if (provider == null || provider.length() < SIZEOF) {
			throw new XCoffException("Invalid XCOFF: file is too small.");
		}

		BinaryReader reader = new BinaryReader(provider, false/*always big endian*/);

		if (!XCoffFileHeaderMagic.isMatch(reader.peekNextShort())) {
			throw new XCoffException("Invalid XCOFF: incorrect magic value.");
		}

		f_magic      = reader.readNextShort();
		f_nscns      = reader.readNextShort();
		f_timdat     = reader.readNextInt();
		if (XCoffFileHeaderMagic.is32bit(this)) {
			f_symptr = reader.readNextInt() & 0xffffffffL;
		}
		else if (XCoffFileHeaderMagic.is64bit(this)) {
			f_symptr = reader.readNextLong();
		}
		else {
			throw new XCoffException("Invalid XCOFF: unrecognized bit size.");
		}
		f_nsyms      = reader.readNextInt();
		f_opthdr     = reader.readNextShort();
		f_flags      = reader.readNextShort();

		if (f_opthdr > 0) {
			_optionalHeader = new XCoffOptionalHeader(reader, this);
		}
	}

	public short getMagic() {
		return f_magic;
	}

	public short getSectionCount() {
		return f_nscns;
	}

	public int getTimeStamp() {
		return f_timdat;
	}

	public long getSymbolTablePointer() {
		return f_symptr;
	}

	public int getSymbolTableEntries() {
		return f_nsyms;
	}

	public short getOptionalHeaderSize() {
		return f_opthdr;
	}

	public short getFlags() {
		return f_flags;
	}

	public XCoffOptionalHeader getOptionalHeader() {
		return _optionalHeader;
	}

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append("FILE HEADER VALUES").append(NL);
		buffer.append("f_magic  = ").append(f_magic).append(NL);
		buffer.append("f_nscns  = ").append(f_nscns).append(NL);
		buffer.append("f_timdat = ");
		buffer.append(DateFormat.getDateInstance().format(new Date(f_timdat)));
		buffer.append(NL);
		buffer.append("f_symptr = ").append(f_symptr).append(NL);
		buffer.append("f_nsyms  = ").append(f_nsyms).append(NL);
		buffer.append("f_opthdr = ").append(f_opthdr).append(NL);
		buffer.append("f_flags  = ").append(f_flags).append(NL);
		return buffer.toString();
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(XCoffFileHeader.class);
	}
}
