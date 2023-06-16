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
package ghidra.app.util.bin.format.macho.commands.chained;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a dyld_chained_import structure.
 * 
 * @see <a href="https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h">mach-o/fixup-chains.h</a> 
 */
public class DyldChainedImport implements StructConverter {
	private static final int DYLD_CHAINED_IMPORT = 1;
	private static final int DYLD_CHAINED_IMPORT_ADDEND = 2;
	private static final int DYLD_CHAINED_IMPORT_ADDEND64 = 3;

	private int imports_format;
	private int lib_ordinal;
	private boolean weak_import;
	private long name_offset;
	private long addend;
	private String symbolName;

	DyldChainedImport(BinaryReader reader, DyldChainedFixupHeader cfh, int imports_format)
			throws IOException {
		this.imports_format = imports_format;
		switch (imports_format) {
			case DYLD_CHAINED_IMPORT: {
				int ival = reader.readNextInt();
				lib_ordinal = ival & 0xff;
				weak_import = ((ival >> 8) & 1) == 1;
				name_offset = (ival >> 9 & 0x7fffff);
				break;
			}
			case DYLD_CHAINED_IMPORT_ADDEND: {
				int ival = reader.readNextInt();
				lib_ordinal = ival & 0xff;
				weak_import = ((ival >> 8) & 1) == 1;
				name_offset = (ival >> 9 & 0x7fffff);
				addend = reader.readNextInt();
				break;
			}
			case DYLD_CHAINED_IMPORT_ADDEND64: {
				long ival = reader.readNextLong();
				lib_ordinal = (int) (ival & 0xffff);
				weak_import = ((ival >> 8) & 1) == 1;
				name_offset = (ival >> 32 & 0xffffffff);
				addend = reader.readNextLong();
				break;
			}
			default:
				throw new IOException("Bad Chained import format: " + imports_format);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType dt = new StructureDataType("dyld_chained_import", 0);

		try {
			switch (imports_format) {
				case DYLD_CHAINED_IMPORT:
					dt.addBitField(DWORD, 8, "lib_ordinal", "ordinal in imports");
					dt.addBitField(DWORD, 1, "weak_import", null);
					dt.addBitField(DWORD, 23, "name_offset", null);
					break;
				case DYLD_CHAINED_IMPORT_ADDEND:
					dt.addBitField(DWORD, 8, "lib_ordinal", "ordinal in imports");
					dt.addBitField(DWORD, 1, "weak_import", null);
					dt.addBitField(DWORD, 23, "name_offset", null);
					dt.add(DWORD, "addend", null);
					break;
				case DYLD_CHAINED_IMPORT_ADDEND64:
					dt.addBitField(QWORD, 16, "lib_ordinal", "ordinal in imports");
					dt.addBitField(QWORD, 1, "weak_import", null);
					dt.addBitField(QWORD, 15, "reserved", null);
					dt.addBitField(QWORD, 32, "name_offset", null);
					dt.add(QWORD, "addend", null);
					break;
				default:
					throw new IOException("Bad Chained import format: " + imports_format);
			}
		}
		catch (InvalidDataTypeException exc) {
			// ignore
		}
		dt.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return dt;
	}

	public int getLibOrdinal() {
		return lib_ordinal;
	}

	public boolean isWeakImport() {
		return weak_import;
	}

	public long getNameOffset() {
		return name_offset;
	}

	public long getAddend() {
		return addend;
	}

	public String getName() {
		return symbolName;
	}

	public void initString(BinaryReader reader) throws IOException {
		symbolName = reader.readNextAsciiString();
	}

}
