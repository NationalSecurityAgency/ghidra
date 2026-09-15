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
package ghidra.app.util.bin.format.som;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a SOM {@code import_entry} structure
 * 
 * @see <a href="https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf">The 32-bit PA-RISC Run-time Architecture Document</a> 
 */
public class SomImportEntry implements StructConverter {

	/** The size in bytes of a {@link SomImportEntry} */
	public static final int SIZE = 0x8;

	private String name;
	private int reserved2;
	private int type;
	private boolean bypassable;
	private int reserved1;

	/**
	 * Creates a new {@link SomImportEntry}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the import list
	 * @param stringTableLoc The location of the string table
	 * @throws IOException if there was an IO-related error
	 */
	public SomImportEntry(BinaryReader reader, long stringTableLoc) throws IOException {
		int nameIndex = reader.readNextInt();
		name = nameIndex != -1 ? reader.readAsciiString(stringTableLoc + nameIndex) : null;
		int bitfield = reader.readNextInt();
		reserved1 = bitfield & 0x7f;
		bypassable = ((bitfield >> 7) & 0x1) != 0;
		type = (bitfield >> 8) & 0xff;
		reserved2 = (bitfield >> 16) & 0xffff;
	}

	/**
	 * {@return the name of the import, or {@code null} if it doesn't have one}
	 */
	public String getName() {
		return name;
	}

	/**
	 * {@return the second reserved value}
	 */
	public int getReserved2() {
		return reserved2;
	}

	/**
	 * {@return the symbol type (text, data, or bss)}
	 */
	public int getType() {
		return type;
	}

	/**
	 * {@return whether or not code imports do not have their address taken in that shared library}
	 */
	public boolean isBypassable() {
		return bypassable;
	}

	/**
	 * {@return the first reserved value}
	 */
	public int getReserved1() {
		return reserved1;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("import_entry", SIZE);
		struct.setPackingEnabled(true);
		struct.add(DWORD, "name", "offset in string table");
		try {
			struct.addBitField(DWORD, 16, "reserved2", "unused");
			struct.addBitField(DWORD, 8, "type", "symbol type");
			struct.addBitField(DWORD, 1, "bypassable", "address of code symbol not taken in shlib");
			struct.addBitField(DWORD, 7, "reserved1", "unused");
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}
		struct.setCategoryPath(new CategoryPath("/SOM"));
		return struct;
	}
}
