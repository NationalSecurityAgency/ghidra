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
 * Represents a SOM {@code export_entry} structure
 * 
 * @see <a href="https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf">The 32-bit PA-RISC Run-time Architecture Document</a> 
 */
public class SomExportEntry implements StructConverter {

	/** The size in bytes of a {@link SomExportEntry} */
	public static final int SIZE = 0x14;

	private int next;
	private String name;
	private int value;
	private int info;
	private int type;
	private boolean isTpRelative;
	private int reserved1;
	private short moduleIndex;

	/**
	 * Creates a new {@link SomExportEntry}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the export list
	 * @param stringTableLoc The location of the string table
	 * @throws IOException if there was an IO-related error
	 */
	public SomExportEntry(BinaryReader reader, long stringTableLoc) throws IOException {
		next = reader.readNextInt();
		int nameIndex = reader.readNextInt();
		name = nameIndex != -1 ? reader.readAsciiString(stringTableLoc + nameIndex) : null;
		value = reader.readNextInt();
		info = reader.readNextInt();
		type = reader.readNextUnsignedByte();
		int bitfield = reader.readNextUnsignedByte();
		reserved1 = bitfield & 0x7f;
		isTpRelative = ((bitfield >> 7) & 0x1) != 0;
		moduleIndex = reader.readNextShort();
	}

	/**
	 * {@return the next export record in the hash chain}
	 */
	public int getNext() {
		return next;
	}

	/**
	 * {@return the symbol name}
	 */
	public String getName() {
		return name;
	}

	/**
	 * {@return the symbol address (subject to relocation)}
	 */
	public int getValue() {
		return value;
	}

	/**
	 * {@return the size of the storage request if exported symbol is of type {@code STORAGE}, or
	 * the version of the exported symbol along with argument relocation information}
	 */
	public int getInfo() {
		return info;
	}

	/**
	 * {@return the symbol type}
	 * 
	 * @see SomConstants
	 */
	public int getType() {
		return type;
	}

	/**
	 * {@return whether or not this is a TLS export}
	 */
	public boolean isTpRelative() {
		return isTpRelative;
	}

	/**
	 * {@return the first reserved value}
	 */
	public int getReserved1() {
		return reserved1;
	}

	/**
	 * {@return the index into the module table of the module defining this symbol}
	 */
	public short getModuleIndex() {
		return moduleIndex;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType miscInfoStruct = new StructureDataType("misc_info", 4);
		miscInfoStruct.setPackingEnabled(true);
		miscInfoStruct.add(WORD, "version", "months since January, 1990");
		try {
			miscInfoStruct.addBitField(WORD, 6, "reserved2", null);
			miscInfoStruct.addBitField(WORD, 10, "arg_reloc", "parameter relocation bits (5*2)");
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}
		miscInfoStruct.setCategoryPath(new CategoryPath("/SOM"));

		UnionDataType infoUnion = new UnionDataType("info");
		infoUnion.add(DWORD, "size", "storage request area size in bytes");
		infoUnion.add(miscInfoStruct, "misc", "version, etc. N/A to storage requests");
		infoUnion.setCategoryPath(new CategoryPath("/SOM"));

		StructureDataType struct = new StructureDataType("export_entry", SIZE);
		struct.setPackingEnabled(true);
		struct.add(DWORD, "next", "index of next export entry in hash chain");
		struct.add(DWORD, "name", "offset within string table");
		struct.add(DWORD, "value", "offset of symbol (subject to relocation)");
		struct.add(infoUnion, "info", null);
		struct.add(BYTE, "type", "symbol type");
		try {
			struct.addBitField(BYTE, 1, "is_tp_relative", "TLS export");
			struct.addBitField(BYTE, 7, "reserved1", "reserved");
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}
		struct.add(WORD, "module_index", "index of module defining symbol");
		struct.setCategoryPath(new CategoryPath("/SOM"));
		return struct;
	}
}
