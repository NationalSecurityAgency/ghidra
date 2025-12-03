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
 * Represents a SOM {@code dreloc_record} structure
 * 
 * @see <a href="https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf">The 32-bit PA-RISC Run-time Architecture Document</a> 
 */
public class SomDynamicRelocation implements StructConverter {

	/** The size in bytes of a {@link SomDynamicRelocation} */
	public static final int SIZE = 0x14;

	private int shlib;
	private int symbol;
	private int location;
	private int value;
	private int type;
	private byte reserved;
	private short moduleIndex;

	/**
	 * Creates a new {@link SomDynamicRelocation}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the dynamic relocation list
	 * @throws IOException if there was an IO-related error
	 */
	public SomDynamicRelocation(BinaryReader reader) throws IOException {
		shlib = reader.readNextInt();
		symbol = reader.readNextInt();
		location = reader.readNextInt();
		value = reader.readNextInt();
		type = reader.readNextUnsignedByte();
		reserved = reader.readNextByte();
		moduleIndex = reader.readNextShort();
	}

	/**
	 * {@return the shared library name (currently a reserved field)}
	 */
	public int getShlib() {
		return shlib;
	}

	/**
	 * {@return the index into the import table if the relocation is an external type}
	 */
	public int getSymbol() {
		return symbol;
	}

	/**
	 * {@return the data-relative offset of the data item the dreloc record refers to}
	 */
	public int getLocation() {
		return location;
	}

	/**
	 * {@return the text or data-relative offset to use for a patch if it is an internal fixup type}
	 */
	public int getValue() {
		return value;
	}

	/**
	 * {@return the type of dynamic relocation}
	 * 
	 * @see SomConstants
	 */
	public int getType() {
		return type;
	}

	/**
	 * {@return the reserved value}
	 */
	public byte getReserved() {
		return reserved;
	}

	/**
	 * {@return the module index (currently reserved)}
	 */
	public short getModuleIndex() {
		return moduleIndex;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dreloc_record", SIZE);
		struct.setPackingEnabled(true);
		struct.add(DWORD, "shlib", "reserved");
		struct.add(DWORD, "symbol",
			"index into import table of shlib if *_EXT type. low order 16 bits used for module index if *_INT type");
		struct.add(DWORD, "location", "offset of location to patch data-relative");
		struct.add(DWORD, "value",
			"text or data-relative offset to use for patch if internal-type fixup");
		struct.add(BYTE, "type", "type of dreloc record");
		struct.add(BYTE, "reserved", "currently unused");
		struct.add(WORD, "module_index", "reserved");
		struct.setCategoryPath(new CategoryPath("/SOM"));
		return struct;
	}
}
