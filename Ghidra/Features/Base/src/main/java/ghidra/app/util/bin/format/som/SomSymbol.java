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
 * Represents a SOM {@code symbol_dictionary_record} structure
 * 
 * @see <a href="https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf">The 32-bit PA-RISC Run-time Architecture Document</a> 
 */
public class SomSymbol implements StructConverter {

	/** The size in bytes of a {@link SomSymbol} */
	public static final int SIZE = 0x14;

	private boolean hidden;
	private boolean secondaryDef;
	private int symbolType;
	private int symbolScope;
	private int checkLevel;
	private boolean mustQualify;
	private boolean initiallyFrozen;
	private boolean memoryResident;
	private boolean isCommon;
	private boolean dupCommon;
	private int xleast;
	private int argReloc;
	private String name;
	private String qualifierName;
	private boolean hasLongReturn;
	private boolean noRelocation;
	private boolean isComdat;
	private int reserved;
	private int symbolInfo;
	private long symbolValue;


	/**
	 * Creates a new {@link SomSymbol}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the record
	 * @param symbolStringsLocation The starting index of the symbol strings
	 * @throws IOException if there was an IO-related error
	 */
	public SomSymbol(BinaryReader reader, long symbolStringsLocation) throws IOException {
		int bitfield = reader.readNextInt();
		argReloc = bitfield & 0x3ff;
		xleast = (bitfield >> 10) & 0x3;
		dupCommon = ((bitfield >> 12) & 0x1) != 0;
		isCommon = ((bitfield >> 13) & 0x1) != 0;
		memoryResident = ((bitfield >> 14) & 0x1) != 0;
		initiallyFrozen = ((bitfield >> 15) & 0x1) != 0;
		mustQualify = ((bitfield >> 16) & 0x1) != 0;
		checkLevel = (bitfield >> 17) & 0x7;
		symbolScope = (bitfield >> 20) & 0xf;
		symbolType = (bitfield >> 24) & 0x3f;
		secondaryDef = ((bitfield >> 30) & 0x1) != 0;
		hidden = ((bitfield >> 31) & 0x1) != 0;
		name = reader.readAsciiString(symbolStringsLocation + reader.readNextUnsignedInt());
		qualifierName =
			reader.readAsciiString(symbolStringsLocation + reader.readNextUnsignedInt());
		bitfield = reader.readNextInt();
		symbolInfo = bitfield & 0xffffff;
		reserved = (bitfield >> 24) & 0x1f;
		isComdat = ((bitfield >> 29) & 0x1) != 0;
		noRelocation = ((bitfield >> 30) & 0x1) != 0;
		hasLongReturn = ((bitfield >> 31) & 0x1) != 0;
		symbolValue = reader.readNextUnsignedInt();
	}

	/**
	 * {@return whether or not the symbol is to be hidden from the loader for the purpose of 
	 * resolving external (inter-SOM) references}
	 */
	public boolean isHidden() {
		return hidden;
	}

	/**
	 * {@return whether or not the symbol is a secondary definition and has an additional name
	 * that is preceded by “_”}
	 */
	public boolean isSecondaryDef() {
		return secondaryDef;
	}

	/**
	 * {@return the symbol type}
	 * 
	 * @see SomConstants
	 */
	public int getSymbolType() {
		return symbolType;
	}

	/**
	 * {@return the symbol scope}
	 * 
	 * @see SomConstants
	 */
	public int getSymbolScope() {
		return symbolScope;
	}

	/**
	 * {@return the check level}
	 */
	public int getCheckLevel() {
		return checkLevel;
	}

	/**
	 * {@return whether or not the qualifier name must be used to fully qualify the symbol}
	 */
	public boolean mustQualify() {
		return mustQualify;
	}

	/**
	 * {@return whether or not the code importing or exporting this symbol is to be locked in 
	 * physical memory when the operating system is being booted}
	 */
	public boolean isInitiallyFrozen() {
		return initiallyFrozen;
	}

	/**
	 * {@return whether or the the code that is importing or exporting this symbol is frozen in 
	 * memory}
	 */
	public boolean isMemoryResident() {
		return memoryResident;
	}

	/**
	 * {@return whether or not this symbol is an initialized common data block}
	 */
	public boolean isCommon() {
		return isCommon;
	}

	/**
	 * {@return whether or not this symbol name may conflict with another symbol of the same name if 
	 * both are of type data}
	 */
	public boolean isDupCommon() {
		return dupCommon;
	}

	/**
	 * {@return the execution level that is required to call this entry point}
	 */
	public int getXleast() {
		return xleast;
	}

	/**
	 * {@return the location of the first four words of the parameter list, and the location of the
	 * function return value to the linker and loader}
	 */
	public int getArgReloc() {
		return argReloc;
	}

	/**
	 * {@return the symbol name}
	 */
	public String getName() {
		return name;
	}

	/**
	 * {@return the symbol qualifier name}
	 */
	public String getQualifierName() {
		return qualifierName;
	}

	/**
	 * {@return whether or not the called entry point will have a long return sequence}
	 */
	public boolean hasLongReturn() {
		return hasLongReturn;
	}

	/**
	 * {@return whether or not the called entry point will not require any parameter relocation}
	 */
	public boolean hasNoRelocation() {
		return noRelocation;
	}

	/**
	 * {@return whether or not this symbol identifies as the key symbol for a set of COMDAT 
	 * subspaces}
	 */
	public boolean isComdat() {
		return isComdat;
	}

	/**
	 * {@return the reserved value}
	 */
	public int getReserved() {
		return reserved;
	}

	/**
	 * {@return the symbol info}
	 */
	public int getSymbolInfo() {
		return symbolInfo;
	}

	/**
	 * {@return the symbol value}
	 */
	public long getSymbolValue() {
		return symbolValue;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("symbol_dictionary_record", SIZE);
		struct.setPackingEnabled(true);
		try {
			struct.addBitField(DWORD, 1, "hidden", null);
			struct.addBitField(DWORD, 1, "secondary_def", null);
			struct.addBitField(DWORD, 6, "symbol_type", null);
			struct.addBitField(DWORD, 4, "symbol_scope", null);
			struct.addBitField(DWORD, 3, "check_level", null);
			struct.addBitField(DWORD, 1, "must_qualify", null);
			struct.addBitField(DWORD, 1, "initially_frozen", null);
			struct.addBitField(DWORD, 1, "memory_resident", null);
			struct.addBitField(DWORD, 1, "is_common", null);
			struct.addBitField(DWORD, 1, "dup_common", null);
			struct.addBitField(DWORD, 2, "xleast", null);
			struct.addBitField(DWORD, 10, "arg_reloc", null);
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}
		struct.add(DWORD, "name", null);
		struct.add(DWORD, "qualifier_name", null);
		try {
			struct.addBitField(DWORD, 1, "has_long_return", null);
			struct.addBitField(DWORD, 1, "no_relocation", null);
			struct.addBitField(DWORD, 1, "is_comdat", null);
			struct.addBitField(DWORD, 5, "reserved", null);
			struct.addBitField(DWORD, 24, "symbol_info", null);
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}
		struct.add(DWORD, "symbol_value", null);
		struct.setCategoryPath(new CategoryPath("/SOM"));
		return struct;
	}

	@Override
	public String toString() {
		return "name=%s, type=%d, scope=%d, value = 0x%x".formatted(name, symbolType, symbolScope,
			symbolValue);
	}

}
