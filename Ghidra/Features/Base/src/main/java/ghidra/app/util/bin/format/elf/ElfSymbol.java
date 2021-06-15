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
package ghidra.app.util.bin.format.elf;

import java.io.IOException;

import ghidra.app.util.bin.ByteArrayConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.util.Conv;
import ghidra.util.DataConverter;
import ghidra.util.exception.NotFoundException;

/**
 * A class to represent the ELF 32bit and 64bit Symbol data structures.
 * <br>
 * <pre>
 * typedef struct {
 *     Elf32_Word      st_name;     //Symbol name (string tbl index)
 *     Elf32_Addr      st_value;    //Symbol value
 *     Elf32_Word      st_size;     //Symbol size
 *     unsigned char   st_info;     //Symbol type and binding
 *     unsigned char   st_other;    //Symbol visibility
 *     Elf32_Section   st_shndx;    //Section index
 * } Elf32_Sym;
 * 
 * typedef struct {
 *     Elf64_Word       st_name;    //Symbol name (string tbl index)
 *     unsigned char    st_info;    //Symbol type and binding
 *     unsigned char    st_other;   //Symbol visibility
 *     Elf64_Section    st_shndx;   //Section index
 *     Elf64_Addr       st_value;   //Symbol value
 *     Elf64_Xword      st_size;    //Symbol size
 * } Elf64_Sym;
 * 
 * </pre>
 */
public class ElfSymbol implements ByteArrayConverter {
	/**Local symbols are not visible outside the object file containing their definition.*/
	public static final byte STB_LOCAL = 0;
	/**Global symbols are visible to all object files being combined.*/
	public static final byte STB_GLOBAL = 1;
	/**Weak symbols resemble global symbols, but their definitions have lower precedence.*/
	public static final byte STB_WEAK = 2;
	/**Symbol is unique in namespace.*/
	public static final byte STB_GNU_UNIQUE = 10;

	/**The symbol's type is not specified.*/
	public static final byte STT_NOTYPE = 0;
	/**The symbol is associated with a data object, such as a variable, an array, etc.*/
	public static final byte STT_OBJECT = 1;
	/**The symbol is associated with a function or other executable code.*/
	public static final byte STT_FUNC = 2;
	/**The symbol is associated with a section. (Used for relocation and normally have STB_LOCAL binding.)*/
	public static final byte STT_SECTION = 3;
	/** The symbol's name gives the name of the source file associated with the object file.*/
	public static final byte STT_FILE = 4;
	/** An uninitialized common block */
	public static final byte STT_COMMON = 5;

	/**
	 * In object files: st_value contains offset from the beginning of the section
	 * In DSOs:         st_value contains offset in the TLS initialization image (inside of .tdata)
	 * 
	 */
	public static final byte STT_TLS = 6; // thread local storage symbols
	/**Symbol is in support of complex relocation.*/
	public static final byte STT_RELC = 8;
	/**Symbol is in support of complex relocation (signed value).*/
	public static final byte STT_SRELC = 9;

	/**Default symbol visibility rules*/
	public static final byte STV_DEFAULT = 0;
	/**Processor specific hidden class*/
	public static final byte STV_INTERNAL = 1;
	/**Sym unavailable in other modules*/
	public static final byte STV_HIDDEN = 2;
	/**Not preemptible, not exported*/
	public static final byte STV_PROTECTED = 3;

	private ElfHeader header;
	private ElfSymbolTable symbolTable;
	private int symbolTableIndex;

	private int st_name;
	private long st_value;
	private long st_size;
	private byte st_info;
	private byte st_other;
	private short st_shndx;

	private String nameAsString;

	/**
	 * create an ElfSymbol()
	 * Warning! the routine initSymbolName() must be called on the symbol later
	 * to initialize the string name.  This is a performance enhancement.
	 * 
	 * @param reader to read symbol from
	 * @param symbolIndex index of the symbol to read
	 * @param symbolTable symbol table to associate the symbol to
	 * @param header else header
	 * @return newly created ElfSymbol
	 * 
	 * @throws IOException if an issue with reading occurs
	 */
	public static ElfSymbol createElfSymbol(FactoryBundledWithBinaryReader reader, int symbolIndex,
			ElfSymbolTable symbolTable, ElfHeader header) throws IOException {
		ElfSymbol elfSymbol = (ElfSymbol) reader.getFactory().create(ElfSymbol.class);
		elfSymbol.initElfSymbol(reader, symbolIndex, symbolTable, header);
		return elfSymbol;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public ElfSymbol() {
	}

	/**
	 * Creates a new section symbol.
	 * @param header the corresponding ELF header
	 * @param sectionAddress the start address of the section
	 * @param sectionHeaderIndex the index of the section in the section header table
	 * @param name the string name of the section
	 * @param symbolIndex index of symbol within corresponding symbol table
	 * @param symbolTable symbol table
	 * @return the new section symbol
	 */
	public static ElfSymbol createSectionSymbol32(ElfHeader header, long sectionAddress,
			short sectionHeaderIndex, String name, int symbolIndex, ElfSymbolTable symbolTable) {
		return new ElfSymbol(header, name, 0, sectionAddress, 0, STT_SECTION, (byte) 0,
			sectionHeaderIndex, symbolIndex, symbolTable);
	}

	/**
	 * Creates a new global function symbol.
	 * @param header the corresponding ELF header
	 * @param name the byte index of the name
	 * @param nameAsString the string name of the section
	 * @param addr the address of the function
	 * @param symbolIndex index of symbol within corresponding symbol table
	 * @param symbolTable symbol table
	 * @return the new global function symbol
	 */
	public static ElfSymbol createGlobalFunctionSymbol(ElfHeader header, int name,
			String nameAsString, long addr, int symbolIndex, ElfSymbolTable symbolTable) {
		return new ElfSymbol(header, nameAsString, name, addr, 0,
			(byte) ((STB_GLOBAL << 4) | STT_FUNC), (byte) 0, (short) 0, symbolIndex, symbolTable);
	}

	private ElfSymbol(ElfHeader header, String nameAsString, int name, long value, long size,
			byte info, byte other, short sectionHeaderIndex, int symbolIndex,
			ElfSymbolTable symbolTable) {
		this.header = header;
		this.nameAsString = nameAsString;

		this.st_name = name;
		this.st_value = value;
		this.st_size = size;
		this.st_info = info;
		this.st_other = other;
		this.st_shndx = sectionHeaderIndex;

		this.symbolTable = symbolTable;
		this.symbolTableIndex = symbolIndex;
	}

	private void initElfSymbol(FactoryBundledWithBinaryReader reader, int symbolIndex,
			ElfSymbolTable symbolTable, ElfHeader header) throws IOException {
		this.header = header;
		this.symbolTable = symbolTable;
		this.symbolTableIndex = symbolIndex;

		if (header.is32Bit()) {
			st_name = reader.readNextInt();
			st_value = reader.readNextInt() & Conv.INT_MASK;
			st_size = reader.readNextInt() & Conv.INT_MASK;
			st_info = reader.readNextByte();
			st_other = reader.readNextByte();
			st_shndx = reader.readNextShort();
		}
		else {
			st_name = reader.readNextInt();
			st_info = reader.readNextByte();
			st_other = reader.readNextByte();
			st_shndx = reader.readNextShort();
			st_value = reader.readNextLong();
			st_size = reader.readNextLong();
		}

		if (st_name == 0) {
			if (getType() == STT_SECTION) {
				ElfSectionHeader[] sections = header.getSections();
				if (st_shndx < 0 || st_shndx >= sections.length) {
					//invalid section reference...
					//this is a bug in objcopy, whereby sections are removed
					//but the corresponding section symbols are left behind.
				}
				else {
					ElfSectionHeader section = sections[st_shndx];
					nameAsString = section.getNameAsString();
				}
			}
		}
		else {
			// The string name will be initialized later
			// in a call to initSymbolName()
		}
	}

	/**
	 * Initialize the string name of the symbol.
	 * 
	 * NOTE: This routine MUST be called for each
	 * ELFSymbol after the elf symbols have been created.
	 * 
	 * This is done separately from the initial symbol entry read because
	 * the string names are in a separate location.  If they are read
	 * at the same time the reading buffer will jump around and significantly
	 * degrade reading performance.
	 * 
	 * @param reader to read from
	 * @param stringTable stringTable to initialize symbol name
	 */
	public void initSymbolName(FactoryBundledWithBinaryReader reader, ElfStringTable stringTable) {
		if (nameAsString == null) {
			nameAsString = stringTable.readString(reader, st_name);
		}
	}

	/**
	 * Get the symbol table containing this symbol
	 * @return symbol table
	 */
	public ElfSymbolTable getSymbolTable() {
		return symbolTable;
	}

	/**
	 * Get the index of this symbol within the corresponding symbol table.
	 * @return index of this symbol within the corresponding symbol table
	 */
	public int getSymbolTableIndex() {
		return symbolTableIndex;
	}

	/**
	 * Returns true if this symbol's type is not specified.
	 * @return true if this symbol's type is not specified
	 */
	public boolean isNoType() {
		return getType() == STT_NOTYPE;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + st_info;
		result = prime * result + st_name;
		result = prime * result + st_other;
		result = prime * result + st_shndx;
		result = prime * result + (int) (st_size ^ (st_size >>> 32));
		result = prime * result + (int) (st_value ^ (st_value >>> 32));
		result = prime * result + symbolTableIndex;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		ElfSymbol other = (ElfSymbol) obj;
		if (st_info != other.st_info) {
			return false;
		}
		if (st_name != other.st_name) {
			return false;
		}
		if (st_other != other.st_other) {
			return false;
		}
		if (st_shndx != other.st_shndx) {
			return false;
		}
		if (st_size != other.st_size) {
			return false;
		}
		if (st_value != other.st_value) {
			return false;
		}
		if (symbolTableIndex != other.symbolTableIndex) {
			return false;
		}
		return true;
	}

	/**
	 * Returns true if this symbol is local.
	 * Local symbols are not visible outside the object file
	 * containing their definition. Local symbols of the same
	 * name may exist in multiple files without colliding.
	 * @return true if this symbol is local
	 */
	public boolean isLocal() {
		return getBind() == STB_LOCAL;
	}

	/**
	 * Returns true if this symbol is global.
	 * Global symbols are visible to all object files 
	 * being combined. One object file's definition
	 * of a global symbol will satisfy another
	 * file's undefined reference to the same
	 * global symbol.
	 * @return true if this symbol is global
	 */
	public boolean isGlobal() {
		return getBind() == STB_GLOBAL;
	}

	/**
	 * Returns true if this symbol is weak.
	 * Weak symbols resemble global symbols,
	 * but their definitions have lower precedence.
	 * @return true if this symbol is weak
	 */
	public boolean isWeak() {
		return getBind() == STB_WEAK;
	}

	/**
	 * Returns true if this is an external symbol.
	 * A symbol is considered external if it's 
	 * binding is global and it's size is zero.
	 * @return true if this is an external symbol
	 */
	public boolean isExternal() {
		return (isGlobal() || isWeak()) && getValue() == 0 && getSize() == 0 &&
			getType() == STT_NOTYPE &&
			getSectionHeaderIndex() == ElfSectionHeaderConstants.SHT_NULL;
	}

	/**
	 * Returns true if this symbol defines a section.
	 * @return true if this symbol defines a section
	 */
	public boolean isSection() {
		return getType() == STT_SECTION;
	}

	/**
	 * Returns true if this symbol defines a function.
	 * @return true if this symbol defines a function
	 */
	public boolean isFunction() {
		return getType() == STT_FUNC;
	}

	/**
	 * Returns true if this symbol defines an object.
	 * @return true if this symbol defines an object
	 */
	public boolean isObject() {
		return getType() == STT_OBJECT;
	}

	/**
	 * Returns true if this symbol defines a file.
	 * @return true if this symbol defines a file
	 */
	public boolean isFile() {
		return getType() == STT_FILE;
	}

	/**
	 * Returns true if this symbol defines a thread-local symbol.
	 * @return true if this symbol defines a thread-local symbol
	 */
	public boolean isTLS() {
		return getType() == STT_TLS;
	}

	/**
	 * Returns true if the symbol has an absolute 
	 * value that will not change because of relocation.
	 * @return true if the symbol value will not change due to relocation
	 */
	public boolean isAbsolute() {
		return st_shndx == ElfSectionHeaderConstants.SHN_ABS;
	}

	/**
	 * The symbol labels a common block that has not yet been allocated. The symbol's value
	 * gives alignment constraints, similar to a section's sh_addralign member. That is, the
	 * link editor will allocate the storage for the symbol at an address that is a multiple of
	 * st_value. The symbol's size tells how many bytes are required.
	 * @return true if this is a common symbol
	 */
	public boolean isCommon() {
		return st_shndx == ElfSectionHeaderConstants.SHN_COMMON;
	}

	/**
	 * This member specifies the symbol's type and binding attributes.
	 * @return the symbol's type and binding attributes
	 */
	public byte getInfo() {
		return st_info;
	}

	/**
	 * Returns the symbol's visibility. For example, default.
	 * @return the symbol's visibility
	 */
	public byte getVisibility() {
		return (byte) (st_other & 0x03);
	}

	/**
	 * Returns the symbol's binding. For example, global.
	 * @return the symbol's binding
	 */
	public byte getBind() {
		return (byte) (st_info >> 4);
	}

	/**
	 * Returns the symbol's binding. For example, section.
	 * @return the symbol's binding
	 */
	public byte getType() {
		return (byte) (st_info & 0xf);
	}

	/**
	 * This member holds an index into the object file's symbol 
	 * string table, which holds the character representations 
	 * of the symbol names. If the value is non-zero, it represents a
	 * string table index that gives the symbol name.
	 * Otherwise, the symbol table entry has no name.
	 * @return the index to the symbol's name
	 */
	public int getName() {
		return st_name;
	}

	/**
	 * Returns the actual string name for this symbol. The symbol only
	 * stores an byte index into the string table where
	 * the name string is located.
	 * @return the actual string name for this symbol
	 */
	public String getNameAsString() {
		return nameAsString;
	}

	/**
	 * This member currently holds 0 and has no defined meaning.
	 * @return no defined meaning
	 */
	public byte getOther() {
		return st_other;
	}

	/**
	 * Every symbol table entry is "defined" in relation to some section;
	 * this member holds the relevant section header table index.
	 * @return the relevant section header table index
	 */
	public short getSectionHeaderIndex() {
		return st_shndx;
	}

	/**
	 * Many symbols have associated sizes. For example, a data object's size is the number of
	 * bytes contained in the object. This member holds 0 if the symbol has no size or an
	 * unknown size.
	 * @return the symbol's size
	 */
	public long getSize() {
		return st_size;
	}

	/**
	 * This member gives the value of the associated symbol.
	 * Depending on the context, this may be an absolute value, 
	 * an address, etc.
	 * @return the symbol's value
	 */
	public long getValue() {
		return st_value;
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return nameAsString + " - " + "st_value:" + Long.toHexString(st_value) + " - " +
			"st_size: " + Long.toHexString(st_size) + " - " + "st_info: " +
			Integer.toHexString(st_info) + " - " + "st_other: " + Integer.toHexString(st_other) +
			" - " + "st_shndx:" + Integer.toHexString(st_shndx);
	}

	/**
	 * @see ghidra.app.util.bin.ByteArrayConverter#toBytes(ghidra.util.DataConverter)
	 */
	@Override
	public byte[] toBytes(DataConverter dc) {
		// FIXME! BUG!! Symbols can exist without a dynamic table !!
		ElfDynamicTable dynamic = header.getDynamicTable();
		int syment = 0;
		try {
			syment = (int) dynamic.getDynamicValue(ElfDynamicType.DT_SYMENT);
		}
		catch (NotFoundException e) {
			throw new RuntimeException(e);//should never happen!
		}
		byte[] bytes = new byte[syment];
		int index = 0;
		dc.putInt(bytes, 0, st_name);
		index += 4;
		if (header.is32Bit()) {
			dc.putInt(bytes, index, (int) st_value);
			index += 4;
			dc.putInt(bytes, index, (int) st_size);
			index += 4;
		}
		else {
			dc.putLong(bytes, index, st_value);
			index += 8;
			dc.putLong(bytes, index, st_size);
			index += 8;
		}
		bytes[index] = st_info;
		index += 1;
		bytes[index] = st_other;
		index += 1;
		dc.putShort(bytes, index, st_shndx);
		return bytes;
	}

	/**
	 * Sets the value of this symbol. The value is generally an address.
	 * @param value the new value of the symbol
	 */
	public void setValue(long value) {
		this.st_value = (int) value;
	}

}
