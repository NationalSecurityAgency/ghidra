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
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * A container class to hold ELF symbols.
 */
public class ElfSymbolTable implements ElfFileSection {

	static final int ELF64_SYMENT_SIZE = 24;
	static final int ELF32_SYMENT_SIZE = 16;

	private final ElfStringTable stringTable; // may be null
	private final ElfSectionHeader symbolTableSection; // may be null
	private final int[] symbolSectionIndexTable;
	private final long fileOffset;
	private final long addrOffset;
	private final long length;
	private final int entrySize;
	private final int symbolCount;

	private boolean symbolTableTruncated;

	private final boolean is32bit;
	private final boolean isDynamic;

	private final ElfSymbol[] symbols;

	/**
	 * Construct and parse an Elf symbol table
	 * @param reader byte reader (reader is not retained and position is unaffected)
	 * @param header elf header
	 * @param symbolTableSection string table section header or null if associated with a dynamic table entry
	 *           or unable to locate string table.
	 * @param fileOffset symbol table file offset (must be pre-validated)
	 * @param addrOffset memory address of symbol table (should already be adjusted for prelink)
	 * @param entrySize size of each symbol entry in bytes
	 * @param symbolCount number of symbol entries within symbol table
	 * @param symbolTableTruncated true if symbol count was reduced during parse due to constraints
	 * @param stringTable associated string table
	 * @param symbolSectionIndexTable extended symbol section index table (may be null, used when 
	 *           symbol <code>st_shndx == SHN_XINDEX</code>).  See 
	 *           {@link ElfSymbol#getExtendedSectionHeaderIndex()}).
	 * @param isDynamic true if symbol table is the dynamic symbol table
	 * @throws IOException if an IO or parse error occurs
	 */
	public ElfSymbolTable(BinaryReader reader, ElfHeader header,
			ElfSectionHeader symbolTableSection, long fileOffset, long addrOffset,
			int entrySize, int symbolCount, boolean symbolTableTruncated,
			ElfStringTable stringTable,
			int[] symbolSectionIndexTable,
			boolean isDynamic) throws IOException {

		this.is32bit = header.is32Bit();

		this.symbolTableSection = symbolTableSection;
		this.fileOffset = fileOffset;
		this.addrOffset = addrOffset;
		this.entrySize = entrySize;
		this.symbolCount = symbolCount;
		this.length = (long) entrySize * (long) symbolCount;
		this.symbolTableTruncated = symbolTableTruncated;
		this.stringTable = stringTable;
		this.symbolSectionIndexTable = symbolSectionIndexTable;
		this.isDynamic = isDynamic;

		BinaryReader symTableReader = reader.clone(fileOffset);

		List<ElfSymbol> symbolList = new ArrayList<>();

		// load the all the symbol entries first, don't initialize the string name
		// that will be done later to help localize memory access
		long entryPos = fileOffset;
		for (int i = 0; i < symbolCount; i++) {
			// Reposition reader to start of symbol element since ElfSymbol object 
			// may not consume all symbol element data
			symTableReader.setPointerIndex(entryPos);
			ElfSymbol sym = new ElfSymbol(symTableReader, i, this, header);
			symbolList.add(sym);
			entryPos += entrySize;
		}

		// sort the entries by the index in the string table, so don't jump around reading
		List<ElfSymbol> sortedList = symbolList.stream()
				.sorted((o1, o2) -> Integer.compare(o1.getName(), o2.getName()))
				.collect(Collectors.toList());

		// initialize the Symbol string names from string table
		if (stringTable != null) {
			for (ElfSymbol sym : sortedList) {
				sym.initSymbolName(symTableReader, stringTable);
			}
		}

		symbols = new ElfSymbol[symbolList.size()];
		symbolList.toArray(symbols);
	}

	/**
	 * Check if specified symbol entry size is valid and may be cast to a 32-bit integer
	 * @param is32bit true if 32-bit ELF, false of 64-bit Elf
	 * @param entrySize symbol entry size
	 * @return true if entry size is valid
	 */
	static boolean isValidEntrySize(boolean is32bit, long entrySize) {
		int minEntrySize = is32bit ? ELF32_SYMENT_SIZE : ELF64_SYMENT_SIZE;
		return entrySize >= minEntrySize && entrySize <= Integer.MAX_VALUE;
	}

	/**
	 * Returns true if this is the dynamic symbol table
	 * @return true if this is the dynamic symbol table
	 */
	public boolean isDynamic() {
		return isDynamic;
	}

	/**
	 * {@return associated string table section or null if string table not found}
	 */
	public ElfStringTable getStringTable() {
		return stringTable;
	}

	/**
	 * @return number of symbols
	 */
	public int getSymbolCount() {
		return symbolCount;
	}

	/**
	 * {@return true if {@link #getSymbolCount()} was reduced or table entries were truncated 
	 * during parse due to constraints}
	 */
	public boolean hasTruncatedSymbolTable() {
		return symbolTableTruncated;
	}

	/**
	 * Returns all of the symbols defined in this symbol table.
	 * @return all of the symbols defined in this symbol table
	 */
	public ElfSymbol[] getSymbols() {
		return symbols;
	}

	/**
	 * Get the extended symbol section index value for the specified ELF symbol which originated
	 * from this symbol table.   This section index is provided by an associated SHT_SYMTAB_SHNDX 
	 * section when the symbols st_shndx == SHN_XINDEX.
	 * @param sym ELF symbol from this symbol table
	 * @return associated extended section index value or 0 if not defined.
	 */
	public int getExtendedSectionIndex(ElfSymbol sym) {
		if (sym.getSectionHeaderIndex() == ElfSectionHeaderConstants.SHN_XINDEX &&
			symbolSectionIndexTable != null) {
			int symbolTableIndex = sym.getSymbolTableIndex();
			if (symbolTableIndex < symbolSectionIndexTable.length) {
				return symbolSectionIndexTable[symbolTableIndex];
			}
		}
		return 0;
	}

	/**
	 * Returns the index of the specified symbol in this
	 * symbol table.
	 * @param symbol the symbol
	 * @return the index of the specified symbol
	 */
	public int getSymbolIndex(ElfSymbol symbol) {
		for (int i = 0; i < symbols.length; i++) {
			if (symbols[i].equals(symbol)) {
				return i;
			}
		}
		return -1;
	}

	/**
	 * Returns the symbol at the specified address.
	 * @param addr the symbol address
	 * @return the symbol at the specified address
	 */
	public ElfSymbol getSymbolAt(long addr) {
		for (ElfSymbol symbol : symbols) {
			if (symbol.getValue() == addr) {
				return symbol;
			}
		}
		return null;
	}

	/**
	 * Get the Elf symbol which corresponds to the specified index.  Each relocation table
	 * may correspond to a specific symbol table to which the specified symbolIndex will be
	 * applied.
	 * @param symbolIndex symbol index
	 * @return Elf symbol which corresponds to symbol index or <B>null</B> if out of range
	 */
	public final ElfSymbol getSymbol(int symbolIndex) {
		if (symbolIndex < 0 || symbolIndex >= symbols.length) {
			return null;
		}
		return symbols[symbolIndex];
	}

	/**
	 * Get the ELF symbol name which corresponds to the specified index. 
	 * @param symbolIndex symbol index
	 * @return symbol name which corresponds to symbol index or null if out of range
	 */
	public final String getSymbolName(int symbolIndex) {
		ElfSymbol sym = getSymbol(symbolIndex);
		return sym != null ? sym.getNameAsString() : null;
	}

	/**
	 * Get the formatted ELF symbol name which corresponds to the specified index. 
	 * If the name is blank or can not be resolved due to a missing string table the 
	 * literal string <I>&lt;no name&gt;</I> will be returned.  
	 * @param symbolIndex symbol index
	 * @return formatted symbol name which corresponds to symbol index or the 
	 * literal string <I>&lt;no name&gt;</I>
	 */
	public final String getFormattedSymbolName(int symbolIndex) {
		ElfSymbol sym = getSymbol(symbolIndex);
		return sym != null ? sym.getFormattedName() : ElfSymbol.FORMATTED_NO_NAME;
	}

	/**
	 * Returns all of the global symbols.
	 * @return all of the global symbols
	 */
	public ElfSymbol[] getGlobalSymbols() {
		List<ElfSymbol> list = new ArrayList<>();
		for (ElfSymbol symbol : symbols) {
			if (symbol.getBind() == ElfSymbol.STB_GLOBAL) {
				list.add(symbol);
			}
		}
		ElfSymbol[] array = new ElfSymbol[list.size()];
		list.toArray(array);
		return array;
	}

	/**
	 * Returns all of the sources file names.
	 * @return all of the sources file names
	 */
	public String[] getSourceFiles() {
		List<String> list = new ArrayList<>();
		for (ElfSymbol symbol : symbols) {
			if (symbol.getType() == ElfSymbol.STT_FILE) {
				String name = symbol.getNameAsString();
				if (name != null) {
					list.add(symbol.getNameAsString());
				}
			}
		}
		String[] files = new String[list.size()];
		list.toArray(files);
		return files;
	}

	@Override
	public long getLength() {
		return length;
	}

	@Override
	public long getAddressOffset() {
		return addrOffset;
	}

	/**
	 * Get the section header which corresponds to this table, or null
	 * if only associated with a dynamic table entry
	 * @return symbol table section header or null
	 */
	public ElfSectionHeader getTableSectionHeader() {
		return symbolTableSection;
	}

	@Override
	public long getFileOffset() {
		return fileOffset;
	}

	@Override
	public int getEntrySize() {
		return (int) entrySize;
	}

// Comments are repetitive - should refer to Elf documentation 
//	private static String ST_NAME_COMMENT = "index into object file's symbol string table";
//	private static String ST_SIZE_COMMENT = "data object's size";
//	private static String ST_VALUE_COMMENT = "value associated with symbol, usually an address";
//	private static String ST_INFO_COMMENT = "type and binding attributes";
//	private static String ST_OTHER_COMMENT = "0, no defined meaning";
//	private static String ST_SHNDX_COMMENT = "index into string section header";

	@Override
	public DataType toDataType() throws DuplicateNameException {
		if (length > Integer.MAX_VALUE) {
			return null;
		}
		String dtName = is32bit ? "Elf32_Sym" : "Elf64_Sym";
		Structure struct = new StructureDataType(new CategoryPath("/ELF"), dtName, 0);
		struct.add(DWORD, "st_name", null);
		if (is32bit) {
			struct.add(DWORD, "st_value", null);
			struct.add(DWORD, "st_size", null);
			struct.add(BYTE, "st_info", null);
			struct.add(BYTE, "st_other", null);
			struct.add(WORD, "st_shndx", null);
		}
		else {
			struct.add(BYTE, "st_info", null);
			struct.add(BYTE, "st_other", null);
			struct.add(WORD, "st_shndx", null);
			struct.add(QWORD, "st_value", null);
			struct.add(QWORD, "st_size", null);
		}
		int sizeRemaining = getEntrySize() - struct.getLength();
		if (sizeRemaining > 0) {
			struct.add(new ArrayDataType(ByteDataType.dataType, sizeRemaining, 1), "st_unknown",
				null);
		}
		return new ArrayDataType(struct, symbolCount, -1);
	}
}
