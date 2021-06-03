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

import ghidra.app.util.bin.ByteArrayConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.data.*;
import ghidra.util.DataConverter;
import ghidra.util.exception.DuplicateNameException;

/**
 * A container class to hold ELF symbols.
 */
public class ElfSymbolTable implements ElfFileSection, ByteArrayConverter {

	private ElfStringTable stringTable;

	private ElfSectionHeader symbolTableSection; // may be null
	private long fileOffset;
	private long addrOffset;
	private long length;
	private long entrySize;
	private int symbolCount;

	private boolean is32bit;
	private boolean isDynamic;

	private ElfSymbol[] symbols;

	/**
	 * Create and parse an Elf symbol table
	 * @param reader
	 * @param header elf header
	 * @param symbolTableSection string table section header or null if associated with a dynamic table entry
	 * @param fileOffset symbol table file offset
	 * @param addrOffset memory address of symbol table (should already be adjusted for prelink)
	 * @param length length of symbol table in bytes of -1 if unknown
	 * @param entrySize size of each symbol entry in bytes
	 * @param stringTable associated string table
	 * @param isDynamic true if symbol table is the dynamic symbol table
	 * @return Elf symbol table object
	 * @throws IOException
	 */
	static ElfSymbolTable createElfSymbolTable(FactoryBundledWithBinaryReader reader,
			ElfHeader header, ElfSectionHeader symbolTableSection, long fileOffset, long addrOffset,
			long length, long entrySize, ElfStringTable stringTable, boolean isDynamic)
			throws IOException {
		ElfSymbolTable elfSymbolTable =
			(ElfSymbolTable) reader.getFactory().create(ElfSymbolTable.class);
		elfSymbolTable.initElfSymbolTable(reader, header, symbolTableSection, fileOffset,
			addrOffset, length, entrySize, stringTable, isDynamic);
		return elfSymbolTable;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public ElfSymbolTable() {
	}

	private void initElfSymbolTable(FactoryBundledWithBinaryReader reader, ElfHeader header,
			ElfSectionHeader symbolTableSection, long fileOffset, long addrOffset, long length,
			long entrySize, ElfStringTable stringTable, boolean isDynamic) throws IOException {

		this.symbolTableSection = symbolTableSection;
		this.fileOffset = fileOffset;
		this.addrOffset = addrOffset;
		this.length = length;
		this.entrySize = entrySize;
		this.stringTable = stringTable;
		this.is32bit = header.is32Bit();
		this.isDynamic = isDynamic;

		long ptr = reader.getPointerIndex();
		reader.setPointerIndex(fileOffset);

		List<ElfSymbol> symbolList = new ArrayList<>();
		symbolCount = (int) (length / entrySize);

		long entryPos = reader.getPointerIndex();

		// load the all the symbol entries first, don't initialize the string name
		// that will be done later to help localize memory access
		for (int i = 0; i < symbolCount; i++) {
			// Reposition reader to start of symbol element since ElfSymbol object 
			// may not consume all symbol element data
			reader.setPointerIndex(entryPos);
			ElfSymbol sym = ElfSymbol.createElfSymbol(reader, i, this, header);
			symbolList.add(sym);
			entryPos += entrySize;
		}

		// sort the entries by the index in the string table, so don't jump around reading
		List<ElfSymbol> sortedList = symbolList.stream().sorted(
			(o1, o2) -> Integer.compare(o1.getName(), o2.getName())).collect(Collectors.toList());

		// initialize the Symbol string names from string table
		for (ElfSymbol sym : sortedList) {
			sym.initSymbolName(reader, stringTable);
		}

		reader.setPointerIndex(ptr);

		symbols = new ElfSymbol[symbolList.size()];
		symbolList.toArray(symbols);
	}

	/**
	 * Returns true if this is the dynamic symbol table
	 * @return true if this is the dynamic symbol table
	 */
	public boolean isDynamic() {
		return isDynamic;
	}

	/**
	 * Returns the associated string table section.
	 * @return the associated string table section
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
	 * Returns all of the symbols defined in this symbol table.
	 * @return all of the symbols defined in this symbol table
	 */
	public ElfSymbol[] getSymbols() {
		return symbols;
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

	/**
	 * Adds the specified symbol into this symbol table.
	 * @param symbol the new symbol to add
	 */
	public void addSymbol(ElfSymbol symbol) {
		ElfSymbol[] tmp = new ElfSymbol[symbols.length + 1];
		System.arraycopy(symbols, 0, tmp, 0, symbols.length);
		tmp[tmp.length - 1] = symbol;
		symbols = tmp;
	}

	/**
	 * @see ghidra.app.util.bin.ByteArrayConverter#toBytes(ghidra.util.DataConverter)
	 */
	@Override
	public byte[] toBytes(DataConverter dc) {
		byte[] bytes = null;
		int index = 0;
		for (int i = 0; i < symbols.length; i++) {
			byte[] symbytes = symbols[i].toBytes(dc);

			//all symbols are the same size, use the first one to determine the
			//total number of bytes
			if (i == 0) {
				bytes = new byte[symbols.length * symbytes.length];
			}

			System.arraycopy(symbytes, 0, bytes, index, symbytes.length);
			index += symbytes.length;
		}
		return bytes;
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
		return new ArrayDataType(struct, (int) (length / entrySize), (int) entrySize);
	}
}
