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

import generic.continues.GenericFactory;
import ghidra.app.util.bin.ByteArrayConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.util.DataConverter;

/**
 * A container class to hold ELF relocations.
 */
public class ElfRelocationTable implements ElfFileSection, ByteArrayConverter {

	private ElfSectionHeader sectionToBeRelocated;

	private ElfSymbolTable symbolTable;

	private ElfSectionHeader relocTableSection; // may be null
	private long fileOffset;
	private long addrOffset;
	private long length;
	private long entrySize;

	private boolean addendTypeReloc;
	private GenericFactory factory;
	private ElfHeader elfHeader;

	private ElfRelocation[] relocs;

	/**
	 * Create an Elf Relocation Table
	 * @param reader
	 * @param header elf header
	 * @param relocTableSection relocation table section header or null if associated with a dynamic table entry
	 * @param fileOffset relocation table file offset
	 * @param addrOffset memory address of relocation table (should already be adjusted for prelink)
	 * @param length length of relocation table in bytes
	 * @param entrySize size of each relocation entry in bytes
	 * @param addendTypeReloc true if addend type relocation table
	 * @param symbolTable associated symbol table
	 * @param sectionToBeRelocated or null for dynamic relocation table
	 * @return Elf relocation table object
	 * @throws IOException
	 */
	static ElfRelocationTable createElfRelocationTable(FactoryBundledWithBinaryReader reader,
			ElfHeader header, ElfSectionHeader relocTableSection, long fileOffset, long addrOffset,
			long length, long entrySize, boolean addendTypeReloc, ElfSymbolTable symbolTable,
			ElfSectionHeader sectionToBeRelocated) throws IOException {
		ElfRelocationTable elfRelocationTable =
			(ElfRelocationTable) reader.getFactory().create(ElfRelocationTable.class);
		elfRelocationTable.initElfRelocationTable(reader, header, relocTableSection, fileOffset,
			addrOffset, length, entrySize, addendTypeReloc, symbolTable, sectionToBeRelocated);
		return elfRelocationTable;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public ElfRelocationTable() {
	}

	private void initElfRelocationTable(FactoryBundledWithBinaryReader reader, ElfHeader header,
			ElfSectionHeader relocTableSection, long fileOffset, long addrOffset, long length,
			long entrySize, boolean addendTypeReloc, ElfSymbolTable symbolTable,
			ElfSectionHeader sectionToBeRelocated) throws IOException {

		this.relocTableSection = relocTableSection;
		this.fileOffset = fileOffset;
		this.addrOffset = addrOffset;
		this.length = length;
		this.entrySize = entrySize;
		this.addendTypeReloc = addendTypeReloc;
		this.elfHeader = header;
		this.factory = reader.getFactory();

		this.sectionToBeRelocated = sectionToBeRelocated;
		this.symbolTable = symbolTable;

		long ptr = reader.getPointerIndex();
		reader.setPointerIndex(fileOffset);

		List<ElfRelocation> relocList = new ArrayList<ElfRelocation>();

		int nRelocs = (int) (length / entrySize);
		for (int relocationIndex = 0; relocationIndex < nRelocs; ++relocationIndex) {
			relocList.add(ElfRelocation.createElfRelocation(reader, header, relocationIndex,
				addendTypeReloc));
		}

		reader.setPointerIndex(ptr);

		relocs = new ElfRelocation[relocList.size()];
		relocList.toArray(relocs);
	}

	/**
	 * @return true if has addend relocations, otherwise addend extraction from
	 * relocation target may be required
	 */
	public boolean hasAddendRelocations() {
		return addendTypeReloc;
	}

	/**
	 * Returns the section where the relocations will be applied.
	 * For example, this method will return ".plt" for ".rel.plt"
	 * @return the section where the relocations will be applied
	 * or null for dynamic relocation table not associated with 
	 * a section.
	 */
	public ElfSectionHeader getSectionToBeRelocated() {
		return sectionToBeRelocated;
	}

	/**
	 * Returns the relocations defined in this table.
	 * @return the relocations defined in this table
	 */
	public ElfRelocation[] getRelocations() {
		return relocs;
	}

	/**
	 * Get number of relocation entries contained within this table
	 * @return relocation entry count
	 */
	public int getRelocationCount() {
		return relocs.length;
	}

	/**
	 * Returns the associated symbol table.
	 * A relocation object contains a symbol index.
	 * This index is into this symbol table.
	 * @return the associated symbol table
	 */
	public ElfSymbolTable getAssociatedSymbolTable() {
		return symbolTable;
	}

	/**
	 * @see ghidra.app.util.bin.ByteArrayConverter#toBytes(ghidra.util.DataConverter)
	 */
	@Override
	public byte[] toBytes(DataConverter dc) {
		byte[] bytes = new byte[relocs.length * relocs[0].sizeof()];
		int index = 0;
		for (int i = 0; i < relocs.length; i++) {
			byte[] relocBytes = relocs[i].toBytes(dc);
			System.arraycopy(relocBytes, 0, bytes, index, relocBytes.length);
			index += relocBytes.length;
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
	 * Get section header which corresponds to this table, or null
	 * if only associated with a dynamic table entry
	 * @return relocation table section header or null
	 */
	public ElfSectionHeader getTableSectionHeader() {
		return relocTableSection;
	}

	@Override
	public long getFileOffset() {
		return fileOffset;
	}

	@Override
	public int getEntrySize() {
		return (int) entrySize;
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	@Override
	public DataType toDataType() {
		ElfRelocation relocationRepresentative =
			ElfRelocation.createElfRelocation(factory, elfHeader, -1, addendTypeReloc);
		DataType relocEntryDataType = relocationRepresentative.toDataType();
		return new ArrayDataType(relocEntryDataType, (int) (length / entrySize), (int) entrySize);
	}

}
