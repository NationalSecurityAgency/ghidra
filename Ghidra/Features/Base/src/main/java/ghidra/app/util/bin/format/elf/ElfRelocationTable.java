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

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.*;
import ghidra.util.Msg;

/**
 * A container class to hold ELF relocations.
 */
public class ElfRelocationTable implements ElfFileSection {

	public enum TableFormat {
		DEFAULT, ANDROID, RELR;
	}

	private final TableFormat format;

	private final ElfSectionHeader sectionToBeRelocated;

	private final ElfSymbolTable symbolTable;

	private final ElfSectionHeader relocTableSection; // may be null
	private final long fileOffset;
	private final long addrOffset;
	private final long length;
	private final long entrySize;

	private final boolean addendTypeReloc;

	private final ElfHeader elfHeader;

	private final ElfRelocation[] relocs;

	/**
	 * Construct an Elf Relocation Table
	 * @param reader byte provider reader (reader is not retained and position is unaffected)
	 * @param header elf header
	 * @param relocTableSection relocation table section header or null if associated with a dynamic table entry
	 * @param fileOffset relocation table file offset
	 * @param addrOffset memory address of relocation table (should already be adjusted for prelink)
	 * @param length length of relocation table in bytes
	 * @param entrySize size of each relocation entry in bytes
	 * @param addendTypeReloc true if addend type relocation table
	 * @param symbolTable associated symbol table (may be null if not applicable)
	 * @param sectionToBeRelocated or null for dynamic relocation table
	 * @param format table format
	 * @throws IOException if an IO or parse error occurs
	 */
	public ElfRelocationTable(BinaryReader reader, ElfHeader header,
			ElfSectionHeader relocTableSection, long fileOffset, long addrOffset, long length,
			long entrySize, boolean addendTypeReloc, ElfSymbolTable symbolTable,
			ElfSectionHeader sectionToBeRelocated, TableFormat format) throws IOException {

		this.elfHeader = header;
		this.relocTableSection = relocTableSection;
		this.fileOffset = fileOffset;
		this.addrOffset = addrOffset;
		this.length = length;
		this.entrySize = (format == TableFormat.DEFAULT && entrySize <= 0)
				? ElfRelocation.getStandardRelocationEntrySize(header.is64Bit(), addendTypeReloc)
				: entrySize;
		this.addendTypeReloc = addendTypeReloc;
		this.format = format;
		this.sectionToBeRelocated = sectionToBeRelocated;
		this.symbolTable = symbolTable;

		BinaryReader relocReader = reader.clone(fileOffset);
		List<ElfRelocation> relocList;
		if (format == TableFormat.RELR) {
			relocList = parseRelrRelocations(relocReader);
		}
		else if (format == TableFormat.ANDROID) {
			relocList = parseAndroidRelocations(relocReader);
		}
		else {
			relocList = parseStandardRelocations(relocReader);
		}
		relocs = new ElfRelocation[relocList.size()];
		relocList.toArray(relocs);
	}

	/**
	 * Determine if required symbol table is missing.  If so, relocations may not be processed.
	 * @return true if required symbol table is missing, else false
	 */
	public boolean isMissingRequiredSymbolTable() {
		if (symbolTable == null) {
			// relocTableSection is may only be null for dynamic relocation table which must
			// have a symbol table.  All other section-based relocation tables require a symbol
			// table if link != 0.  NOTE: There is the possibility that a symbol table is required
			// when link==0 which may result in relocation processing errors if it is missing.
			return relocTableSection == null || relocTableSection.getLink() != 0;
		}
		return false;
	}

	private List<ElfRelocation> parseStandardRelocations(BinaryReader reader) throws IOException {
		List<ElfRelocation> relocations = new ArrayList<>();
		int nRelocs = (int) (length / entrySize);
		for (int relocationIndex = 0; relocationIndex < nRelocs; ++relocationIndex) {
			relocations.add(ElfRelocation.createElfRelocation(reader, elfHeader, relocationIndex,
				addendTypeReloc));
		}
		return relocations;
	}

	private long readNextRelrEntry(BinaryReader reader) throws IOException {
		return entrySize == 8 ? reader.readNextLong() : reader.readNextUnsignedInt();
	}

	private long addRelrEntry(long offset, List<ElfRelocation> relocList) throws IOException {
		relocList.add(ElfRelocation.createElfRelocation(elfHeader, relocList.size(),
			addendTypeReloc, offset, 0, 0));
		return offset + entrySize;
	}

	private long addRelrEntries(long baseOffset, long entry, List<ElfRelocation> relocList)
			throws IOException {
		long offset = baseOffset;
		while (entry != 0) {
			entry >>>= 1;
			if ((entry & 1) != 0) {
				relocList.add(ElfRelocation.createElfRelocation(elfHeader, relocList.size(),
					addendTypeReloc, offset, 0, 0));
			}
			offset += entrySize;
		}
		long nBits = (entrySize * 8) - 1;
		return baseOffset + (nBits * entrySize);
	}

	private List<ElfRelocation> parseRelrRelocations(BinaryReader reader) throws IOException {

		// NOTE: Current implementation supports an entrySize of 8 or 4.  This could be 
		// made more flexable if needed (applies to ElfRelrRelocationTableDataType as well)

		List<ElfRelocation> relocList = new ArrayList<>();
		long remaining = length; // limit to number of bytes specified for RELR table

		long offset = readNextRelrEntry(reader);
		offset = addRelrEntry(offset, relocList);
		remaining -= entrySize;

		while (remaining > 0) {
			long nextValue = readNextRelrEntry(reader);
			if ((nextValue & 1) == 1) {
				offset = addRelrEntries(offset, nextValue, relocList);
			}
			else {
				offset = addRelrEntry(nextValue, relocList);
			}
			remaining -= entrySize;
		}
		return relocList;
	}

	private List<ElfRelocation> parseAndroidRelocations(BinaryReader reader) throws IOException {

		String identifier = reader.readNextAsciiString(4);
		if (!"APS2".equals(identifier)) {
			throw new IOException("Unsupported Android relocation table format");
		}

		List<ElfRelocation> relocations = new ArrayList<>();

		try {
			int relocationIndex = 0;
			long remainingRelocations = reader.readNext(LEB128::signed); // reloc_count
			long offset = reader.readNext(LEB128::signed); // reloc_baseOffset
			long addend = 0;

			while (remainingRelocations > 0) {

				// start new group - read group header (size and flags)

				// group_size
				long groupSize = reader.readNext(LEB128::signed);
				if (groupSize > remainingRelocations) {
					elfHeader.logError("Group relocation count " + groupSize +
						" exceeded total count " + remainingRelocations);
					break;
				}

				// group_flags
				long groupFlags = reader.readNext(LEB128::signed);
				boolean groupedByInfo =
					(groupFlags & AndroidElfRelocationGroup.RELOCATION_GROUPED_BY_INFO_FLAG) != 0;
				boolean groupedByDelta = (groupFlags &
					AndroidElfRelocationGroup.RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) != 0;
				boolean groupedByAddend =
					(groupFlags & AndroidElfRelocationGroup.RELOCATION_GROUPED_BY_ADDEND_FLAG) != 0;
				boolean groupHasAddend =
					(groupFlags & AndroidElfRelocationGroup.RELOCATION_GROUP_HAS_ADDEND_FLAG) != 0;

				// group_offsetDelta (optional)
				long groupOffsetDelta = groupedByDelta ? reader.readNext(LEB128::signed) : 0;

				// group_info (optional)
				long groupRInfo = groupedByInfo ? reader.readNext(LEB128::signed) : 0;

				if (groupHasAddend && groupedByAddend) {
					if (!addendTypeReloc) {
						elfHeader.logError(
							"ELF Android Relocation processing failed.  Unexpected r_addend in android.rel section");
						return List.of();
					}
					// group_addend (optional)
					addend += reader.readNext(LEB128::signed);
				}
				else if (!groupHasAddend) {
					addend = 0;
				}

				// Process all group entries
				for (int i = 0; i < groupSize; i++) {
					// reloc_offset (optional)
					offset += groupedByDelta ? groupOffsetDelta : reader.readNext(LEB128::signed);

					// reloc_info (optional)
					long info = groupedByInfo ? groupRInfo : reader.readNext(LEB128::signed);

					long rAddend = 0;
					if (addendTypeReloc && groupHasAddend) {
						if (!groupedByAddend) {
							// reloc_addend (optional)
							addend += reader.readNext(LEB128::signed);
						}
						rAddend = addend;
					}
					relocations.add(ElfRelocation.createElfRelocation(elfHeader, relocationIndex++,
						addendTypeReloc, offset, info, rAddend));
				}

				remainingRelocations -= groupSize;
			}
		}
		catch (IOException e) {
			Msg.error(this, "Error reading relocations.", e);
		}

		return relocations;
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
	 * @return the associated symbol table or null if not applicable to this reloc table
	 */
	public ElfSymbolTable getAssociatedSymbolTable() {
		return symbolTable;
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

	public boolean isRelrTable() {
		return format == TableFormat.RELR;
	}

	@Override
	public long getFileOffset() {
		return fileOffset;
	}

	@Override
	public int getEntrySize() {
		return (int) entrySize;
	}

	@Override
	public DataType toDataType() throws IOException {
		if (format == TableFormat.RELR) {
			String relrStructureName = "Elf_RelrRelocationTable_" + Long.toHexString(addrOffset);
			return new ElfRelrRelocationTableDataType(relrStructureName, (int) length,
				(int) entrySize);
		}
		else if (format == TableFormat.ANDROID) {
			return new AndroidElfRelocationTableDataType();
		}

		ElfRelocation relocationRepresentative =
			ElfRelocation.createElfRelocation(elfHeader, -1, addendTypeReloc, 0, 0, 0);
		DataType relocEntryDataType = relocationRepresentative.toDataType();
		return new ArrayDataType(relocEntryDataType, (int) (length / entrySize), (int) entrySize);
	}

}
