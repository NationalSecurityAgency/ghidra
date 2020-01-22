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
package ghidra.app.util.bin.format.coff;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Language;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * A 0x28 byte COFF section header
 */
public class CoffSectionHeader implements StructConverter {

	protected String s_name;       // section name
	protected int s_paddr;      // physical address, aliased s_nlib
	protected int s_vaddr;      // virtual address
	protected int s_size;       // section size
	protected int s_scnptr;     // file pointer to raw data for section
	protected int s_relptr;     // file pointer to relocations
	protected int s_lnnoptr;    // file pointer to line numbers
	protected int s_nreloc;     // number of relocation entries
	protected int s_nlnno;      // number of line number entries
	protected int s_flags;      // flags
	protected short s_reserved;   // reserved
	protected short s_page;       // section page number (load)

	protected CoffFileHeader _header;
	protected List<CoffRelocation> _relocations = new ArrayList<CoffRelocation>();
	protected List<CoffLineNumber> _lineNumbers = new ArrayList<CoffLineNumber>();

	protected CoffSectionHeader() {
	}

	CoffSectionHeader(BinaryReader reader, CoffFileHeader header) throws IOException {
		this._header = header;

		readName(reader);

		s_paddr = reader.readNextInt();
		s_vaddr = reader.readNextInt();
		s_size = reader.readNextInt();
		s_scnptr = reader.readNextInt();
		s_relptr = reader.readNextInt();
		s_lnnoptr = reader.readNextInt();
		s_nreloc = reader.readNextShort() & 0xffff;
		s_nlnno = reader.readNextShort() & 0xffff;
		s_flags = reader.readNextInt();
		s_reserved = 0;
		s_page = 0;
	}

	protected void readName(BinaryReader reader) throws IOException {
		byte[] nameBytes = reader.readNextByteArray(CoffConstants.SECTION_NAME_LENGTH);
		if (nameBytes[0] == 0 && nameBytes[1] == 0 && nameBytes[2] == 0 && nameBytes[3] == 0) {//if 1st 4 bytes are zero, then lookup name in string table

			DataConverter dc = reader.isLittleEndian() ? LittleEndianDataConverter.INSTANCE
					: BigEndianDataConverter.INSTANCE;
			int nameIndex = dc.getInt(nameBytes, 4);//string table index
			int stringTableIndex = _header.getSymbolTablePointer() +
				(_header.getSymbolTableEntries() * CoffConstants.SYMBOL_SIZEOF);
			s_name = reader.readAsciiString(stringTableIndex + nameIndex);
		}
		else {
			s_name = (new String(nameBytes)).trim();
		}
	}

	/**
	 * Returns the section name.
	 * The section name will never be more than eight characters.
	 * @return the section name
	 */
	public String getName() {
		return s_name;
	}

	/**
	 * Returns the physical address offset.
	 * This is the address at which the section 
	 * should be loaded into memory and reflects a addressable word offset.
	 * For linked executables, this is the absolute 
	 * address within the program space.
	 * For unlinked objects, this address is relative
	 * to the object's address space (i.e. the first section
	 * is always at offset zero).
	 * @return the physical address
	 */
	public int getPhysicalAddress() {
		return s_paddr;
	}

	/**
	 * Adds offset to the physical address; this must be performed before
	 * relocations in order to achieve the proper result.
	 * @param offset the offset to add to the physical address
	 */
	public void move(int offset) {
		s_paddr += offset;
	}

	/**
	 * Returns the physical address.
	 * This is the address at which the section 
	 * should be loaded into memory.
	 * For linked executables, this is the absolute 
	 * address within the program space.
	 * For unlinked objects, this address is relative
	 * to the object's address space (i.e. the first section
	 * is always at offset zero).
	 * @return the physical address
	 */
	public Address getPhysicalAddress(Language language) {
		return getAddress(language, s_paddr, this);
	}

	/**
	 * Returns the virtual address.
	 * This value is always the same as s_paddr.
	 * @return the virtual address
	 */
	public int getVirtualAddress() {
		return s_vaddr;
	}

	/**
	 * Returns true if this section is byte oriented and aligned and should assume
	 * an addressable unit size of 1.
	 * @return true if byte aligned, false if word aligned
	 */
	public boolean isExplicitlyByteAligned() {
		return (s_reserved & CoffSectionHeaderReserved.EXPLICITLY_BYTE_ALIGNED) != 0;
	}

	/**
	 * Returns the number of bytes of data stored in the file for this section.
	 * NOTE: This value does not strictly indicate size in bytes.
	 *       For word-oriented machines, this value is represents
	 *       size in words.
	 * @return the number of bytes of data stored in the file for this section
	 */
	public int getSize(Language language) {
		if (isExplicitlyByteAligned()) {
			return s_size;
		}
		Address physicalAddr = getPhysicalAddress(language);
		return s_size * physicalAddr.getAddressSpace().getAddressableUnitSize();
	}

	/**
	 * Returns the file offset to the section data.
	 * @return the file offset to the section data
	 */
	public int getPointerToRawData() {
		return s_scnptr;
	}

	/**
	 * Returns the file offset to the relocations for this section.
	 * @return the file offset to the relocations for this section
	 */
	public int getPointerToRelocations() {
		return s_relptr;
	}

	/**
	 * Returns the file offset to the line numbers for this section.
	 * @return the file offset to the line numbers for this section
	 */
	public int getPointerToLineNumbers() {
		return s_lnnoptr;
	}

	/**
	 * Returns the number of relocations for this section.
	 * @return the number of relocations for this section
	 */
	public int getRelocationCount() {
		return s_nreloc;
	}

	/**
	 * Returns the number of line number entries for this section.
	 * @return the number of line number entries for this section
	 */
	public int getLineNumberCount() {
		return s_nlnno;
	}

	/**
	 * Returns the flags for this section.
	 * @return the flags for this section
	 */
	public int getFlags() {
		return s_flags;
	}

	public short getReserved() {
		return s_reserved;
	}

	public short getPage() {
		return s_page;
	}

	/**
	 * Returns an input stream that will supply the bytes
	 * for this section.
	 * @return the input stream 
	 * @throws IOException if an I/O error occurs
	 */
	public InputStream getRawDataStream(ByteProvider provider, Language language)
			throws IOException {

		// XXX XXX XXX XXX
		// XXX XXX XXX XXX
		// It is NOT CLEAR AT ALL that all big endian, > 1-byte wordsize executables should be BYTE-SWAPPED!!!
		// XXX XXX XXX XXX
		// XXX XXX XXX XXX

		int addressableUnitSize =
			language.getAddressFactory().getDefaultAddressSpace().getAddressableUnitSize();
		if (addressableUnitSize > 1 && language.isBigEndian()) {
			return new BigEndianUnitSizeByteSwapperInputStream(provider.getInputStream(s_scnptr),
				addressableUnitSize);
		}
		return provider.getInputStream(s_scnptr);
	}

	public boolean isProcessedBytes(Language language) {
		int addressableUnitSize =
			language.getAddressFactory().getDefaultAddressSpace().getAddressableUnitSize();
		return addressableUnitSize > 1 && language.isBigEndian();
	}

	/**
	 * Parse the relocations and line number information
	 * for this section.
	 * @throws IOException if an I/O error occurs
	 */
	void parse(BinaryReader reader, CoffFileHeader header, TaskMonitor monitor) throws IOException {
		long origIndex = reader.getPointerIndex();
		try {
			parseRelocations(reader, header, monitor);
			parseLineNumbers(reader, monitor);
		}
		finally {
			reader.setPointerIndex(origIndex);
		}
	}

	private void parseLineNumbers(BinaryReader reader, TaskMonitor monitor) throws IOException {
		reader.setPointerIndex(s_lnnoptr);
		for (int i = 0; i < s_nlnno; ++i) {
			if (monitor.isCancelled()) {
				break;
			}
			_lineNumbers.add(new CoffLineNumber(reader));
		}
	}

	private void parseRelocations(BinaryReader reader, CoffFileHeader header, TaskMonitor monitor)
			throws IOException {
		reader.setPointerIndex(s_relptr);
		for (int i = 0; i < s_nreloc; ++i) {
			if (monitor.isCancelled()) {
				break;
			}
			_relocations.add(new CoffRelocation(reader, header));
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(StructConverterUtil.parseName(getClass()), 0);
		struct.add(new ArrayDataType(ASCII, CoffConstants.SECTION_NAME_LENGTH, ASCII.getLength()),
			"s_name", null);
		struct.add(DWORD, "s_paddr", null);
		struct.add(DWORD, "s_vaddr", null);
		struct.add(DWORD, "s_size", null);
		struct.add(DWORD, "s_scnptr", null);
		struct.add(DWORD, "s_relptr", null);
		struct.add(DWORD, "s_lnnoptr", null);
		struct.add(WORD, "s_nreloc", null);
		struct.add(WORD, "s_nlnno", null);
		struct.add(DWORD, "s_flags", null);
		if (_header.getMagic() == CoffMachineType.TICOFF1MAGIC) {
			struct.add(BYTE, "s_reserved", null);
			struct.add(BYTE, "s_page", null);
		}
		else if (_header.getMagic() == CoffMachineType.TICOFF2MAGIC) {
			struct.add(WORD, "s_reserved", null);
			struct.add(WORD, "s_page", null);
		}
		return struct;
	}

	public boolean isUninitializedData() {
		return ((s_flags & CoffSectionHeaderFlags.STYP_BSS) != 0) || (s_scnptr == 0);
	}

	public boolean isInitializedData() {
		return (s_flags & CoffSectionHeaderFlags.STYP_DATA) != 0 &&
			(s_flags & CoffSectionHeaderFlags.STYP_TEXT) == 0;
	}

	public boolean isData() {
		return isInitializedData() || isUninitializedData();
	}

	public boolean isReadable() {
		return true;
	}

	public boolean isGroup() {
		return (s_flags & CoffSectionHeaderFlags.STYP_GROUP) != 0;
	}

	public boolean isWritable() {
		return (s_flags & CoffSectionHeaderFlags.STYP_TEXT) == 0;
	}

	public boolean isExecutable() {
		return (s_flags & CoffSectionHeaderFlags.STYP_TEXT) != 0;
	}

	public boolean isAllocated() {
		return (s_flags & CoffSectionHeaderFlags.STYP_COPY) == 0 &&
			(s_flags & CoffSectionHeaderFlags.STYP_PAD) == 0 &&
//			(s_flags & CoffSectionHeaderFlags.STYP_OVER) == 0 &&
			(s_flags & CoffSectionHeaderFlags.STYP_DSECT) == 0;
	}

	public List<CoffRelocation> getRelocations() {
		return new ArrayList<CoffRelocation>(_relocations);
	}

	public List<CoffLineNumber> getLineNumbers() {
		return new ArrayList<CoffLineNumber>(_lineNumbers);
	}

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append(getName());
		buffer.append(' ');
		buffer.append("PhysAddr:0x" + Integer.toHexString(s_paddr));
		buffer.append(' ');
		buffer.append("Size:0x" + Integer.toHexString(s_size));
		buffer.append(' ');
		buffer.append("Flags:0x" + Integer.toHexString(s_flags));
		buffer.append(' ');
		return buffer.toString();
	}

	private static int getOffsetUnitSize(Language language, CoffSectionHeader section) {
		// Assumes all offset utilize a consistent unit size based upon the code space.
		// Keep notes here when this offset characterization is violated and a new one established.
		//   TMS320C55x appears to use byte offsets (unit sizes: code=1 data=2)
		AddressSpace codeSpace = language.getDefaultSpace(); // presumed code space
		if (section == null || !section.isExplicitlyByteAligned()) {
			return codeSpace.getAddressableUnitSize();
		}
		return 1;
	}

	/**
	 * Convert address offset to an Address object.  The default data space (defined by pspec)
	 * will be used if section is null or corresponds to a data section.  The language default
	 * space (defined by slaspec) will be used for all non-data sections.  If pspec does not 
	 * specify a default data space, the default language space is used.
	 * @param language
	 * @param offset address offset (byte offset assumed if section is null or is not explicitly
	 * byte aligned, otherwise word offset assumed).
	 * @param section section which contains the specified offset or null (data space assumed)
	 * @return address object
	 */
	public static Address getAddress(Language language, long offset, CoffSectionHeader section) {
		boolean isData = section == null || section.isData();
		AddressSpace space = isData ? language.getDefaultDataSpace() : language.getDefaultSpace();
		return space.getAddress(offset * getOffsetUnitSize(language, section));
	}

	/**
	 * Convert address offset to an Address in the specified space (defined by pspec).
	 * If pspec does not specify a default data space, the default language space is used.
	 * @param language
	 * @param offset address offset (word offset assumed).
	 * @param space address space
	 * @return address object
	 */
	public static Address getAddress(Language language, long offset, AddressSpace space) {
		return space.getAddress(offset * getOffsetUnitSize(language, null));
	}
}
