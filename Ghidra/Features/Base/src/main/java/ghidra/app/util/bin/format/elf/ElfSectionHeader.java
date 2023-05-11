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
import java.io.InputStream;
import java.util.HashMap;
import java.util.function.BiConsumer;
import java.util.zip.InflaterInputStream;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.MemoryLoadable;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.StringUtilities;

/**
 * A class to represent the Elf32_Shdr data structure.
 * <br>
 * <pre>
 * typedef  int32_t  Elf32_Sword;
 * typedef uint32_t  Elf32_Word;
 * typedef uint32_t  Elf32_Addr;
 * 
 * typedef struct {
 *     Elf32_Word    sh_name;       //Section name (string tbl index)
 *     Elf32_Word    sh_type;       //Section type
 *     Elf32_Word    sh_flags;      //Section flags
 *     Elf32_Addr    sh_addr;       //Section virtual addr at execution
 *     Elf32_Off     sh_offset;     //Section file offset
 *     Elf32_Word    sh_size;       //Section size in bytes
 *     Elf32_Word    sh_link;       //Link to another section
 *     Elf32_Word    sh_info;       //Additional section information
 *     Elf32_Word    sh_addralign;  //Section alignment
 *     Elf32_Word    sh_entsize;    //Entry size if section holds table *
 * } Elf32_Shdr;
 * 
 * typedef  uint32_t  Elf64_Word;
 * typedef  uint64_t  Elf64_Xword;
 * typedef  uint64_t  Elf64_Addr;
 * typedef  uint64_t  Elf64_Off;
 * 
 * typedef struct {
 *     Elf64_Word    sh_name;       //Section name (string tbl index)
 *     Elf64_Word    sh_type;       //Section type
 *     Elf64_Xword   sh_flags;      //Section flags
 *     Elf64_Addr    sh_addr;       //Section virtual addr at execution
 *     Elf64_Off     sh_offset;     //Section file offset
 *     Elf64_Xword   sh_size;       //Section size in bytes
 *     Elf64_Word    sh_link;       //Link to another section
 *     Elf64_Word    sh_info;       //Additional section information
 *     Elf64_Xword   sh_addralign;  //Section alignment
 *     Elf64_Xword   sh_entsize;    //Entry size if section holds table *
 * } Elf64_Shdr;
 * </pre>
 */

public class ElfSectionHeader implements StructConverter, MemoryLoadable {

	private int sh_name;
	private int sh_type;
	private long sh_flags;
	private long sh_addr;
	private long sh_offset;
	private long sh_size;
	private int sh_link;
	private int sh_info;
	private long sh_addralign;
	private long sh_entsize;

	private BinaryReader reader;

	private ElfHeader header;
	private String name;
	private byte[] data;
	private boolean modified = false;
	private boolean bytesChanged = false;

	private ElfCompressedSectionHeader compressedHeader;

	public ElfSectionHeader(BinaryReader reader, ElfHeader header)
			throws IOException {
		this.reader = reader;
		this.header = header;

		sh_name = reader.readNextInt();
		sh_type = reader.readNextInt();

		if (header.is32Bit()) {
			sh_flags = Integer.toUnsignedLong(reader.readNextInt());
			sh_addr = Integer.toUnsignedLong(reader.readNextInt());
			sh_offset = Integer.toUnsignedLong(reader.readNextInt());
			sh_size = Integer.toUnsignedLong(reader.readNextInt());
		}
		else if (header.is64Bit()) {
			sh_flags = reader.readNextLong();
			sh_addr = reader.readNextLong();
			sh_offset = reader.readNextLong();
			sh_size = reader.readNextLong();
		}

		sh_link = reader.readNextInt();
		sh_info = reader.readNextInt();

		if (header.is32Bit()) {
			sh_addralign = Integer.toUnsignedLong(reader.readNextInt());
			sh_entsize = Integer.toUnsignedLong(reader.readNextInt());
		}
		else if (header.is64Bit()) {
			sh_addralign = reader.readNextLong();
			sh_entsize = reader.readNextLong();
		}

		if ((sh_flags & ElfSectionHeaderConstants.SHF_COMPRESSED) != 0) {
			compressedHeader = readCompressedSectionHeader();
		}
		//checkSize();
	}

	private ElfCompressedSectionHeader readCompressedSectionHeader() {
		try {
			if (!isValidForCompressed(reader.length())) {
				throw new IOException(
					"Invalid compressed section: %s".formatted(getNameAsString()));
			}
			ElfCompressedSectionHeader result =
				ElfCompressedSectionHeader.read(getRawSectionReader(), header);
			if (!isSupportedCompressionType(result.getCh_type())) {
				throw new IOException("Unknown ELF section compression type 0x%x for section %s"
						.formatted(compressedHeader.getCh_type(), getNameAsString()));
			}
			return result;
		}
		catch (IOException e) {
			Msg.warn(this, "Error reading compressed section information: " + e);
			Msg.debug(this, "Error reading compressed section information", e);
		}
		return null;
	}

	private boolean isValidForCompressed(long streamLength) {
		long endOffset = sh_offset + sh_size;
		return !isAlloc() && sh_offset >= 0 && sh_size > 0 && endOffset > 0 &&
			endOffset <= streamLength;
	}

	ElfSectionHeader(ElfHeader header, MemoryBlock block, int sh_name, long imageBase)
			throws MemoryAccessException {

		this.header = header;
		this.sh_name = sh_name;

		if (block.isInitialized()) {
			sh_type = ElfSectionHeaderConstants.SHT_PROGBITS;
		}
		else {
			sh_type = ElfSectionHeaderConstants.SHT_NOBITS;
		}
		sh_flags = ElfSectionHeaderConstants.SHF_ALLOC | ElfSectionHeaderConstants.SHF_WRITE |
			ElfSectionHeaderConstants.SHF_EXECINSTR;
		sh_addr = block.getStart().getOffset();
		sh_offset = block.getStart().getAddressableWordOffset() - imageBase;
		sh_size = block.getSize();
		sh_link = 0;
		sh_info = 0;
		sh_addralign = 0;
		sh_entsize = 0;
		name = block.getName();

		data = new byte[(int) sh_size];
		if (block.isInitialized()) {
			block.getBytes(block.getStart(), data);
		}

		modified = true;
	}

	ElfSectionHeader(ElfHeader header, String name, int sh_name, int type) {
		this.header = header;
		this.name = name;
		this.sh_name = sh_name;
		this.sh_type = type;

		sh_flags = ElfSectionHeaderConstants.SHF_ALLOC | ElfSectionHeaderConstants.SHF_WRITE |
			ElfSectionHeaderConstants.SHF_EXECINSTR;
		sh_link = 0;
		sh_info = 0;
		sh_addralign = 0;
		sh_entsize = 0;

		data = new byte[0];
		sh_size = 0;
		sh_addr = -1;
		sh_offset = -1;
	}

	/**
	 * Return ElfHeader associated with this section
	 * @return ElfHeader
	 */
	public ElfHeader getElfHeader() {
		return header;
	}

	/**
	 * If the section will appear in the memory image of a process, this 
	 * member gives the address at which the section's first byte 
	 * should reside. Otherwise, the member contains 0.
	 * @return the address of the section in memory
	 */
	public long getAddress() {
		return header.adjustAddressForPrelink(sh_addr);
	}

	/**
	 * Some sections have address alignment constraints. For example, if a section holds a
	 * doubleword, the system must ensure doubleword alignment for the entire section.
	 * That is, the value of sh_addr must be congruent to 0, modulo the value of
	 * sh_addralign. Currently, only 0 and positive integral powers of two are allowed.
	 * Values 0 and 1 mean the section has no alignment constraints.
	 * @return the section address alignment constraints
	 */
	public long getAddressAlignment() {
		return compressedHeader == null
				? sh_addralign
				: compressedHeader.getCh_addralign();
	}

	/**
	 * Some sections hold a table of fixed-size entries, such as a symbol table. For such a section,
	 * this member gives the size in bytes of each entry. The member contains 0 if the
	 * section does not hold a table of fixed-size entries.
	 * @return the section entry size
	 */
	public long getEntrySize() {
		return sh_entsize;
	}

	/**
	 * Sections support 1-bit flags that describe miscellaneous attributes. Flag definitions
	 * appear aove.
	 * @return the section flags
	 */
	public long getFlags() {
		return sh_flags;
	}

	/**
	 * Returns true if this section is writable.
	 * @return true if this section is writable.
	 */
	public boolean isWritable() {
		return header.getLoadAdapter().isSectionWritable(this);
	}

	/**
	 * Returns true if this section is executable.
	 * @return true if this section is executable.
	 */
	public boolean isExecutable() {
		return header.getLoadAdapter().isSectionExecutable(this);
	}

	/**
	 * Returns true if this section is allocated (e.g., SHF_ALLOC is set)
	 * @return true if this section is allocated.
	 */
	public boolean isAlloc() {
		return header.getLoadAdapter().isSectionAllocated(this);
	}

	/**
	 * Returns true if this section is compressed in a supported manner.  This does NOT include
	 * sections that carry compressed data, such as ".zdebuginfo" type sections.
	 * 
	 * @return true if the section was compressed and needs to be decompressed, false if normal
	 * section
	 */
	public boolean isCompressed() {
		return compressedHeader != null;
	}

	private boolean isSupportedCompressionType(int compressionType) {
		return switch ( compressionType ) {
			case ElfCompressedSectionHeader.ELFCOMPRESS_ZLIB -> true;
			default -> false;
		};
	}

	private boolean isNoBits() {
		return sh_type == ElfSectionHeaderConstants.SHT_NOBITS;
	}

	/**
	 * This member holds extra information, whose interpretation 
	 * depends on the section type.
	 *  
	 * If sh_type is SHT_REL or SHT_RELA, then sh_info holds 
	 * the section header index of the
	 * section to which the relocation applies.
	 * 
	 * If sh_type is SHT_SYMTAB or SHT_DYNSYM, then sh_info
	 * holds one greater than the symbol table index of the last
	 * local symbol (binding STB_LOCAL).
	 * 
	 * @return the section header info
	 */
	public int getInfo() {
		return sh_info;
	}

	/**
	 * This member holds extra information, whose interpretation 
	 * depends on the section type.
	 * 
	 * If sh_type is SHT_SYMTAB, SHT_DYNSYM, or SHT_DYNAMIC, 
	 * then sh_link holds the section header table index of
	 * its associated string table.
	 * 
	 * If sh_type is SHT_REL, SHT_RELA, or SHT_HASH
	 * sh_link holds the section header index of the 
	 * associated symbol table.
	 * 
	 * @return the section header link
	 */
	public int getLink() {
		return sh_link;
	}

	/**
	 * An index into the section header string table section, 
	 * giving the location of a null-terminated string which is the name of this section.
	 * @return the index of the section name
	 */
	public int getName() {
		return sh_name;
	}

	void updateName() {
		if (reader == null) {
			throw new UnsupportedOperationException("This ElfSectionHeader does not have a reader");
		}

		ElfSectionHeader[] sections = header.getSections();
		int e_shstrndx = header.e_shstrndx();
		name = null;
		try {
			if (sh_name >= 0 && e_shstrndx > 0 && e_shstrndx < sections.length) {
				// read section name from string table
				if (!sections[e_shstrndx].isInvalidOffset()) {
					long stringTableOffset = sections[e_shstrndx].getOffset();
					long offset = stringTableOffset + sh_name;
					if (offset < reader.length()) {
						name = reader.readAsciiString(stringTableOffset + sh_name);
						if ("".equals(name)) {
							name = null;
						}
					}
				}
			}
		}
		catch (IOException e) {
			// ignore
		}
		if (name == null) {
			name = "NO-NAME";
			for (int i = 0; i < sections.length; ++i) {//find this section's index
				if (sections[i] == this) {
					name = "SECTION" + i;
					break;
				}
			}
		}
	}

	/**
	 * Returns the actual string name for this section. The section only
	 * stores an byte index into the string table where
	 * the name string is located.
	 * @return the actual string name for this section
	 */
	public String getNameAsString() {
		return name;
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return name + " - " + "0x" + Long.toHexString(sh_addr) + ":0x" +
			Long.toHexString(sh_addr + sh_size - 1) + " - 0x" + Long.toHexString(sh_size) + " " +
			" - 0x" + Long.toHexString(sh_offset) + "";
	}

	/**
	 * The byte offset from the beginning of the file to the first
	 * byte in the section.
	 * One section type, SHT_NOBITS described below, occupies no
	 * space in the file, and its sh_offset member locates the conceptual placement in the
	 * file.
	 * @return byte offset from the beginning of the file to the first byte in the section
	 */
	public long getOffset() {
		return sh_offset;
	}

	/**
	 * Returns true if this section header's offset is invalid.
	 * 
	 * @return true if this section header's offset is invalid
	 */
	public boolean isInvalidOffset() {
		return sh_offset < 0 ||
			(header.is32Bit() && sh_offset == ElfConstants.ELF32_INVALID_OFFSET);
	}

	/**
	 * This member gives the section's size in bytes. Unless the section type is
	 * SHT_NOBITS, the section occupies sh_size bytes in the file. A section of type
	 * SHT_NOBITS may have a non-zero size, but it occupies no space in the file.
	 * @return the section's size in bytes
	 */
	public long getSize() {
		return sh_size;
	}

	/**
	 * Returns the logical size of this section, possibly affected by compression.
	 * 
	 * @return logical size of this section, see {@link #getSize()}
	 */
	public long getLogicalSize() {
		return compressedHeader == null
				? sh_size
				: compressedHeader.getCh_size();
	}

	@Override
	public boolean hasFilteredLoadInputStream(ElfLoadHelper elfLoadHelper, Address start) {
		return isCompressed() ||
			header.getLoadAdapter().hasFilteredLoadInputStream(elfLoadHelper, this, start);
	}

	@Override
	public InputStream getFilteredLoadInputStream(ElfLoadHelper elfLoadHelper, Address start,
			long dataLength, BiConsumer<String, Throwable> errorConsumer) throws IOException {
		InputStream is = isCompressed()
				? getDecompressedDataStream(dataLength, errorConsumer)
				: getRawInputStream();
		return header.getLoadAdapter()
				.getFilteredLoadInputStream(elfLoadHelper, this, start, dataLength, is);
	}

	@Override
	public InputStream getRawInputStream() throws IOException {
		return getRawSectionByteProvider().getInputStream(0);
	}

	/**
	 * This member categorizes the section's contents and semantics.
	 * @return the section's contents and semantics
	 */
	public int getType() {
		return sh_type;
	}

	/**
	 * Get header type as string.  ElfSectionHeaderType name will be returned
	 * if know, otherwise a numeric name of the form "SHT_0x12345678" will be returned.
	 * @return header type as string
	 */
	public String getTypeAsString() {
		ElfSectionHeaderType sectionHeaderType = header.getSectionHeaderType(sh_type);
		if (sectionHeaderType != null) {
			return sectionHeaderType.name;
		}
		return "SHT_0x" + StringUtilities.pad(Integer.toHexString(sh_type), '0', 8);
	}

	private InputStream getDecompressedDataStream(long dataLength,
			BiConsumer<String, Throwable> errorConsumer) throws IOException {
		if (compressedHeader == null || dataLength != compressedHeader.getCh_size()) {
			throw new UnsupportedOperationException();
		}

		int skip = compressedHeader.getHeaderSize();
		InputStream is = getRawSectionByteProvider().getInputStream(skip);

		is = getDecompressionStream(is);

		return new FaultTolerantInputStream(is, compressedHeader.getCh_size(), errorConsumer);
	}

	private ByteProvider getRawSectionByteProvider() {
		if (reader == null) {
			throw new UnsupportedOperationException("This ElfSectionHeader does not have a reader");
		}
		if (isNoBits()) {
			return ByteProvider.EMPTY_BYTEPROVIDER;
		}
		return new ByteProviderWrapper(reader.getByteProvider(), sh_offset, sh_size);
	}

	private BinaryReader getRawSectionReader() throws IOException {
		return new BinaryReader(getRawSectionByteProvider(), header.isLittleEndian());
	}

	private InputStream getDecompressionStream(InputStream compressedStream) throws IOException {
		switch (compressedHeader.getCh_type()) {
			case ElfCompressedSectionHeader.ELFCOMPRESS_ZLIB:
				Msg.debug(this,
					"Decompressing ELF section %s, original/decompressed size: 0x%x/0x%x"
							.formatted(getNameAsString(), sh_size, compressedHeader.getCh_size()));
				return new InflaterInputStream(compressedStream);
			default:
				throw new IOException("Unknown ELF section compression type 0x%x for section %s"
						.formatted(compressedHeader.getCh_type(), getNameAsString()));
		}

	}

	/**
	 * Returns the binary reader.
	 * @return the binary reader
	 */
	public BinaryReader getReader() {
		return reader;
	}

	/**
	 * Returns true if the data bytes have changed for this section.
	 * @return true if the data bytes have changed for this section
	 */
	public boolean isBytesChanged() {
		return bytesChanged;
	}

	/**
	 * Returns true if this section has been modified.
	 * A modified section requires that a new program header
	 * get created.
	 * @return true if this section has been modified
	 */
	public boolean isModified() {
		return modified;
	}

	/**
	 * Sets the start address of this section.
	 * @param addr the new start address of this section
	 */
	public void setAddress(long addr) {
		if (!header.isRelocatable() && sh_addr == 0) {
			throw new RuntimeException(
				"Attempting to place non-loaded section into memory :" + name);
		}
		this.sh_addr = header.unadjustAddressForPrelink(addr);
	}
	
	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	@Override
	public DataType toDataType() {
		String dtName = header.is32Bit() ? "Elf32_Shdr" : "Elf64_Shdr";
		StructureDataType struct = new StructureDataType(new CategoryPath("/ELF"), dtName, 0);
		struct.add(DWORD, "sh_name", null);
		struct.add(getTypeDataType(), "sh_type", null);
		if (header.is32Bit()) {
			struct.add(DWORD, "sh_flags", null);
			struct.add(DWORD, "sh_addr", null);
			struct.add(DWORD, "sh_offset", null);
			struct.add(DWORD, "sh_size", null);
		}
		else if (header.is64Bit()) {
			struct.add(QWORD, "sh_flags", null);
			struct.add(QWORD, "sh_addr", null);
			struct.add(QWORD, "sh_offset", null);
			struct.add(QWORD, "sh_size", null);
		}
		struct.add(DWORD, "sh_link", null);
		struct.add(DWORD, "sh_info", null);
		if (header.is32Bit()) {
			struct.add(DWORD, "sh_addralign", null);
			struct.add(DWORD, "sh_entsize", null);
		}
		else if (header.is64Bit()) {
			struct.add(QWORD, "sh_addralign", null);
			struct.add(QWORD, "sh_entsize", null);
		}
		return struct;
	}

	private DataType getTypeDataType() {

		HashMap<Integer, ElfSectionHeaderType> sectionHeaderTypeMap =
			header.getSectionHeaderTypeMap();
		if (sectionHeaderTypeMap == null) {
			return DWordDataType.dataType;
		}

		String dtName = "Elf_SectionHeaderType";

		String typeSuffix = header.getTypeSuffix();
		if (typeSuffix != null) {
			dtName = dtName + typeSuffix;
		}

		EnumDataType typeEnum = new EnumDataType(new CategoryPath("/ELF"), dtName, 4);
		for (ElfSectionHeaderType type : sectionHeaderTypeMap.values()) {
			typeEnum.add(type.name, type.value);
		}
		return typeEnum;
	}

	@Override
	public int hashCode() {
		return (int) ((17 * sh_offset) + (sh_offset >>> 32));
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof ElfSectionHeader)) {
			return false;
		}
		ElfSectionHeader other = (ElfSectionHeader) obj;
		return reader == other.reader && sh_name == other.sh_name && sh_type == other.sh_type &&
			sh_flags == other.sh_flags && sh_addr == other.sh_addr &&
			sh_offset == other.sh_offset && sh_size == other.sh_size && sh_link == other.sh_link &&
			sh_info == other.sh_info && sh_addralign == other.sh_addralign &&
			sh_entsize == other.sh_entsize;
	}

}
