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
import java.io.RandomAccessFile;
import java.util.HashMap;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.*;
import ghidra.program.model.data.*;
import ghidra.util.*;

/**
 * An executable or shared object file's program header table is an 
 * array of structures, each describing a segment
 * or other information the system needs to prepare the program for execution. 
 * An object file segment contains one or more sections. 
 * Program headers are meaningful only for executable 
 * and shared object files. A file specifies its 
 * own program header size with the ELF
 * header's e_phentsize and e_phnum members.
 * Some entries describe process segments; others give supplementary information and do not contribute to
 * the process image. Segment entries may appear in any order. Except for PT_LOAD segment 
 * entries which must appear in ascending order, sorted on the p_vaddr member.
 * <br>
 * <pre>
 * typedef struct {
 *     Elf32_Word   p_type;
 *     Elf32_Off    p_offset;
 *     Elf32_Addr   p_vaddr;
 *     Elf32_Addr   p_paddr;
 *     Elf32_Word   p_filesz;
 *     Elf32_Word   p_memsz;
 *     Elf32_Word   p_flags;
 *     Elf32_Word   p_align;
 * } Elf32_Phdr;
 * 
 * typedef struct {
 *     Elf64_Word   p_type;         //Segment type
 *     Elf64_Word   p_flags;        //Segment flags
 *     Elf64_Off    p_offset;       //Segment file offset
 *     Elf64_Addr   p_vaddr;        //Segment virtual address
 *     Elf64_Addr   p_paddr;        //Segment physical address
 *     Elf64_Xword  p_filesz;       //Segment size in file
 *     Elf64_Xword  p_memsz;        //Segment size in memory
 *     Elf64_Xword  p_align;        //Segment alignment
 * } Elf64_Phdr;
 * </pre>
 */
public class ElfProgramHeader
		implements StructConverter, Comparable<ElfProgramHeader>, Writeable, MemoryLoadable {

	protected ElfHeader header;

	private int p_type;
	private int p_flags;
	private long p_offset;
	private long p_vaddr;
	private long p_paddr;
	private long p_filesz;
	private long p_memsz;
	private long p_align;

	private FactoryBundledWithBinaryReader reader;

	static ElfProgramHeader createElfProgramHeader(FactoryBundledWithBinaryReader reader,
			ElfHeader header) throws IOException {
		ElfProgramHeader elfProgramHeader =
			(ElfProgramHeader) reader.getFactory().create(ElfProgramHeader.class);
		elfProgramHeader.initElfProgramHeader(reader, header);
		return elfProgramHeader;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public ElfProgramHeader() {
	}

	protected void initElfProgramHeader(FactoryBundledWithBinaryReader reader, ElfHeader header)
			throws IOException {
		this.header = header;
		this.reader = reader;

		if (header.is32Bit()) {
			p_type = reader.readNextInt();
			p_offset = reader.readNextInt() & Conv.INT_MASK;
			p_vaddr = reader.readNextInt() & Conv.INT_MASK;
			p_paddr = reader.readNextInt() & Conv.INT_MASK;
			p_filesz = reader.readNextInt() & Conv.INT_MASK;
			p_memsz = reader.readNextInt() & Conv.INT_MASK;
			p_flags = reader.readNextInt();
			p_align = reader.readNextInt() & Conv.INT_MASK;
		}
		else if (header.is64Bit()) {
			p_type = reader.readNextInt();
			p_flags = reader.readNextInt();
			p_offset = reader.readNextLong();
			p_vaddr = reader.readNextLong();
			p_paddr = reader.readNextLong();
			p_filesz = reader.readNextLong();
			p_memsz = reader.readNextLong();
			p_align = reader.readNextLong();
		}

		if (p_memsz > p_filesz) {
			//This case occurs when the data segment has both
			//initialized and uninitialized sections.
			//For example, the data program header may be comprised
			//of ".data", ".dynamic", ".ctors", ".dtors", ".jcr", 
			//and ".bss".
			//TODO Err.warn(this, "Program Header: extra bytes");
		}
	}

	/**
	 * Constructs a new program header with the specified type.
	 * @param type the new type of the program header
	 */
	public ElfProgramHeader(ElfHeader header, int type) {
		this.header = header;

		p_type = type;
		p_flags = ElfProgramHeaderConstants.PF_R | ElfProgramHeaderConstants.PF_W |
			ElfProgramHeaderConstants.PF_X;
		p_align = 0x1000;
		p_paddr = 0xffffffff;
		p_vaddr = 0xffffffff;
	}

	/**
	 * Return ElfHeader associated with this program header
	 * @return ElfHeader
	 */
	public ElfHeader getElfHeader() {
		return header;
	}

	/**
	 * @see ghidra.app.util.bin.format.Writeable#write(java.io.RandomAccessFile, ghidra.util.DataConverter)
	 */
	@Override
	public void write(RandomAccessFile raf, DataConverter dc) throws IOException {
		if (header.is32Bit()) {
			raf.write(dc.getBytes(p_type));
			raf.write(dc.getBytes((int) p_offset));
			raf.write(dc.getBytes((int) p_vaddr));
			raf.write(dc.getBytes((int) p_paddr));
			raf.write(dc.getBytes((int) p_filesz));
			raf.write(dc.getBytes((int) p_memsz));
			raf.write(dc.getBytes(p_flags));
			raf.write(dc.getBytes((int) p_align));
		}
		else if (header.is64Bit()) {
			raf.write(dc.getBytes(p_flags));
			raf.write(dc.getBytes(p_type));
			raf.write(dc.getBytes(p_offset));
			raf.write(dc.getBytes(p_vaddr));
			raf.write(dc.getBytes(p_paddr));
			raf.write(dc.getBytes(p_filesz));
			raf.write(dc.getBytes(p_memsz));
			raf.write(dc.getBytes(p_align));
		}
	}

	/**
	 * Get header type as string.  ElfProgramHeaderType name will be returned
	 * if know, otherwise a numeric name of the form "PT_0x12345678" will be returned.
	 * @return header type as string
	 */
	public String getTypeAsString() {
		ElfProgramHeaderType programHeaderType = header.getProgramHeaderType(p_type);
		if (programHeaderType != null) {
			return programHeaderType.name;
		}
		return "PT_0x" + StringUtilities.pad(Integer.toHexString(p_type), '0', 8);
	}

	@Override
	public String toString() {
		return getTypeAsString();
	}

	/**
	 * Get header description
	 * @return header description
	 */
	public String getDescription() {
		ElfProgramHeaderType programHeaderType = header.getProgramHeaderType(p_type);
		if (programHeaderType != null) {
			String description = programHeaderType.description;
			if (description != null && description.length() != 0) {
				return programHeaderType.description;
			}
		}
		return null;
	}

	/**
	 * Get descriptive comment which includes type and description
	 * @return descriptive comment
	 */
	public String getComment() {
		String description = getDescription();
		if (description != null) {
			return getTypeAsString() + " - " + description;
		}
		return getTypeAsString();
	}

	/**
	 * As ''Program Loading'' later in this part describes, loadable process segments must have
	 * congruent values for p_vaddr and p_offset, modulo the page size. This member
	 * gives the value to which the segments are aligned in memory and in the file. Values 0
	 * and 1 mean no alignment is required. Otherwise, p_align should be a positive, integral
	 * power of 2, and p_vaddr should equal p_offset, modulo p_align.
	 * @return the segment alignment value
	 */
	public long getAlign() {
		return p_align;
	}

	/**
	 * This member gives the number of bytes in the file image of the segment; it may be zero.
	 * @return the number of bytes in the file image
	 */
	public long getFileSize() {
		return p_filesz;
	}

	/**
	 * This member gives flags relevant to the segment. Defined flag values appear below.
	 * @return the segment flags
	 */
	public int getFlags() {
		return p_flags;
	}

	public void setFlags(int flags) {
		this.p_flags = flags;
	}

	/**
	 * Returns true if this segment is readable when loaded
	 * @return true if this segment is readable when loaded
	 */
	public boolean isRead() {
		return header.getLoadAdapter().isSegmentReadable(this);
	}

	/**
	 * Returns true if this segment is writable when loaded
	 * @return true if this segment is writable when loaded
	 */
	public boolean isWrite() {
		return header.getLoadAdapter().isSegmentWritable(this);
	}

	/**
	 * Returns true if this segment is executable when loaded
	 * @return true if this segment is executable when loaded
	 */
	public boolean isExecute() {
		return header.getLoadAdapter().isSegmentExecutable(this);
	}

	/**
	 * Get the unadjusted memory size in bytes specified by this program header; it may be zero.
	 * @return the unadjusted memory size in bytes specified by this program header
	 */
	public long getMemorySize() {
		return p_memsz;
	}

	/**
	 * Get the adjusted memory size in bytes of the memory block which relates to this program header; it may be zero
	 * if no block should be created.  The returned value reflects any adjustment the ElfExtension may require
	 * based upon the specific processor/language implementation which may require filtering of file bytes
	 * as loaded into memory.
	 * @return the number of bytes in the resulting memory block
	 */
	public long getAdjustedMemorySize() {
		return header.getLoadAdapter().getAdjustedMemorySize(this);
	}

	/**
	 * Get the adjusted file load size (i.e., filtered load size) to be loaded into memory block which relates to 
	 * this program header; it may be zero if no block should be created.  The returned value reflects any adjustment 
	 * the ElfExtension may require based upon the specific processor/language implementation which may 
	 * require filtering of file bytes as loaded into memory.
	 * @return the number of bytes to be loaded into the resulting memory block
	 */
	public long getAdjustedLoadSize() {
		return header.getLoadAdapter().getAdjustedLoadSize(this);
	}

	/**
	 * Returns the binary reader.
	 * @return the binary reader
	 */
	public BinaryReader getReader() {
		return reader;
	}

	/**
	 * This member gives the offset from the beginning of the file at which 
	 * the first byte of the segment resides.
	 * @return the offset from the beginning of the file
	 */
	public long getOffset() {
		return p_offset;
	}

	/**
	 * Compute the file offset associated with the specified loaded virtual address 
	 * defined by this PT_LOAD program header.  This can be useful when attempting to locate
	 * addresses defined by the PT_DYNAMIC section.
	 * @param virtualAddress a memory address which has already had the PRElink adjustment applied
	 * @return computed file offset or -1 if virtual address not contained within this header
	 * @see ElfHeader#getProgramLoadHeaderContaining(long) for obtaining PT_LOAD segment which contains
	 * virtualAddress
	 */
	public long getOffset(long virtualAddress) { // TODO: addressable unit size to byte offset may be a problem
		if (p_type != ElfProgramHeaderConstants.PT_LOAD || p_filesz == 0 || p_memsz == 0) {
			throw new UnsupportedOperationException("virtualAddress not loaded by this segment");
		}
		if (getMemorySize() != getAdjustedMemorySize()) {
			// TODO: unsure if we will encounter this situation 
			throw new UnsupportedOperationException("unsupported use of filtered load segment");
		}
		// TODO: additional validation of this approach is needed
		long addressableUnitSize = p_filesz / getAdjustedLoadSize();
		return (addressableUnitSize * (virtualAddress - getVirtualAddress())) + p_offset;
	}

	/**
	 * Set the offset. This value is the byte offset into
	 * the ELF file.
	 * @param offset the new offset value
	 */
	public void setOffset(long offset) {
		this.p_offset = offset;
	}

	/**
	 * Sets the file and memory size.
	 * Note: the file size can be less than or
	 * equal to the memory size. It cannot be larger.
	 * If the file size is less than the memory size,
	 * then the rest of the space is considered to be
	 * uninitialized.
	 * @param fileSize the new file size
	 * @param memSize  the new memory size
	 */
	public void setSize(long fileSize, long memSize) {
		p_filesz = fileSize;
		p_memsz = memSize;
	}

	/**
	 * On systems for which physical addressing is relevant, this member is reserved for the
	 * segment's physical address. Because System V ignores physical addressing for application
	 * programs, this member has unspecified contents for executable files and shared objects.
	 * @return the segment's physical address
	 */
	public long getPhysicalAddress() {
		return header.adjustAddressForPrelink(p_paddr);
	}

	/**
	 * This member tells what kind of segment this array element describes or how to interpret
	 * the array element's information. Type values and their meanings appear below.
	 * @return the program header type
	 */
	public int getType() {
		return p_type;
	}

	/**
	 * This member gives the virtual address at which the first 
	 * byte of the segment resides in memory.
	 * @return the virtual address
	 */
	public long getVirtualAddress() {
		return header.adjustAddressForPrelink(p_vaddr);
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	@Override
	public DataType toDataType() {
		String dtName = header.is32Bit() ? "Elf32_Phdr" : "Elf64_Phdr";
		StructureDataType struct = new StructureDataType(new CategoryPath("/ELF"), dtName, 0);
		if (header.is32Bit()) {
			struct.add(getTypeDataType(), "p_type", null);
			struct.add(DWORD, "p_offset", null);
			struct.add(DWORD, "p_vaddr", null);
			struct.add(DWORD, "p_paddr", null);
			struct.add(DWORD, "p_filesz", null);
			struct.add(DWORD, "p_memsz", null);
			struct.add(DWORD, "p_flags", null);
			struct.add(DWORD, "p_align", null);
		}
		else {
			struct.add(getTypeDataType(), "p_type", null);
			struct.add(DWORD, "p_flags", null);
			struct.add(QWORD, "p_offset", null);
			struct.add(QWORD, "p_vaddr", null);
			struct.add(QWORD, "p_paddr", null);
			struct.add(QWORD, "p_filesz", null);
			struct.add(QWORD, "p_memsz", null);
			struct.add(QWORD, "p_align", null);
		}
		return struct;
	}

	private DataType getTypeDataType() {

		HashMap<Integer, ElfProgramHeaderType> programHeaderTypeMap =
			header.getProgramHeaderTypeMap();
		if (programHeaderTypeMap == null) {
			return DWordDataType.dataType;
		}

		String dtName = "Elf_ProgramHeaderType";

		String typeSuffix = header.getTypeSuffix();
		if (typeSuffix != null) {
			dtName = dtName + typeSuffix;
		}

		EnumDataType typeEnum = new EnumDataType(new CategoryPath("/ELF"), dtName, 4);
		for (ElfProgramHeaderType type : programHeaderTypeMap.values()) {
			typeEnum.add(type.name, type.value);
		}
		return typeEnum;
	}

	/**
	 * Sets the new physical and virtual addresses
	 * @param paddr the new physical address
	 * @param vaddr the new virtual address
	 */
	public void setAddress(long paddr, long vaddr) {
		this.p_paddr = header.unadjustAddressForPrelink(paddr);
		this.p_vaddr = header.unadjustAddressForPrelink(vaddr);
	}

	/**
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(ElfProgramHeader that) {
		//sort the headers putting 0xffffffff (new guys)
		//at the bottom...
		if (this.p_type == ElfProgramHeaderConstants.PT_LOAD) {
			if (this.p_vaddr < that.p_vaddr) {
				if (this.p_vaddr == 0xffffffff) {
					return 1;
				}
				return -1;
			}
			else if (this.p_vaddr > that.p_vaddr) {
				if (that.p_vaddr == 0xffffffff) {
					return -1;
				}
				return 1;
			}
		}
		return 0;
	}

	@Override
	public int hashCode() {
		return (int) ((31 * p_offset) + (p_offset >>> 32));
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof ElfProgramHeader)) {
			return false;
		}
		ElfProgramHeader other = (ElfProgramHeader) obj;
		return reader == other.reader && p_type == other.p_type && p_flags == other.p_flags &&
			p_offset == other.p_offset && p_vaddr == other.p_vaddr && p_paddr == other.p_paddr &&
			p_filesz == other.p_filesz && p_memsz == other.p_memsz && p_align == other.p_align;
	}
}
