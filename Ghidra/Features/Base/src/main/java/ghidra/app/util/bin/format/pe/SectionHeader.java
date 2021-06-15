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
package ghidra.app.util.bin.format.pe;

import java.io.*;

import ghidra.app.util.bin.ByteArrayConverter;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;
import ghidra.util.Conv;
import ghidra.util.DataConverter;
import ghidra.util.exception.DuplicateNameException;

/**
 * A class to the represent the IMAGE_SECTION_HEADER
 * struct as defined in <code>winnt.h</code>.
 * <br>
 * <pre>
 * typedef struct _IMAGE_SECTION_HEADER {
 *    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
 *    union {
 *            DWORD   PhysicalAddress;
 *            DWORD   VirtualSize;			// MANDATORY
 *    } Misc;
 *    DWORD   VirtualAddress;				// MANDATORY
 *    DWORD   SizeOfRawData;				// MANDATORY
 *    DWORD   PointerToRawData;				// MANDATORY
 *    DWORD   PointerToRelocations;
 *    DWORD   PointerToLinenumbers;
 *    WORD    NumberOfRelocations;
 *    WORD    NumberOfLinenumbers;
 *    DWORD   Characteristics;				// MANDATORY
 * } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER; * 
 * </pre>
 * <br>
 * <code>#define IMAGE_SIZEOF_SECTION_HEADER 40</code> * 
 * 
 * 
 */
public class SectionHeader implements StructConverter, ByteArrayConverter {
	/**
	 * The name to use when converting into a structure data type.
	 */
	public final static String NAME = "IMAGE_SECTION_HEADER";
	/**
	 * The size of the section header short name.
	 */
	public final static int IMAGE_SIZEOF_SHORT_NAME = 8;
	/**
	 * The size of the section header.
	 */
	public final static int IMAGE_SIZEOF_SECTION_HEADER = 40;

//  public final static int IMAGE_SCN_TYPE_REG                   = 0x00000000;
//  public final static int IMAGE_SCN_TYPE_DSECT                 = 0x00000001;
//  public final static int IMAGE_SCN_TYPE_NOLOAD                = 0x00000002;
//  public final static int IMAGE_SCN_TYPE_GROUP                 = 0x00000004;
//  public final static int IMAGE_SCN_TYPE_NO_PAD                = 0x00000008;
//  public final static int IMAGE_SCN_TYPE_COPY                  = 0x00000010;
	/**
	 * Section contains code.
	 */
	public final static int IMAGE_SCN_CNT_CODE = 0x00000020;
	/**
	 * Section contains initialized data.
	 */
	public final static int IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
	/**
	 * Section contains uninitialized data.
	 */
	public final static int IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
//  public final static int IMAGE_SCN_LNK_OTHER                  = 0x00000100;
	/**
	 * Section contains information for use by the linker. 
	 * Only exists in OBJs.
	 */
	public final static int IMAGE_SCN_LNK_INFO = 0x00000200;
//  public final static int IMAGE_SCN_TYPE_OVER                  = 0x00000400;
	/**
	 * Section contents will not become part of the image. 
	 * This only appears in OBJ files.
	 */
	public final static int IMAGE_SCN_LNK_REMOVE = 0x00000800;
	/**
	 * Section contents is communal data (comdat). 
	 * Communal data is data (or code) that can be 
	 * defined in multiple OBJs. The linker will select 
	 * one copy to include in the executable. Comdats 
	 * are vital for support of C++ template functions 
	 * and function-level linking. Comdat sections only 
	 * appear in OBJ files.
	 */
	public final static int IMAGE_SCN_LNK_COMDAT = 0x00001000;
//  Reserved.                                                    = 0x00002000; 
//  public final static int IMAGE_SCN_MEM_PROTECTED - Obsolete   = 0x00004000;
	/**
	 * Reset speculative exceptions handling bits in the TLB entries for this section.
	 */
	public final static int IMAGE_SCN_NO_DEFER_SPEC_EXC = 0x00004000;
	/**
	 * Section content can be accessed relative to GP.
	 */
	public final static int IMAGE_SCN_GPREL = 0x00008000;
//  public final static int IMAGE_SCN_MEM_FARDATA                = 0x00008000;
//  public final static int IMAGE_SCN_MEM_SYSHEAP  - Obsolete    = 0x00010000;
//  public final static int IMAGE_SCN_MEM_PURGEABLE              = 0x00020000;
//  public final static int IMAGE_SCN_MEM_16BIT                  = 0x00020000;
//  public final static int IMAGE_SCN_MEM_LOCKED                 = 0x00040000;
//  public final static int IMAGE_SCN_MEM_PRELOAD                = 0x00080000;
	/**
	 * Align on 1-byte boundary.
	 */
	public final static int IMAGE_SCN_ALIGN_1BYTES = 0x00100000;
	/**
	 * Align on 2-byte boundary.
	 */
	public final static int IMAGE_SCN_ALIGN_2BYTES = 0x00200000;
	/**
	 * Align on 4-byte boundary.
	 */
	public final static int IMAGE_SCN_ALIGN_4BYTES = 0x00300000;
	/**
	 * Align on 8-byte boundary.
	 */
	public final static int IMAGE_SCN_ALIGN_8BYTES = 0x00400000;
	/**
	 * Align on 16-byte boundary.
	 */
	public final static int IMAGE_SCN_ALIGN_16BYTES = 0x00500000;
	/**
	 * Align on 32-byte boundary.
	 */
	public final static int IMAGE_SCN_ALIGN_32BYTES = 0x00600000;
	/**
	 * Align on 64-byte boundary.
	 */
	public final static int IMAGE_SCN_ALIGN_64BYTES = 0x00700000;
	/**
	 * Align on 128-byte boundary.
	 */
	public final static int IMAGE_SCN_ALIGN_128BYTES = 0x00800000;
	/**
	 * Align on 256-byte boundary.
	 */
	public final static int IMAGE_SCN_ALIGN_256BYTES = 0x00900000;
	/**
	 * Align on 512-byte boundary.
	 */
	public final static int IMAGE_SCN_ALIGN_512BYTES = 0x00A00000;
	/**
	 * Align on 1024-byte boundary.
	 */
	public final static int IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000;
	/**
	 * Align on 2048-byte boundary.
	 */
	public final static int IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000;
	/**
	 * Align on 4096-byte boundary.
	 */
	public final static int IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000;
	/**
	 * Align on 8192-byte boundary.
	 */
	public final static int IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000;
//  Unused                                                       = 0x00F00000;
//  public final static int IMAGE_SCN_ALIGN_MASK                 = 0x00F00000;
	/**
	 * Section contains extended relocations.
	 */
	public final static int IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000;
	/**
	 * The section can be discarded from the final executable. 
	 * Used to hold information for the linker's use, 
	 * including the .debug$ sections.
	 */
	public final static int IMAGE_SCN_MEM_DISCARDABLE = 0x02000000;
	/**
	 * Section is not cachable.
	 */
	public final static int IMAGE_SCN_MEM_NOT_CACHED = 0x04000000;
	/**
	 * The section is not pageable, so it should 
	 * always be physically present in memory. 
	 * Often used for kernel-mode drivers.
	 */
	public final static int IMAGE_SCN_MEM_NOT_PAGED = 0x08000000;
	/**
	 * Section is shareable. The physical pages containing this 
	 * section's data will be shared between all processes 
	 * that have this executable loaded. Thus, every process 
	 * will see the exact same values for data in this section. 
	 * Useful for making global variables shared between all 
	 * instances of a process. To make a section shared, 
	 * use the /section:name,S linker switch.
	 */
	public final static int IMAGE_SCN_MEM_SHARED = 0x10000000;
	/**
	 * Section is executable.
	 */
	public final static int IMAGE_SCN_MEM_EXECUTE = 0x20000000;
	/**
	 * Section is readable.
	 */
	public final static int IMAGE_SCN_MEM_READ = 0x40000000;
	/**
	 * Section is writeable.
	 */
	public final static int IMAGE_SCN_MEM_WRITE = 0x80000000;

	public final static int NOT_SET = -1;

	private String name;
	private int physicalAddress;
	private int virtualSize;
	private int virtualAddress;
	private int sizeOfRawData;
	private int pointerToRawData;
	private int pointerToRelocations;
	private int pointerToLinenumbers;
	private short numberOfRelocations;
	private short numberOfLinenumbers;
	private int characteristics;

	private FactoryBundledWithBinaryReader reader;
	private long index;

	static SectionHeader createSectionHeader(FactoryBundledWithBinaryReader reader, long index)
			throws IOException {
		SectionHeader sectionHeader =
			(SectionHeader) reader.getFactory().create(SectionHeader.class);
		sectionHeader.initSectionHeader(reader, index);
		return sectionHeader;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public SectionHeader() {
	}

	private void initSectionHeader(FactoryBundledWithBinaryReader reader, long index)
			throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	SectionHeader(MemoryBlock block, OptionalHeader optHeader, int ptr) {
		name = block.getName();
		physicalAddress = virtualSize = (int) block.getSize();
		virtualAddress = (int) block.getStart().getOffset() - (int) optHeader.getImageBase();
		sizeOfRawData =
			PortableExecutable.computeAlignment(virtualSize, optHeader.getFileAlignment());
		pointerToRawData = ptr;
		pointerToLinenumbers = 0;
		pointerToRelocations = 0;
		numberOfLinenumbers = 0;
		numberOfRelocations = 0;
		characteristics = 0;
		if (block.isRead()) {
			characteristics |= SectionFlags.IMAGE_SCN_MEM_READ.getMask();
		}
		if (block.isWrite()) {
			characteristics |= SectionFlags.IMAGE_SCN_MEM_WRITE.getMask();
		}
		if (block.isExecute()) {
			characteristics |= SectionFlags.IMAGE_SCN_MEM_EXECUTE.getMask() |
				SectionFlags.IMAGE_SCN_CNT_CODE.getMask();
		}
		if (block.isExecute()) {
			characteristics |=
				SectionHeader.IMAGE_SCN_MEM_EXECUTE | SectionHeader.IMAGE_SCN_CNT_CODE;
		}
		else if (block.getType() == MemoryBlockType.DEFAULT) {//not executable, then must be data...
			if (block.isInitialized()) {
				characteristics |= SectionFlags.IMAGE_SCN_CNT_INITIALIZED_DATA.getMask();
			}
			else {
				characteristics |= SectionFlags.IMAGE_SCN_CNT_UNINITIALIZED_DATA.getMask();
			}
		}
	}

	/**
	 * Returns the ASCII name of the section. A 
	 * section name is not guaranteed to be 
	 * null-terminated. If you specify a section name 
	 * longer than eight characters, the linker 
	 * truncates it to eight characters in the 
	 * executable. A mechanism exists for allowing 
	 * longer section names in OBJ files. Section 
	 * names often start with a period, but this is 
	 * not a requirement. Section names with a $ in 
	 * the name get special treatment from the linker. 
	 * Sections with identical names prior to the $ 
	 * character are merged. The characters following 
	 * the $ provide an alphabetic ordering for how the 
	 * merged sections appear in the final section. 
	 * There's quite a bit more to the subject of sections 
	 * with $ in the name and how they're combined, but 
	 * the details are outside the scope of this article
	 * 
	 * @return the ASCII name of the section
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns a readable ascii version of the name.
	 * All non-readable characters
	 * are replaced with underscores.
	 * @return a readable ascii version of the name
	 */
	public String getReadableName() {
		StringBuffer buffer = new StringBuffer();
		for (int i = 0; i < name.length(); ++i) {
			char ch = name.charAt(i);
			if (ch >= 0x20 && ch <= 0x7e) {//is readable ascii?
				buffer.append(ch);
			}
			else {
				buffer.append('_');
			}
		}
		return buffer.toString();
	}

	/**
	 * Returns the physical (file) address of this section.
	 * @return the physical (file) address of this section
	 */
	public int getPhysicalAddress() {
		return physicalAddress;
	}

	/**
	 * In executables, returns the RVA where 
	 * the section begins in memory. Should be set to 0 in OBJs.
	 * this section should be loaded into memory.
	 * @return the RVA where the section begins in memory.
	 */
	public int getVirtualAddress() {
		return virtualAddress;
	}

	/**
	 * Returns the actual, used size of the section. 
	 * This field may be larger or 
	 * smaller than the SizeOfRawData field. 
	 * If the VirtualSize is larger, the 
	 * SizeOfRawData field is the size of the 
	 * initialized data from the executable, 
	 * and the remaining bytes up to the VirtualSize 
	 * should be zero-padded. This field is set 
	 * to 0 in OBJ files.
	 * @return the actual, used size of the section
	 */
	public int getVirtualSize() {
		if (virtualSize == 0) {
			return sizeOfRawData;
		}
		return virtualSize;
	}

	/**
	 * Returns the size (in bytes) of data stored for the section 
	 * in the executable or OBJ. 
	 * @return the size (in bytes) of data stored for the section
	 */
	public int getSizeOfRawData() {
		return sizeOfRawData;
	}

	/**
	 * Returns the file offset where the data 
	 * for the section begins. For executables, 
	 * this value must be a multiple of the file 
	 * alignment given in the PE header.
	 * <p>
	 * If a section is uninitialized, this value will be 0.
	 * 
	 * @return the file offset where the data for the section begins
	 */
	public int getPointerToRawData() {
		if (pointerToRawData < 0x200) {
			return 0;
		}
		return pointerToRawData;
	}

	/**
	 * Returns the file offset of relocations for this section. 
	 * @return the file offset of relocations for this section
	 */
	public int getPointerToRelocations() {
		return pointerToRelocations;
	}

	/**
	 * Returns the number of relocations pointed 
	 * to by the PointerToRelocations field. 
	 * @return the number of relocations
	 */
	public short getNumberOfRelocations() {
		return numberOfRelocations;
	}

	/**
	 * Return the file offset for COFF-style line 
	 * numbers for this section. 
	 * @return the file offset for COFF-style line numbers for this section
	 */
	public int getPointerToLinenumbers() {
		return pointerToLinenumbers;
	}

	/**
	 * Returns the flags OR'ed together, indicating the 
	 * attributes of this section. Many of these flags 
	 * can be set with the linker's /SECTION option. 
	 * Common values include those listed in Figure 7.
	 * @return the flags OR'ed together, indicating the attributes of this section
	 */
	public int getCharacteristics() {
		return characteristics;
	}

	/**
	 * Returns the number of line numbers pointed to by the 
	 * NumberOfRelocations field. 
	 * @return the number of line numbers
	 */
	public short getNumberOfLinenumbers() {
		return numberOfLinenumbers;
	}

	@Override
	public byte[] toBytes(DataConverter dc) throws IOException {
		return reader.readByteArray(getPointerToRawData(), getSizeOfRawData());
	}

	/**
	 * Returns an input stream to underlying bytes of this section.
	 * @return an input stream to underlying bytes of this section
	 * @throws IOException if an i/o error occurs.
	 */
	public InputStream getDataStream() throws IOException {
		return reader.getByteProvider().getInputStream(getPointerToRawData());
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		StringBuffer buff = new StringBuffer();

		buff.append("Section Header:" + "\n");
		buff.append("\t" + "name:                 " + name + "\n");
		buff.append("\t" + "physicalAddress:      " + Integer.toHexString(physicalAddress) + "\n");
		buff.append("\t" + "virtualSize:          " + Integer.toHexString(virtualSize) + "\n");
		buff.append("\t" + "virtualAddress:       " + Integer.toHexString(virtualAddress) + "\n");
		buff.append("\t" + "sizeOfRawData:        " + Integer.toHexString(sizeOfRawData) + "\n");
		buff.append("\t" + "pointerToRawData:     " + Integer.toHexString(pointerToRawData) + "\n");
		buff.append(
			"\t" + "pointerToRelocations: " + Integer.toHexString(pointerToRelocations) + "\n");
		buff.append(
			"\t" + "pointerToLinenumbers: " + Integer.toHexString(pointerToLinenumbers) + "\n");
		buff.append(
			"\t" + "numberOfRelocations:  " + Integer.toHexString(numberOfRelocations) + "\n");
		buff.append(
			"\t" + "numberOfLinenumbers:  " + Integer.toHexString(numberOfLinenumbers) + "\n");
		buff.append("\t" + "characteristics:      " + Integer.toHexString(characteristics) + "\n");

		return buff.toString();
	}

	private void parse() throws IOException {
		name = reader.readAsciiString(index, IMAGE_SIZEOF_SHORT_NAME).trim();

		// we need to skip IMAGE_SIZEOF_SHORT_NAME chars no matter what,
		// since those bytes are always allocated
		reader.setPointerIndex(index + IMAGE_SIZEOF_SHORT_NAME);

		physicalAddress = virtualSize = reader.readNextInt();
		virtualAddress = reader.readNextInt();
		sizeOfRawData = reader.readNextInt();
		pointerToRawData = reader.readNextInt();
		pointerToRelocations = reader.readNextInt();
		pointerToLinenumbers = reader.readNextInt();
		numberOfRelocations = reader.readNextShort();
		numberOfLinenumbers = reader.readNextShort();
		characteristics = reader.readNextInt();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException {
		UnionDataType union = new UnionDataType("Misc");
		union.add(DWORD, "PhysicalAddress", null);
		union.add(DWORD, "VirtualSize", null);
		union.setCategoryPath(new CategoryPath("/PE"));

		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.add(new ArrayDataType(ASCII, 8, 1), "Name", null);
		struct.add(union, "Misc", null);
		struct.add(IBO32, "VirtualAddress", null);
		struct.add(DWORD, "SizeOfRawData", null);
		struct.add(DWORD, "PointerToRawData", null);
		struct.add(DWORD, "PointerToRelocations", null);
		struct.add(DWORD, "PointerToLinenumbers", null);
		struct.add(WORD, "NumberOfRelocations", null);
		struct.add(WORD, "NumberOfLinenumbers", null);
		EnumDataType characteristicsEnum = new EnumDataType("SectionFlags", 4);
		characteristicsEnum.setCategoryPath(new CategoryPath("/PE"));
		for (SectionFlags flag : SectionFlags.values()) {
			characteristicsEnum.add(flag.name(), Conv.intToLong(flag.getMask()));
		}
		struct.add(characteristicsEnum, "Characteristics", null);
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}

	/**
	 * Writes this section header to the specified random access file. 
	 * @param raf the random access file
	 * @param dc  the data converter
	 * @throws IOException if an I/O error occurs
	 */
	public void writeHeader(RandomAccessFile raf, DataConverter dc) throws IOException {
		byte[] paddedName = new byte[IMAGE_SIZEOF_SHORT_NAME];
		byte[] nameBytes = name.getBytes();
		System.arraycopy(nameBytes, 0, paddedName, 0,
			Math.min(nameBytes.length, IMAGE_SIZEOF_SHORT_NAME));

		raf.write(paddedName);
		raf.write(dc.getBytes(virtualSize));
		raf.write(dc.getBytes(virtualAddress));
		raf.write(dc.getBytes(sizeOfRawData));
		raf.write(dc.getBytes(pointerToRawData));
		raf.write(dc.getBytes(pointerToRelocations));
		raf.write(dc.getBytes(pointerToLinenumbers));
		raf.write(dc.getBytes(numberOfRelocations));
		raf.write(dc.getBytes(numberOfLinenumbers));
		raf.write(dc.getBytes(characteristics));
	}

	/**
	 * Writes the bytes from this section into the specified random access file.
	 * The bytes will be written starting at the byte position
	 * specified by <code>getPointerToRawData()</code>.
	 * 
	 * @param raf           the random access file
	 * @param rafIndex      the index into the RAF where the bytes will be written
	 * @param dc            the data converter
	 * @param block         the memory block corresponding to this section
	 * @param useBlockBytes if true, then use the bytes from the memory block, 
	 *                      otherwise use the bytes from this section.
	 *  
	 * @throws IOException if there are errors writing to the file
	 * @throws MemoryAccessException if the byte from the memory block cannot be accesses
	 */
	public void writeBytes(RandomAccessFile raf, int rafIndex, DataConverter dc, MemoryBlock block,
			boolean useBlockBytes) throws IOException, MemoryAccessException {

		if (getSizeOfRawData() == 0) {
			return;
		}

		raf.seek(rafIndex);

		//if ((block.getType() == MemoryBlock.INITIALIZED) || (block.getType() == MemoryBlock.LIVE)) {

		if (useBlockBytes) {
			byte[] blockBytes = new byte[(int) block.getSize()];
			block.getBytes(block.getStart(), blockBytes);
			raf.write(blockBytes);
		}
		else {
			raf.write(toBytes(dc));
		}

		int padLength = getSizeOfRawData() - getVirtualSize();
		if (padLength > 0) {
			raf.write(new byte[padLength]);
		}
		//}
	}

	void updatePointers(int offset) {
		if (pointerToRawData > 0) {
			pointerToRawData += offset;
		}
		if (pointerToRelocations > 0) {
			pointerToRelocations += offset;
		}
		if (pointerToLinenumbers > 0) {
			pointerToLinenumbers += offset;
		}
	}

	public void setVirtualSize(int size) {
		this.virtualSize = size;
	}

	public void setSizeOfRawData(int size) {
		this.sizeOfRawData = size;
	}
}
