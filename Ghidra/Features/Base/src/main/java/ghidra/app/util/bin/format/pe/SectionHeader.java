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

import java.io.IOException;
import java.io.InputStream;

import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.*;
import ghidra.util.DataConverter;
import ghidra.util.exception.DuplicateNameException;

/// A class to the represent the `IMAGE_SECTION_HEADER` struct as defined in `winnt.h`
/// 
/// ```c
/// typedef struct _IMAGE_SECTION_HEADER {
///     BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
///     union {
///         DWORD   PhysicalAddress;
///         DWORD   VirtualSize;			// MANDATORY
///     } Misc;
///     DWORD   VirtualAddress;				// MANDATORY
///     DWORD   SizeOfRawData;				// MANDATORY
///     DWORD   PointerToRawData;				// MANDATORY
///     DWORD   PointerToRelocations;
///     DWORD   PointerToLinenumbers;
///     WORD    NumberOfRelocations;
///     WORD    NumberOfLinenumbers;
///     DWORD   Characteristics;				// MANDATORY
/// } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
/// 
/// #define IMAGE_SIZEOF_SECTION_HEADER 40
/// ```
public class SectionHeader implements StructConverter, ByteArrayConverter {
	/// The name to use when converting into a structure data type
	public final static String NAME = "IMAGE_SECTION_HEADER";

	/// The size of the section header short name
	public final static int IMAGE_SIZEOF_SHORT_NAME = 8;

	/// The size of the section header
	public final static int IMAGE_SIZEOF_SECTION_HEADER = 40;

	/// Reserved for future use
	public final static int IMAGE_SCN_RESERVED1 = 0x00000000;

	/// Reserved for future use
	public final static int IMAGE_SCN_RESERVED2 = 0x00000001;

	/// Reserved for future use
	public final static int IMAGE_SCN_RESERVED3 = 0x00000002;

	/// Reserved for future use
	public final static int IMAGE_SCN_RESERVED4 = 0x00000004;

	public final static int IMAGE_SCN_TYPE_NO_PAD = 0x00000008;

	/// Reserved for future use
	public final static int IMAGE_SCN_RESERVED5 = 0x00000010;

	/// Section contains code
	public final static int IMAGE_SCN_CNT_CODE = 0x00000020;

	/// Section contains initialized data
	public final static int IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;

	/// Section contains uninitialized data
	public final static int IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;

	/// Reserved for future use
	public final static int IMAGE_SCN_LNK_OTHER = 0x00000100;

	/// Section contains information for use by the linker (only exists in OBJs)
	public final static int IMAGE_SCN_LNK_INFO = 0x00000200;

	/// Reserved for future use
	public final static int IMAGE_SCN_RESERVED6 = 0x00000400;

	/// Section contents will not become part of the image (this only appears in OBJ files)
	public final static int IMAGE_SCN_LNK_REMOVE = 0x00000800;

	/// Section contents is communal data (comdat). Communal data is data (or code) that can be 
	/// defined in multiple OBJs. The linker will select one copy to include in the executable. 
	/// Comdats are vital for support of C++ template functions and function-level linking. Comdat
	/// sections only appear in OBJ files.
	public final static int IMAGE_SCN_LNK_COMDAT = 0x00001000;

	/// Reset speculative exceptions handling bits in the TLB entries for this section
	public final static int IMAGE_SCN_NO_DEFER_SPEC_EXC = 0x00004000;

	/// Section content can be accessed relative to GP
	public final static int IMAGE_SCN_GPREL = 0x00008000;

	/// Reserved for future use
	public final static int IMAGE_SCN_MEM_PURGEABLE = 0x00020000;

	/// Reserved for future use
	public final static int IMAGE_SCN_MEM_16BIT = 0x00020000;

	/// Reserved for future use
	public final static int IMAGE_SCN_MEM_LOCKED = 0x00040000;

	/// Reserved for future use
	public final static int IMAGE_SCN_MEM_PRELOAD = 0x00080000;

	/// Align on 1-byte boundary
	public final static int IMAGE_SCN_ALIGN_1BYTES = 0x00100000;

	/// Align on 2-byte boundary
	public final static int IMAGE_SCN_ALIGN_2BYTES = 0x00200000;

	/// Align on 4-byte boundary
	public final static int IMAGE_SCN_ALIGN_4BYTES = 0x00300000;

	/// Align on 8-byte boundary
	public final static int IMAGE_SCN_ALIGN_8BYTES = 0x00400000;

	/// Align on 16-byte boundary
	public final static int IMAGE_SCN_ALIGN_16BYTES = 0x00500000;

	/// Align on 32-byte boundary
	public final static int IMAGE_SCN_ALIGN_32BYTES = 0x00600000;

	/// Align on 64-byte boundary
	public final static int IMAGE_SCN_ALIGN_64BYTES = 0x00700000;

	/// Align on 128-byte boundary
	public final static int IMAGE_SCN_ALIGN_128BYTES = 0x00800000;

	/// Align on 256-byte boundary
	public final static int IMAGE_SCN_ALIGN_256BYTES = 0x00900000;

	/// Align on 512-byte boundary
	public final static int IMAGE_SCN_ALIGN_512BYTES = 0x00A00000;

	/// Align on 1024-byte boundary
	public final static int IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000;

	/// Align on 2048-byte boundary
	public final static int IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000;

	/// Align on 4096-byte boundary
	public final static int IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000;

	/// Align on 8192-byte boundary
	public final static int IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000;

	/// Mask for alignment flags
	public final static int IMAGE_SCN_ALIGN_MASK = 0x00F00000;

	/// Section contains extended relocations
	public final static int IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000;

	/// The section can be discarded from the final executable. Used to hold information for the 
	/// linker's use, including the .debug$ sections.
	public final static int IMAGE_SCN_MEM_DISCARDABLE = 0x02000000;

	/// Section is not cachable
	public final static int IMAGE_SCN_MEM_NOT_CACHED = 0x04000000;

	/// The section is not pageable, so it should always be physically present in memory. Often used
	/// for kernel-mode drivers.
	public final static int IMAGE_SCN_MEM_NOT_PAGED = 0x08000000;

	/// Section is shareable. The physical pages containing this section's data will be shared 
	/// between all processes that have this executable loaded. Thus, every process will see the 
	/// exact same values for data in this section. Useful for making global variables shared 
	/// between all instances of a process. To make a section shared,  use the /section:name,S 
	/// linker switch.
	public final static int IMAGE_SCN_MEM_SHARED = 0x10000000;

	/// Section is executable
	public final static int IMAGE_SCN_MEM_EXECUTE = 0x20000000;

	/// Section is readable
	public final static int IMAGE_SCN_MEM_READ = 0x40000000;

	/// Section is writeable
	public final static int IMAGE_SCN_MEM_WRITE = 0x80000000;

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

	private Integer alignedVirtualSize;
	private Integer alignedVirtualAddress;
	private Integer alignedSizeOfRawData;
	private Integer alignedPointerToRawData;

	private BinaryReader reader;
	private int sectionNumber;

	/**
	 * Creates a new {@link SectionHeader} from the specified stream starting at {@code index}
	 *  
	 * @param reader {@link BinaryReader} to read from
	 * @param index long offset in the reader where the section header starts
	 * @param stringTableOffset offset of the string table, or -1 if not available
	 * @param sectionNumber The section number (0-based)
	 * @throws IOException if error reading data
	 */
	public SectionHeader(BinaryReader reader, long index, long stringTableOffset, int sectionNumber)
			throws IOException {
		this.reader = reader;
		this.sectionNumber = sectionNumber;

		name = reader.readAsciiString(index, IMAGE_SIZEOF_SHORT_NAME).trim();
		if (name.startsWith("/") && stringTableOffset != -1) {
			try {
				int nameOffset = Integer.parseInt(name.substring(1));
				name = reader.readAsciiString(stringTableOffset + nameOffset);
			}
			catch (NumberFormatException | IOException nfe) {
				// ignore format or out-of-bounds errors...section name will remain as it was
			}
		}

		// We need to skip IMAGE_SIZEOF_SHORT_NAME chars no matter what since those bytes are always
		// allocated
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

	/**
	 * {@return the ASCII name of the section}
	 * <p>
	 * A section name is not guaranteed to be null-terminated. If you specify a section name 
	 * longer than eight characters, the linker truncates it to eight characters in the executable. 
	 * A mechanism exists for allowing longer section names in OBJ files. Section names often start 
	 * with a period, but this is not a requirement. Section names with a $ in the name get special
	 * treatment from the linker. Sections with identical names prior to the $ character are merged.
	 * The characters following the $ provide an alphabetic ordering for how the merged sections 
	 * appear in the final section. There's quite a bit more to the subject of sections  with $ in 
	 * the name and how they're combined, but the details are outside the scope of this article.
	 */
	public String getName() {
		return name;
	}

	/**
	 * {@return a readable ascii version of the name (all non-readable characters are replaced with
	 * underscores}
	 */
	public String getReadableName() {
		if (name.isBlank()) {
			return "SECTION." + sectionNumber;
		}

		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < name.length(); ++i) {
			char ch = name.charAt(i);
			if (ch >= 0x20 && ch <= 0x7e) {//is readable ascii?
				sb.append(ch);
			}
			else {
				sb.append('_');
			}
		}
		return sb.toString();
	}

	/**
	 * {@return the original, unaligned physical address of this section}
	 */
	public int getPhysicalAddress() {
		return physicalAddress;
	}

	/**
	 * {@return the original, unaligned RVA where the section begins in memory}
	 */
	public int getVirtualAddress() {
		return virtualAddress;
	}

	/**
	 * {@return the aligned RVA where the section begins in memory}
	 * 
	 * @param optionalHeader The {@link OptionalHeader}, or {@code null} if not available
	 */
	public int getAlignedVirtualAddress(OptionalHeader optionalHeader) {
		if (alignedVirtualAddress != null) {
			return alignedVirtualAddress;
		}

		alignedVirtualAddress = optionalHeader != null
				? PeUtils.alignUp(virtualAddress, optionalHeader.getSectionAlignment())
				: virtualAddress;

		return alignedVirtualAddress;
	}

	/**
	 * {@return the original, unaligned size of the section in memory}
	 */
	public int getVirtualSize() {
		return virtualSize;
	}

	/**
	 * {@return the actual, used size of the section}
	 * 
	 * @param optionalHeader The {@link OptionalHeader}, or {@code null} if not available
	 * @param log A log to report errors to
	 */
	public int getAlignedVirtualSize(OptionalHeader optionalHeader, MessageLog log) {
		if (alignedVirtualSize != null) {
			return alignedVirtualSize;
		}

		if (virtualSize != 0 && optionalHeader != null) {
			alignedVirtualSize = PeUtils.alignUp(virtualSize, optionalHeader.getSectionAlignment());
		}
		else if (virtualSize != 0) {
			alignedVirtualSize = virtualSize;
		}
		else {
			alignedVirtualSize = getAlignedSizeOfRawData(optionalHeader, log);
		}

		return alignedVirtualSize;
	}

	/**
	 * {@return the original, unaligned offset of the section in the file}
	 */
	public int getPointerToRawData() {
		return pointerToRawData;
	}

	/**
	 * {@return the aligned offset of the section in the file}
	 * 
	 * @param optionalHeader The {@link OptionalHeader}, or {@code null} if not available
	 * @param log A log to report errors to
	 */
	public int getAlignedPointerToRawData(OptionalHeader optionalHeader, MessageLog log) {
		if (alignedPointerToRawData != null) {
			return alignedPointerToRawData;
		}

		alignedPointerToRawData = pointerToRawData;

		// While this value *should* be a multiple of the file alignment, Windows will round down 
		// to the nearest multiple of 0x200 regardless of the file alignment. Also note that for 
		// values below 0x200 but above 0x0 Windows will round down to 0 but still load the section
		// into memory instead of not loading anything as it would if it were 0 from the start.
		if (optionalHeader.getFileAlignment() >= 0x200) {
			PeUtils.alignDown(pointerToRawData, 0x200);
		}

		// Ensure aligned PointerToRawData is within file bounds
		if (alignedPointerToRawData >= reader.length()) {
			log.appendMsg("NOTE: Section '%s' begins after end of file!".formatted(name));
			alignedPointerToRawData = 0;
		}

		return alignedPointerToRawData;
	}

	/**
	 * {@return the original, unaligned size of the section in the file}
	 */
	public int getSizeOfRawData() {
		return sizeOfRawData;
	}

	/**
	 * {@return the aligned size of the section in the file}
	 * 
	 * @param optionalHeader The {@link OptionalHeader}, or {@code null} if not available
	 * @param log A log to report errors to
	 */
	public int getAlignedSizeOfRawData(OptionalHeader optionalHeader, MessageLog log) {
		if (alignedSizeOfRawData != null) {
			return alignedSizeOfRawData;
		}

		int fileAlignment = optionalHeader.getFileAlignment();
		if (sizeOfRawData % fileAlignment != 0) {
			log.appendMsg(
				"NOTE: Section '%s' has SizeOfRawData (0x%x) that is not a multiple of the file alignment (0x%x)"
						.formatted(name, sizeOfRawData, fileAlignment));
		}
		alignedSizeOfRawData =
			fileAlignment > 0 ? PeUtils.alignUp(sizeOfRawData, fileAlignment) : sizeOfRawData;

		// Malware can deliberately set invalid or abnormally large values of SizeOfRawData 
		// to break static analysis. If we suspect that is happening, default to the
		// VirtualSize. This may result in padding bytes being replaced by garbage bytes,
		// but it will allow the binary to be imported and analyzed.
		if (sizeOfRawData < 0) {
			log.appendMsg("NOTE: Section '%s' has negative SizeOfRawData (0x%x)".formatted(name,
				sizeOfRawData));
			log.appendMsg(
				"Using '%s' VirtualSize (0x%x) in its place".formatted(name, virtualSize));
			alignedSizeOfRawData = virtualSize;
		}

		// Ensure SizeOfRawData does not exceed the aligned VirtualSize
		alignedSizeOfRawData =
			Math.min(alignedSizeOfRawData, getAlignedVirtualSize(optionalHeader, log));

		// Ensure aligned PointerToRawData + SizeOfRawData doesn't exceed the length of the file
		int ptr = getAlignedPointerToRawData(optionalHeader, log);
		if (ptr + alignedSizeOfRawData > reader.length()) {
			int newSizeOfRawData = (int) (reader.length() - ptr);
			log.appendMsg(
				"NOTE: Section '%s' exceeds file length...truncating aligned SizeOfRawData from %d to %d"
						.formatted(name, alignedSizeOfRawData, newSizeOfRawData));
			alignedSizeOfRawData = newSizeOfRawData;
		}

		return alignedSizeOfRawData;
	}

	/**
	 * {@return the file offset of relocations for this section}
	 */
	public int getPointerToRelocations() {
		return pointerToRelocations;
	}

	/**
	 * {@return the number of relocations pointed to by the {@code PointerToRelocations} field}
	 */
	public short getNumberOfRelocations() {
		return numberOfRelocations;
	}

	/**
	 * {@return the file offset for COFF-style line numbers for this section}
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
	 * {@return the number of line numbers pointed to by the {@code PointerToLinenumbers} field}
	 */
	public short getNumberOfLinenumbers() {
		return numberOfLinenumbers;
	}

	@Override
	public byte[] toBytes(DataConverter dc) throws IOException {
		return reader.readByteArray(getPointerToRawData(), getSizeOfRawData());
	}

	/**
	 * {@return an {@link InputStream} to underlying bytes of this section}
	 * 
	 * @throws IOException if an IO-related error occurred
	 */
	public InputStream getDataStream() throws IOException {
		return reader.getByteProvider().getInputStream(getPointerToRawData());
	}

	/**
	 * {@return a {@link ByteProvider} to underlying bytes of this section}
	 */
	public ByteProvider getDataByteProvider() {
		return new ByteProviderWrapper(reader.getByteProvider(), getPointerToRawData(),
			getSizeOfRawData());
	}

	/**
	 * {@return whether or not this section has read permissions}
	 */
	public boolean isRead() {
		return (characteristics & SectionFlags.IMAGE_SCN_MEM_READ.getMask()) != 0;
	}

	/**
	 * {@return whether or not this section has write permissions}
	 */
	public boolean isWrite() {
		return (characteristics & SectionFlags.IMAGE_SCN_MEM_WRITE.getMask()) != 0;
	}

	/**
	 * {@return whether or not this section has execute permissions}
	 */
	public boolean isExecute() {
		return (characteristics & SectionFlags.IMAGE_SCN_MEM_EXECUTE.getMask()) != 0;
	}

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
			characteristicsEnum.add(flag.name(), Integer.toUnsignedLong(flag.getMask()));
		}
		struct.add(characteristicsEnum, "Characteristics", null);
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}
}
