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
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pe.ImageRuntimeFunctionEntries._IMAGE_RUNTIME_FUNCTION_ENTRY;
import ghidra.app.util.bin.format.pe.debug.DebugCOFFSymbol;
import ghidra.app.util.bin.format.pe.debug.DebugCOFFSymbolAux;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.DataConverter;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

/**
 * A class to represent the IMAGE_FILE_HEADER struct as
 * defined in <code>winnt.h</code>.
 * <br>
 * <pre>
 * typedef struct _IMAGE_FILE_HEADER {
 *     WORD    Machine;								// MANDATORY
 *     WORD    NumberOfSections;					// USED
 *     DWORD   TimeDateStamp;
 *     DWORD   PointerToSymbolTable;
 *     DWORD   NumberOfSymbols;
 *     WORD    SizeOfOptionalHeader;				// USED
 *     WORD    Characteristics;						// MANDATORY
 * } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
 * </pre>
 *
 */
public class FileHeader implements StructConverter {
	/**
	 * The name to use when converting into a structure data type.
	 */
	public final static String NAME = "IMAGE_FILE_HEADER";
	/**
	 * The size of the <code>IMAGE_FILE_HEADER</code> in bytes.
	 */
	public final static int IMAGE_SIZEOF_FILE_HEADER = 20;

	/**
	 * Relocation info stripped from file.
	 */
	public final static int IMAGE_FILE_RELOCS_STRIPPED = 0x0001;
	/**
	 * File is executable (no unresolved externel references).
	 */
	public final static int IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
	/**
	 * Line nunbers stripped from file.
	 */
	public final static int IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004;
	/**
	 * Local symbols stripped from file.
	 */
	public final static int IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008;
	/**
	 * Agressively trim working set
	 */
	public final static int IMAGE_FILE_AGGRESIVE_WS_TRIM = 0x0010;
	/**
	 * App can handle &gt;2gb addresses
	 */
	public final static int IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020;
	/**
	 * Bytes of machine word are reversed.
	 */
	public final static int IMAGE_FILE_BYTES_REVERSED_LO = 0x0080;
	/**
	 * 32 bit word machine.
	 */
	public final static int IMAGE_FILE_32BIT_MACHINE = 0x0100;
	/**
	 * Debugging info stripped from file in .DBG file
	 */
	public final static int IMAGE_FILE_DEBUG_STRIPPED = 0x0200;
	/**
	 * If Image is on removable media, copy and run from the swap file.
	 */
	public final static int IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400;
	/**
	 * If Image is on Net, copy and run from the swap file.
	 */
	public final static int IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800;
	/**
	 * System File.
	 */
	public final static int IMAGE_FILE_SYSTEM = 0x1000;
	/**
	 * File is a DLL.
	 */
	public final static int IMAGE_FILE_DLL = 0x2000;
	/**
	 * File should only be run on a UP machine.
	 */
	public final static int IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000;
	/**
	 * Bytes of machine word are reversed.
	 */
	public final static int IMAGE_FILE_BYTES_REVERSED_HI = 0x8000;

	/**
	 * Magic value in LordPE's Symbol Table pointer field.
	 */
	private final static int LORDPE_SYMBOL_TABLE = 0x726F4C5B;
	/**
	 * Magic value in LordPE's Number of Symbols field.
	 */
	private final static int LORDPE_NUMBER_OF_SYMBOLS = 0x5D455064;

	public final static String[] CHARACTERISTICS = { "Relocation info stripped from file",
		"File is executable  (i.e. no unresolved externel references)",
		"Line nunbers stripped from file", "Local symbols stripped from file",
		"Agressively trim working set", "App can handle >2gb addresses",
		"Bytes of machine word are reversed", "32 bit word machine",
		"Debugging info stripped from file in .DBG file",
		"If Image is on removable media, copy and run from the swap file",
		"If Image is on Net, copy and run from the swap file", "System file", "File is a DLL",
		"File should only be run on a UP machine", "Bytes of machine word are reversed" };

	/**
	 * Values for the Machine field indicating the intended processor architecture
	 */
	public final static int IMAGE_FILE_MACHINE_MASK = 0xFFFF;
	public final static int IMAGE_FILE_MACHINE_UNKNOWN = 0x0; 		//	The content of this field is assumed to be applicable to any machine type
	public final static int IMAGE_FILE_MACHINE_AM33 = 0x1d3; 		//	Matsushita AM33
	public final static int IMAGE_FILE_MACHINE_AMD64 = 0x8664; 		//	x64
	public final static int IMAGE_FILE_MACHINE_ARM = 0x1c0; 		//	ARM little endian
	public final static int IMAGE_FILE_MACHINE_ARM64 = 0xaa64; 		//	ARM64 little endian
	public final static int IMAGE_FILE_MACHINE_ARMNT = 0x1c4; 		//	ARM Thumb-2 little endian
	public final static int IMAGE_FILE_MACHINE_EBC = 0xebc; 		//	EFI byte code
	public final static int IMAGE_FILE_MACHINE_I386 = 0x14c; 		//	Intel 386 or later processors and compatible processors
	public final static int IMAGE_FILE_MACHINE_IA64 = 0x200; 		//	Intel Itanium processor family
	public final static int IMAGE_FILE_MACHINE_M32R = 0x9041; 		//	Mitsubishi M32R little endian
	public final static int IMAGE_FILE_MACHINE_MIPS16 = 0x266; 		//	MIPS16
	public final static int IMAGE_FILE_MACHINE_MIPSFPU = 0x366; 	//	MIPS with FPU
	public final static int IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466; 	//	MIPS16 with FPU
	public final static int IMAGE_FILE_MACHINE_POWERPC = 0x1f0; 	//	Power PC little endian
	public final static int IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1; 	//	Power PC with floating point support
	public final static int IMAGE_FILE_MACHINE_R4000 = 0x166; 		//	MIPS little endian
	public final static int IMAGE_FILE_MACHINE_RISCV32 = 0x5032; 	//	RISC-V 32-bit address space
	public final static int IMAGE_FILE_MACHINE_RISCV64 = 0x5064; 	//	RISC-V 64-bit address space
	public final static int IMAGE_FILE_MACHINE_RISCV128 = 0x5128; 	//	RISC-V 128-bit address space
	public final static int IMAGE_FILE_MACHINE_SH3 = 0x1a2; 		//	Hitachi SH3
	public final static int IMAGE_FILE_MACHINE_SH3DSP = 0x1a3; 		//	Hitachi SH3 DSP
	public final static int IMAGE_FILE_MACHINE_SH4 = 0x1a6; 		//	Hitachi SH4
	public final static int IMAGE_FILE_MACHINE_SH5 = 0x1a8; 		//	Hitachi SH5
	public final static int IMAGE_FILE_MACHINE_THUMB = 0x1c2; 		//	Thumb
	public final static int IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169;	//	MIPS little-endian WCE v2

	private short machine;
	private short numberOfSections;
	private int timeDateStamp;
	private int pointerToSymbolTable;
	private int numberOfSymbols;
	private short sizeOfOptionalHeader; 	// delta between start of OptionalHeader and start of section table
	private short characteristics;

	private SectionHeader[] sectionHeaders;
	private List<DebugCOFFSymbol> symbols = new ArrayList<>();

	// TODO: This is x86-64 architecture-specific and needs to be generalized.
	private List<_IMAGE_RUNTIME_FUNCTION_ENTRY> irfes = new ArrayList<>();

	private FactoryBundledWithBinaryReader reader;
	private int startIndex;
	private NTHeader ntHeader;

	static FileHeader createFileHeader(FactoryBundledWithBinaryReader reader, int startIndex,
			NTHeader ntHeader) throws IOException {
		FileHeader fileHeader = (FileHeader) reader.getFactory().create(FileHeader.class);
		fileHeader.initFileHeader(reader, startIndex, ntHeader);
		return fileHeader;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public FileHeader() {
	}

	private void initFileHeader(FactoryBundledWithBinaryReader reader, int startIndex,
			NTHeader ntHeader) throws IOException {
		this.reader = reader;
		this.startIndex = startIndex;
		this.ntHeader = ntHeader;

		parse();
	}

	/**
	 * Returns the architecture type of the computer.
	 * @return the architecture type of the computer
	 */
	public short getMachine() {
		return machine;
	}

	/**
	 * Returns a string representation of the architecture type of the computer.
	 * @return a string representation of the architecture type of the computer
	 */
	public String getMachineName() {
		return MachineName.getName(machine);
	}

	/**
	 * Returns the number of sections.
	 * Sections equate to Ghidra memory blocks.
	 * @return the number of sections
	 */
	public int getNumberOfSections() {
		return numberOfSections;
	}

	/**
	 * Returns the array of section headers.
	 * @return the array of section headers
	 */
	public SectionHeader[] getSectionHeaders() {
		if (sectionHeaders == null) {
			return new SectionHeader[0];
		}
		return sectionHeaders;
	}

	/**
	 * Returns the array of symbols.
	 * @return the array of symbols
	 */
	public List<DebugCOFFSymbol> getSymbols() {
		return symbols;
	}

	/**
	 * Returns the array of RUNTIME_INFO entries, if any are present.
	 * @return An array of _IMAGE_RUNTIME_FUNCTION_ENTRY. The array can be empty.
	 * TODO: This is x86-64 architecture-specific and needs to be generalized.
	 */
	public List<_IMAGE_RUNTIME_FUNCTION_ENTRY> getImageRuntimeFunctionEntries() {
		return irfes;
	}

	/**
	 * Returns the section header that contains the specified virtual address.
	 * @param virtualAddr the virtual address
	 * @return the section header that contains the specified virtual address
	 */
	public SectionHeader getSectionHeaderContaining(int virtualAddr) {
		for (SectionHeader sectionHeader : sectionHeaders) {
			int start = sectionHeader.getVirtualAddress();
			int end = sectionHeader.getVirtualAddress() + sectionHeader.getVirtualSize() - 1;
			if (virtualAddr >= start && virtualAddr <= end) {
				return sectionHeader;
			}
		}
		return null;
	}

	/**
	 * Returns the section header at the specified position in the array.
	 * @param index index of section header to return
	 * @return the section header at the specified position in the array, or null if invalid
	 */
	public SectionHeader getSectionHeader(int index) {
		if (index >= 0 && index < sectionHeaders.length) {
			return sectionHeaders[index];
		}
		return null;
	}

	/**
	 * Returns the time stamp of the image.
	 * @return the time stamp of the image
	 */
	public int getTimeDateStamp() {
		return timeDateStamp;
	}

	/**
	 * Returns the file offset of the COFF symbol table
	 * @return the file offset of the COFF symbol table
	 */
	public int getPointerToSymbolTable() {
		return pointerToSymbolTable;
	}

	/**
	 * Returns the number of symbols in the COFF symbol table
	 * @return  the number of symbols in the COFF symbol table
	 */
	public int getNumberOfSymbols() {
		return numberOfSymbols;
	}

	/**
	 * Returns the size of the optional header data
	 * @return the size of the optional header, in bytes
	 */
	public int getSizeOfOptionalHeader() {
		return sizeOfOptionalHeader;
	}

	/**
	 * Returns a set of bit flags indicating attributes of the file.
	 * @return a set of bit flags indicating attributes
	 */
	public int getCharacteristics() {
		return characteristics;
	}

	/**
	 * Returns the file pointer to the section headers.
	 * @return the file pointer to the section headers
	 */
	public int getPointerToSections() {
		short sizeOptHdr = ntHeader.getFileHeader().sizeOfOptionalHeader;
		int ptrToSections = startIndex + IMAGE_SIZEOF_FILE_HEADER + sizeOptHdr;
		int testSize =
			ntHeader.getOptionalHeader().is64bit() ? Constants.IMAGE_SIZEOF_NT_OPTIONAL64_HEADER
					: Constants.IMAGE_SIZEOF_NT_OPTIONAL32_HEADER;
		if (sizeOptHdr != testSize) {
			Msg.warn(this, "Non-standard optional header size: " + sizeOptHdr + " bytes");
		}
		return ptrToSections;
	}

	void processSections(OptionalHeader optHeader) throws IOException {
		long oldIndex = reader.getPointerIndex();

		int tmpIndex = getPointerToSections();
		if (numberOfSections < 0) {
			Msg.error(this, "Number of sections = " + numberOfSections);
		}
		else if (optHeader.getFileAlignment() == 0) {
			Msg.error(this, "File alignment == 0: section processing skipped");
		}
		else {
			sectionHeaders = new SectionHeader[numberOfSections];
			for (int i = 0; i < numberOfSections; ++i) {
				sectionHeaders[i] = SectionHeader.createSectionHeader(reader, tmpIndex);

				// Ensure PointerToRawData + SizeOfRawData doesn't exceed the length of the file
				int pointerToRawData = sectionHeaders[i].getPointerToRawData();
				int sizeOfRawData = (int) Math.min(reader.length() - pointerToRawData,
					sectionHeaders[i].getSizeOfRawData());

				// Ensure VirtualSize is large enough to accommodate SizeOfRawData, but do not
				// exceed the next alignment boundary.  We can only do this if the VirtualAddress is
				// already properly aligned, since we currently don't support moving sections to
				// different addresses to enforce alignment.
				int virtualAddress = sectionHeaders[i].getVirtualAddress();
				int virtualSize = sectionHeaders[i].getVirtualSize();
				int alignedVirtualAddress = PortableExecutable.computeAlignment(virtualAddress,
					optHeader.getSectionAlignment());
				int alignedVirtualSize = PortableExecutable.computeAlignment(virtualSize,
					optHeader.getSectionAlignment());
				if (virtualAddress == alignedVirtualAddress) {
					if (sizeOfRawData > virtualSize) {
						sectionHeaders[i]
								.setVirtualSize(Math.min(sizeOfRawData, alignedVirtualSize));
					}
				}
				else {
					Msg.warn(this, "Section " + sectionHeaders[i].getName() + " is not aligned!");
				}
				tmpIndex += SectionHeader.IMAGE_SIZEOF_SECTION_HEADER;
			}
		}

		reader.setPointerIndex(oldIndex);
	}

	void processImageRuntimeFunctionEntries() throws IOException {
		FileHeader fh = ntHeader.getFileHeader();
		SectionHeader[] sections = fh.getSectionHeaders();

		// Look for an exception handler section for an array of
		// RUNTIME_FUNCTION structures, bail if one isn't found
		SectionHeader irfeHeader = null;
		for (SectionHeader header : sections) {
			if (header.getName().equals(".pdata")) {
				irfeHeader = header;
				break;
			}
		}

		if (irfeHeader == null) {
			return;
		}

		long oldIndex = reader.getPointerIndex();

		int start = irfeHeader.getPointerToRawData();
		reader.setPointerIndex(start);

		ImageRuntimeFunctionEntries entries =
			ImageRuntimeFunctionEntries.createImageRuntimeFunctionEntries(reader, start, ntHeader);
		irfes = entries.getRuntimeFunctionEntries();

		reader.setPointerIndex(oldIndex);
	}

	void processSymbols() throws IOException {
		if (isLordPE()) {
			return;
		}

		long oldIndex = reader.getPointerIndex();

		int tmpIndex = getPointerToSymbolTable();
		if (!ntHeader.checkRVA(tmpIndex)) {
			Msg.error(this, "Invalid file index " + Integer.toHexString(tmpIndex));
			return;
		}

		if (numberOfSymbols < 0 || numberOfSymbols > reader.length()) {
			Msg.error(this, "Invalid symbol count " + Integer.toHexString(numberOfSymbols));
			return;
		}

		int stringTableIndex = tmpIndex + DebugCOFFSymbol.IMAGE_SIZEOF_SYMBOL * numberOfSymbols;

		for (int i = 0; i < numberOfSymbols; ++i) {
			if (!ntHeader.checkRVA(tmpIndex)) {
				Msg.error(this, "Invalid file index " + Integer.toHexString(tmpIndex));
				break;
			}

			DebugCOFFSymbol symbol =
				DebugCOFFSymbol.createDebugCOFFSymbol(reader, tmpIndex, stringTableIndex);

			tmpIndex += DebugCOFFSymbol.IMAGE_SIZEOF_SYMBOL;

			tmpIndex +=
				(DebugCOFFSymbolAux.IMAGE_SIZEOF_AUX_SYMBOL * symbol.getNumberOfAuxSymbols());

			int numberOfAuxSymbols = symbol.getNumberOfAuxSymbols();
			i += numberOfAuxSymbols > 0 ? numberOfAuxSymbols : 0;

			symbols.add(symbol);
		}

		reader.setPointerIndex(oldIndex);
	}

	public boolean isLordPE() {
		if (getPointerToSymbolTable() == LORDPE_SYMBOL_TABLE &&
			getNumberOfSymbols() == LORDPE_NUMBER_OF_SYMBOLS) {
			return true;
		}
		return false;
	}

	private void parse() throws IOException {
		reader.setPointerIndex(startIndex);

		machine = reader.readNextShort();
		numberOfSections = reader.readNextShort();
		timeDateStamp = reader.readNextInt();
		pointerToSymbolTable = reader.readNextInt();
		numberOfSymbols = reader.readNextInt();
		sizeOfOptionalHeader = reader.readNextShort();
		characteristics = reader.readNextShort();
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	@Override
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(WORD, 2, "Machine", getMachineName());
		struct.add(WORD, 2, "NumberOfSections", null);
		struct.add(DWORD, 4, "TimeDateStamp", null);
		struct.add(DWORD, 4, "PointerToSymbolTable", null);
		struct.add(DWORD, 4, "NumberOfSymbols", null);
		struct.add(WORD, 2, "SizeOfOptionalHeader", null);
		struct.add(WORD, 2, "Characteristics", null);

		struct.setCategoryPath(new CategoryPath("/PE"));

		return struct;
	}

	private void setSectionHeaders(SectionHeader[] sectionHeaders) {
		this.sectionHeaders = sectionHeaders;
		numberOfSections = (short) sectionHeaders.length;
	}

	void writeHeader(RandomAccessFile raf, DataConverter dc) throws IOException {
		raf.write(dc.getBytes(machine));
		raf.write(dc.getBytes(numberOfSections));
		raf.write(dc.getBytes(timeDateStamp));
		raf.write(dc.getBytes(pointerToSymbolTable));
		raf.write(dc.getBytes(numberOfSymbols));
		raf.write(dc.getBytes(sizeOfOptionalHeader));
		raf.write(dc.getBytes(characteristics));
	}

	/**
	 * Adds a new section to this file header. Uses the given memory block
	 * as the section template. The section will have the memory block's name, start address,
	 * size, etc. The optional header is needed to determine the free byte position in the
	 * file.
	 * @param block the memory block template
	 * @param optionalHeader the related optional header
	 * @throws RuntimeException if the memory block is uninitialized
	 */
	public void addSection(MemoryBlock block, OptionalHeader optionalHeader) {
		DataDirectory[] directories = optionalHeader.getDataDirectories();

		DataDirectory[] dataDirectories = optionalHeader.getDataDirectories();

		SecurityDataDirectory sdd = null;
		if (dataDirectories.length > OptionalHeader.IMAGE_DIRECTORY_ENTRY_SECURITY) {
			sdd =
				(SecurityDataDirectory) dataDirectories[OptionalHeader.IMAGE_DIRECTORY_ENTRY_SECURITY];
			if (sdd != null && sdd.getSize() > 0) {
				sdd.updatePointers(PortableExecutable.computeAlignment((int) block.getSize(),
					optionalHeader.getFileAlignment()));
			}
		}

		int lastPos = computeAlignedNewPosition(optionalHeader, directories);

		SectionHeader newSection = new SectionHeader(block, optionalHeader, lastPos);

		SectionHeader[] newSectionHeaders = new SectionHeader[sectionHeaders.length + 1];
		System.arraycopy(sectionHeaders, 0, newSectionHeaders, 0, sectionHeaders.length);
		newSectionHeaders[sectionHeaders.length] = newSection;
		setSectionHeaders(newSectionHeaders);

		int firstSectionStart = sectionHeaders[0].getPointerToRawData();
		int lastSectionEnd = sectionHeaders[sectionHeaders.length - 1].getPointerToRawData() +
			sectionHeaders[sectionHeaders.length - 1].getSizeOfRawData();

		for (int i = 0; i < directories.length; i++) {
			if (directories[i] == null || directories[i].getSize() == 0 ||
				directories[i].isContainedInSection()) {
				continue;
			}
			if (directories[i].getVirtualAddress() < firstSectionStart) {
				if (i != OptionalHeader.IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT) {
					throw new RuntimeException("PE - Unexpected directory before sections: " + i);
				}
			}
			if (directories[i].getVirtualAddress() > lastSectionEnd) {
				if (i != OptionalHeader.IMAGE_DIRECTORY_ENTRY_SECURITY) {
					throw new RuntimeException("PE - Unexpected directory after sections: " + i);
				}
			}
		}

		int offset = 0;

		if (dataDirectories.length > OptionalHeader.IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT) {
			BoundImportDataDirectory bidd =
				(BoundImportDataDirectory) dataDirectories[OptionalHeader.IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
			if (bidd != null && bidd.getSize() > 0) {
				bidd.updatePointers(SectionHeader.IMAGE_SIZEOF_SECTION_HEADER);
				int endptr = bidd.getVirtualAddress() + bidd.getSize() - 1;
				if (endptr >= sectionHeaders[0].getPointerToRawData()) {
					int alignedPtr = PortableExecutable.computeAlignment(endptr,
						optionalHeader.getFileAlignment());
					offset = alignedPtr - sectionHeaders[0].getPointerToRawData();
					for (SectionHeader sectionHeader : sectionHeaders) {
						sectionHeader.updatePointers(offset);
					}
					//reset the sizeOfHeaders...
					optionalHeader.setSizeOfHeaders(sectionHeaders[0].getPointerToRawData());
				}
			}
		}

		if (dataDirectories.length > OptionalHeader.IMAGE_DIRECTORY_ENTRY_DEBUG) {
			DebugDataDirectory ddd =
				(DebugDataDirectory) dataDirectories[OptionalHeader.IMAGE_DIRECTORY_ENTRY_DEBUG];
			if (ddd != null && ddd.getSize() > 0) {
				if (ddd.getVirtualAddress() > newSection.getVirtualAddress()) {
					if (sdd != null && sdd.getSize() > 0) {
						ddd.updatePointers(offset, sdd.getVirtualAddress() + sdd.getSize());
					}
					else {
						ddd.updatePointers(offset, newSection.getSizeOfRawData());
					}
				}
			}
		}

		if (block.isExecute()) {
			optionalHeader
					.setSizeOfCode(optionalHeader.getSizeOfCode() + newSection.getSizeOfRawData());
		}
		else {
			optionalHeader.setSizeOfInitializedData(
				optionalHeader.getSizeOfInitializedData() + newSection.getSizeOfRawData());
		}

		int soi = newSection.getVirtualAddress() + newSection.getSizeOfRawData();
		soi = PortableExecutable.computeAlignment(soi, optionalHeader.getSectionAlignment());
		optionalHeader.setSizeOfImage(soi);
	}

	private int computeAlignedNewPosition(OptionalHeader optionalHeader,
			DataDirectory[] directories) {
		int lastPos = 0;
		for (SectionHeader sectionHeader : sectionHeaders) {
			if (sectionHeader.getPointerToRawData() + sectionHeader.getSizeOfRawData() > lastPos) {
				lastPos = sectionHeader.getPointerToRawData() + sectionHeader.getSizeOfRawData();
			}
		}
		for (DataDirectory directorie : directories) {
			if (directorie == null || directorie.getSize() == 0) {
				continue;
			}
			if (directorie.rvaToPointer() + directorie.getSize() > lastPos) {
				lastPos = directorie.rvaToPointer() + directorie.getSize();
			}
		}
		return PortableExecutable.computeAlignment(lastPos, optionalHeader.getFileAlignment());
	}
}
