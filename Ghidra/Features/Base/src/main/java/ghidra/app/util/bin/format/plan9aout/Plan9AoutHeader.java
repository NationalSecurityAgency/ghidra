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

package ghidra.app.util.bin.format.plan9aout;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;

public class Plan9AoutHeader implements StructConverter {

	private BinaryReader reader;

	private long binarySize;
	private boolean machineTypeValid;
	private String languageSpec;
	private String compilerSpec = "default";
	private long pageSize;
	private int pointerSize;
	private long hdrSize;

	private long a_magic;
	private long a_text;
	private long a_data;
	private long a_bss;
	private long a_syms;
	private long a_entry;
	private long a_spsize;
	private long a_pcsize;

	private long strSize;

	private long txtOffset;
	private long datOffset;
	private long symOffset;
	private long spOffset;
	private long pcOffset;
	private long strOffset;

	private long txtAddr;
	private long txtEndAddr;
	private long datAddr;
	private long bssAddr;

	// The Linux implementation of a.out appears to start the .text content at
	// file offset 0x400 (rather than immediately after the 0x20 bytes of header
	// data). It's possible that there exist Linux a.out executabLes with other
	// (unintended?) header sizes caused by a mixture of 32- and 64-bit integers
	// being padded out in the struct. The intended size is eight 32-bit words
	// (32 bytes total.)
	private static final int SIZE_OF_EXEC_HEADER = 0x20;
	private static final int SIZE_OF_LONG_EXEC_HEADER = 0x400;

	/**
	 * Interprets binary data as an exec header from a Plan9-style a.out executable, and validates 
	 * the contained fields.
	 *
	 * @param provider Source of header binary data
	 * @throws IOException if an IO-related error occurred
	 */
	public Plan9AoutHeader(ByteProvider provider) throws IOException {
		reader = new BinaryReader(provider, false);

		a_magic = reader.readNextUnsignedInt();
		a_text = reader.readNextUnsignedInt();
		a_data = reader.readNextUnsignedInt();
		a_bss = reader.readNextUnsignedInt();
		a_syms = reader.readNextUnsignedInt();
		a_entry = reader.readNextUnsignedInt();
		a_spsize = reader.readNextUnsignedInt();
		a_pcsize = reader.readNextUnsignedInt();
		pointerSize = 4;
		if ((a_magic & Plan9AoutMachineType.HDR_MAGIC) != 0) {
			pointerSize = 8;
			a_entry = reader.readNextUnsignedValue(pointerSize);
		}
		hdrSize = reader.getPointerIndex();
		binarySize = reader.length();

		checkMachineTypeValidity();

		txtOffset = 0;
		datOffset = txtOffset + hdrSize + a_text;
		symOffset = datOffset + a_data;
		spOffset = symOffset + a_syms;
		pcOffset = spOffset + a_spsize;
		strOffset = pcOffset + a_pcsize;

		strSize = 0;
		if (strOffset != 0 && (strOffset + 4) <= binarySize) {
			strSize = reader.readUnsignedInt(strOffset);
		}

		determineTextAddr();
		txtEndAddr = txtAddr + hdrSize + a_text;
		datAddr = segmentRound(txtEndAddr);
		bssAddr = datAddr + a_data;
	}

	public BinaryReader getReader() {
		return reader;
	}

	/**
	 * {@return the processor/language specified by this header.}
	 */
	public String getLanguageSpec() {
		return languageSpec;
	}

	/**
	 * {@return the compiler used by this executable. This is left as 'default' for
	 * all machine types other than i386, where it is assumed to be plan9.}
	 */
	public String getCompilerSpec() {
		return compilerSpec;
	}

	/**
	 * {@return an indication of whether this header's fields are all valid; this
	 * includes the machine type, executable type, and section offsets.}
	 */
	public boolean isValid() {
		return isMachineTypeValid() &&
			areOffsetsValid();
	}

	public long getTextSize() {
		return a_text;
	}

	public long getDataSize() {
		return a_data;
	}

	public long getBssSize() {
		return a_bss;
	}

	public long getSymSize() {
		return a_syms;
	}

	public long getStrSize() {
		return strSize;
	}

	public int getPointerSize() {
		return pointerSize;
	}

	public long getHeaderSize() {
		return hdrSize;
	}

	public long getEntryPoint() {
		return a_entry;
	}

	public long getTextRelocSize() {
		return 0;
	}

	public long getDataRelocSize() {
		return 0;
	}


	public long getTextOffset() {
		return txtOffset;
	}

	public long getDataOffset() {
		return datOffset;
	}

	public long getSymOffset() {
		return symOffset;
	}

	public long getTextRelocOffset() {
		return 0;
	}

	public long getDataRelocOffset() {
		return 0;
	}

	public long getStrOffset() {
		return strOffset;
	}

	public long getTextAddr() {
		return txtAddr;
	}

	public long getDataAddr() {
		return datAddr;
	}

	public long getBssAddr() {
		return bssAddr;
	}

	/**
	 * Checks the magic word in the header for a known machine type ID, and sets the
	 * languageSpec string accordingly.
	 */
	private void checkMachineTypeValidity() {

		machineTypeValid = true;
		pageSize = (a_magic & Plan9AoutMachineType.HDR_MAGIC) != 0 ? 0x200000 : 4096;

		switch ((int)a_magic) {
			/**
			 * Motorola 68K family
			 */
			case Plan9AoutMachineType.M_68020:
				languageSpec = "68000:BE:32:MC68020";
				break;

			/**
			 * SPARC family
			 */
			case Plan9AoutMachineType.M_SPARC:
				languageSpec = "sparc:BE:32:default";
				break;
			case Plan9AoutMachineType.M_SPARC64:
				languageSpec = "sparc:BE:64:default";
				break;

			/**
			 * MIPS family
			 */
			case Plan9AoutMachineType.M_SPIM1:
			case Plan9AoutMachineType.M_SPIM2:
				languageSpec = "MIPS:LE:32:default";
				break;
			case Plan9AoutMachineType.M_MIPS1:
			case Plan9AoutMachineType.M_MIPS2:
				languageSpec = "MIPS:BE:32:default";
				break;

			/**
			 * x86 family
			 */
			case Plan9AoutMachineType.M_386:
				languageSpec = "x86:LE:32:default";
				break;
			case Plan9AoutMachineType.M_AMD64:
				compilerSpec = "plan9";
				languageSpec = "x86:LE:64:default";
				break;

			/**
			 * ARM family
			 */
			case Plan9AoutMachineType.M_ARM:
				languageSpec = "ARM:LE:32:default";
				break;
			case Plan9AoutMachineType.M_AARCH64:
				languageSpec = "AARCH64:LE:64:default";
				break;

			/**
			 * RISC family
			 */
			case Plan9AoutMachineType.M_RISCV:
				languageSpec = "RISCV:LE:32:default";
				break;

			/**
			 * PowerPC family
			 */
			case Plan9AoutMachineType.M_POWERPC:
				languageSpec = "PowerPC:BE:32:default";
				break;
			case Plan9AoutMachineType.M_POWERPC64:
				languageSpec = "PowerPC:BE:64:default";
				break;

			/**
			 * Other
			 */
			case Plan9AoutMachineType.M_ALPHA:
				languageSpec = "UNKNOWN:BE:64:default";
				break;
			case Plan9AoutMachineType.M_29K:
				languageSpec = "UNKNOWN:LE:32:default";
				break;
			case Plan9AoutMachineType.M_UNKNOWN:
				languageSpec = "UNKNOWN:LE:32:default";
				break;
			default:
				machineTypeValid = false;
		}
	}

	/**
	 * Returns a flag indicating whether the header contains a known machine type
	 * ID.
	 */
	private boolean isMachineTypeValid() {
		return machineTypeValid;
	}

	/**
	 * Uses the combination of executable type and architecture to set the
	 * appropriate
	 * base address of the .text segment when loaded.
	 */
	private void determineTextAddr() {
		txtAddr = pageSize;
	}

	/**
	 * Returns a flag indicating whether all the file offsets in the header
	 * (for the segments of nonzero size) fall within the size of the file.
	 */
	private boolean areOffsetsValid() {
		// Note that we can't check the string table validity because, if it
		// doesn't exist, its offset will be computed to be beyond the end of
		// the file. The string table is also not given an explicit size in
		// the header.
		boolean status = ((a_text == 0) || (txtOffset < binarySize) &&
			((a_data == 0) || (datOffset < binarySize)) &&
			((a_syms == 0) || (symOffset < binarySize)) &&
			((a_spsize == 0) || (spOffset < binarySize)) &&
			((a_pcsize == 0) || (pcOffset < binarySize)));
		return status;
	}

	/**
	 * Rounds the provided address up to the next page boundary.
	 */
	private long segmentRound(long addr) {
		final long mask = pageSize - 1;
		long rounded = ((addr + mask) & ~mask);
		return rounded;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType(new CategoryPath("/AOUT"), "exec", 0);
		struct.add(DWORD, "a_midmag", "magic (network byte order)");
		struct.add(DWORD, "a_text", "the size of the text segment in bytes");
		struct.add(DWORD, "a_data", "the size of the data segment in bytes");
		struct.add(DWORD, "a_bss", "the number of bytes in the bss segment");
		struct.add(DWORD, "a_syms", "the size in bytes of the symbol table section");
		struct.add(DWORD, "a_entry", "the address of the entry point");
		struct.add(DWORD, "a_spsize", "the size in bytes of the SP/PC table");
		struct.add(DWORD, "a_pcsize", "the size in bytes of the PC/lineno table");
		if ((a_magic & Plan9AoutMachineType.HDR_MAGIC) != 0)
			struct.add(QWORD, "a_entry64", "the address of the entry point");

		return struct;
	}

	public void markup(Program program, Address headerAddress)
			throws CodeUnitInsertionException, DuplicateNameException, IOException {
		DataType dt = program.getDataTypeManager().addDataType(toDataType(), DataTypeConflictHandler.DEFAULT_HANDLER);
		for (DataTypeComponent field : ((Composite)dt).getComponents()) {
			field.getDefaultSettings().setLong("endian", EndianSettingsDefinition.BIG);
		}
		Listing listing = program.getListing();
		listing.createData(headerAddress, dt);
	}
}
