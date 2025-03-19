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

package ghidra.app.util.bin.format.unixaout;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;

public class UnixAoutHeader implements StructConverter {

	public enum AoutType {
		OMAGIC, NMAGIC, ZMAGIC, QMAGIC, CMAGIC, UNKNOWN
	}

	private BinaryReader reader;

	private long binarySize;
	private AoutType exeType;
	private boolean machineTypeValid;
	private String languageSpec;
	private String compilerSpec = "default";
	private long pageSize;

	private boolean isNetBSD = false;
	private boolean isSparc = false;

	private long a_magic;
	private long a_text;
	private long a_data;
	private long a_bss;
	private long a_syms;
	private long a_entry;
	private long a_trsize;
	private long a_drsize;

	private long strSize;

	private long txtOffset;
	private long datOffset;
	private long txtRelOffset;
	private long datRelOffset;
	private long symOffset;
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
	 * Interprets binary data as an exec header from a UNIX-style a.out executable, and validates 
	 * the contained fields.
	 *
	 * @param provider Source of header binary data
	 * @param isLittleEndian Flag indicating whether to interpret the data as little-endian.
	 * @throws IOException if an IO-related error occurred
	 */
	public UnixAoutHeader(ByteProvider provider, boolean isLittleEndian) throws IOException {
		reader = new BinaryReader(provider, isLittleEndian);

		a_magic = reader.readNextUnsignedInt();
		a_text = reader.readNextUnsignedInt();
		a_data = reader.readNextUnsignedInt();
		a_bss = reader.readNextUnsignedInt();
		a_syms = reader.readNextUnsignedInt();
		a_entry = reader.readNextUnsignedInt();
		a_trsize = reader.readNextUnsignedInt();
		a_drsize = reader.readNextUnsignedInt();
		binarySize = reader.length();

		setExecutableType(a_magic);

		// NOTE: In NetBSD/i386 examples of a.out, the "new-style" 32-bit a_magic/midmag word is
		// written in big-endian regardless of the data endianness in the rest of the file.
		if ((exeType == AoutType.UNKNOWN) && isLittleEndian) {
			a_magic = Integer.reverseBytes((int) a_magic);
			setExecutableType(a_magic);
		}

		checkMachineTypeValidity(isLittleEndian);
		determineTextOffset();

		datOffset = txtOffset + a_text;
		txtRelOffset = datOffset + a_data;
		datRelOffset = txtRelOffset + a_trsize;
		symOffset = datRelOffset + a_drsize;
		strOffset = symOffset + a_syms;

		strSize = 0;
		if (strOffset != 0 && (strOffset + 4) <= binarySize) {
			strSize = reader.readUnsignedInt(strOffset);
		}

		determineTextAddr();
		txtEndAddr = txtAddr + a_text;
		datAddr = (exeType == AoutType.OMAGIC) ? txtEndAddr : segmentRound(txtEndAddr);
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
	 * all machine types other than i386, where it is assumed to be gcc.}
	 */
	public String getCompilerSpec() {
		return compilerSpec;
	}

	/**
	 * {@return the enumerated type of executable contained in this A.out file.}
	 */
	public AoutType getExecutableType() {
		return exeType;
	}

	/**
	 * {@return an indication of whether this header's fields are all valid; this
	 * includes the machine type, executable type, and section offsets.}
	 */
	public boolean isValid() {
		return isMachineTypeValid() &&
			(exeType != AoutType.UNKNOWN) &&
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

	public long getEntryPoint() {
		return a_entry;
	}

	public long getTextRelocSize() {
		return a_trsize;
	}

	public long getDataRelocSize() {
		return a_drsize;
	}

	public long getTextOffset() {
		return txtOffset;
	}

	public long getDataOffset() {
		return datOffset;
	}

	public long getTextRelocOffset() {
		return txtRelOffset;
	}

	public long getDataRelocOffset() {
		return datRelOffset;
	}

	public long getSymOffset() {
		return symOffset;
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
	private void checkMachineTypeValidity(boolean readingAsLittleEndian) {

		machineTypeValid = true;
		pageSize = 4096;
		final short machtype = (short) ((a_magic >> 16) & 0xFF);
		final String readEndianness = readingAsLittleEndian ? "LE" : "BE";

		switch (machtype) {
			/**
			 * Motorola 68K family
			 */
			case UnixAoutMachineType.M_68010:
				languageSpec = "68000:BE:32:MC68010";
				break;
			case UnixAoutMachineType.M_68020:
				languageSpec = "68000:BE:32:MC68020";
				break;
			case UnixAoutMachineType.M_M68K_NETBSD:
				pageSize = 8192;
			case UnixAoutMachineType.M_M68K4K_NETBSD:
				isNetBSD = true;
				languageSpec = "68000:BE:32:default";
				break;

			/**
			 * SPARC family
			 */
			case UnixAoutMachineType.M_SPARC_NETBSD:
				isNetBSD = true;
			case UnixAoutMachineType.M_SPARC:
			case UnixAoutMachineType.M_SPARCLET:
				isSparc = true;
				pageSize = 8192;
				languageSpec = "sparc:BE:32:default";
				break;
			case UnixAoutMachineType.M_SPARC64_NETBSD:
				isNetBSD = true;
				isSparc = true;
				languageSpec = "sparc:BE:64:default";
				break;

			/**
			 * MIPS family
			 */
			case UnixAoutMachineType.M_PMAX_NETBSD:
				isNetBSD = true;
			case UnixAoutMachineType.M_MIPS1:
			case UnixAoutMachineType.M_MIPS2:
			case UnixAoutMachineType.M_R3000:
				languageSpec = "MIPS:LE:32:default";
				break;
			case UnixAoutMachineType.M_MIPS:
				languageSpec = "MIPS:BE:32:default";
				break;

			/**
			 * National Semiconductor NS32000 family
			 */
			case UnixAoutMachineType.M_532_NETBSD:
				isNetBSD = true;
			case UnixAoutMachineType.M_NS32032:
			case UnixAoutMachineType.M_NS32532:
				languageSpec = "UNKNOWN:LE:32:default";
				break;

			/**
			 * x86 family
			 */
			case UnixAoutMachineType.M_386_NETBSD:
				isNetBSD = true;
			case UnixAoutMachineType.M_386:
			case UnixAoutMachineType.M_386_DYNIX:
				compilerSpec = "gcc";
				languageSpec = "x86:LE:32:default";
				break;
			case UnixAoutMachineType.M_X86_64_NETBSD:
				compilerSpec = "gcc";
				languageSpec = "x86:LE:64:default";
				break;

			/**
			 * ARM family
			 */
			case UnixAoutMachineType.M_ARM6_NETBSD:
				isNetBSD = true;
			case UnixAoutMachineType.M_ARM:
				languageSpec = "ARM:" + readEndianness + ":32:default";
				break;
			case UnixAoutMachineType.M_AARCH64:
				languageSpec = "AARCH64:" + readEndianness + ":64:default";
				break;

			/**
			 * RISC family
			 */
			case UnixAoutMachineType.M_OR1K:
				languageSpec = "UNKNOWN:BE:32:default";
				break;
			case UnixAoutMachineType.M_RISCV:
				languageSpec = "RISCV:LE:32:default";
				break;
			case UnixAoutMachineType.M_HPPA_OPENBSD:
				languageSpec = "pa-risc:BE:32:default";
				break;

			/**
			 * PowerPC family
			 */
			case UnixAoutMachineType.M_POWERPC_NETBSD:
				isNetBSD = true;
				languageSpec = "PowerPC:" + readEndianness + ":32:default";
				break;
			case UnixAoutMachineType.M_POWERPC64:
				languageSpec = "PowerPC:" + readEndianness + ":64:default";
				break;

			/**
			 * SuperH family
			 * NOTE: It's unclear if there is support for SuperH SH-3 or SH-5 cores;
			 * the primary SuperH language seems to support SH-1 and SH-2 variants
			 * and the alternative is the SuperH4 language.
			 */
			case UnixAoutMachineType.M_SH3:
			case UnixAoutMachineType.M_SH5_32:
				languageSpec = "SuperH:BE:32:default";
				break;
			case UnixAoutMachineType.M_SH5_64:
				languageSpec = "SuperH:BE:64:default";
				break;

			/**
			 * VAX family
			 */
			case UnixAoutMachineType.M_VAX_NETBSD:
				pageSize = 512;
			case UnixAoutMachineType.M_VAX4K_NETBSD:
				isNetBSD = true;
				languageSpec = "UNKNOWN:LE:32:default";
				break;

			/**
			 * Other
			 */
			case UnixAoutMachineType.M_CRIS:
				languageSpec = "UNKNOWN:LE:32:default";
				break;
			case UnixAoutMachineType.M_ALPHA_NETBSD:
				isNetBSD = true;
			case UnixAoutMachineType.M_IA64:
				languageSpec = "UNKNOWN:" + readEndianness + ":64:default";
				break;
			case UnixAoutMachineType.M_29K:
			case UnixAoutMachineType.M_88K_OPENBSD:
				languageSpec = "UNKNOWN:" + readEndianness + ":32:default";
				break;
			case UnixAoutMachineType.M_UNKNOWN:
				languageSpec = "UNKNOWN:" + readEndianness + ":32:default";
				break;
			default:
				machineTypeValid = false;
		}

		// Check that the detected architecture's endianness matches the endianness
		// with which we're reading the file; if there's a mismatch, clear the
		// machineTypeValid flag because this was evidently a false reading.
		if (machineTypeValid) {
			String[] languageTokens = languageSpec.split(":");
			if ((languageTokens.length < 2) ||
				!languageTokens[1].equalsIgnoreCase(readEndianness)) {
				machineTypeValid = false;
			}
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
	 * Sets the executable type based on the given magic
	 * 
	 * @param magic The magic
	 */
	private void setExecutableType(long magic) {
		exeType = switch ((short) (magic & 0xFFFF)) {
			case 0x111 -> AoutType.CMAGIC; // 0421: core file
			case 0x108 -> AoutType.NMAGIC; // 0410: pure executable
			case 0x107 -> AoutType.OMAGIC; // 0407: object file or impure executable
			case 0x0CC -> AoutType.QMAGIC; // 0314: demand-paged exe w/ header in .text
			case 0x10B -> AoutType.ZMAGIC; // 0413: demand-paged executable
			default -> AoutType.UNKNOWN;
		};
	}

	/**
	 * Determines the offset in the binary file at which the .text segment begins.
	 * This routine should attempt to replicate the logic from the N_TXTOFF macro
	 * that appears in the different incarnations of a.out.h.
	 *
	 * NOTE: The FreeBSD imgact_aout.h implies that, if the a_magic word contains
	 * ZMAGIC when read as little endian, the file offset for .text is __LDPGSZ;
	 * otherwise, if a_magic contains ZMAGIC when read as big endian, the file
	 * offset
	 * for .text is 0. Indeed, it looks like NetBSD uses big-endian ordering for
	 * the a_magic word even when the file contains code for a little-endian
	 * processor.
	 */
	private void determineTextOffset() {

		boolean isLinuxStyle = false;
		final long fixedContentSize = a_text + a_data + a_syms + a_trsize + a_drsize;

		// If the file is large enough to read at least one word beyond a long-style
		// header
		// of 0x400 bytes plus all the sections whose sizes are specified in the
		// header...
		if (reader.isValidIndex(SIZE_OF_LONG_EXEC_HEADER + fixedContentSize)) {
			try {
				// The word that immediately follows the symbol table will contain the size of
				// the string table.
				final long stringTableLength =
					reader.readUnsignedInt(SIZE_OF_LONG_EXEC_HEADER + fixedContentSize);
				final long longHeaderExpectedFileSize =
					SIZE_OF_LONG_EXEC_HEADER + fixedContentSize + stringTableLength;

				// If the size of the file exactly matches what we'd expect if the .text content
				// starts at offset 0x400 rather than 0, this implies that the a.out is a
				// Linux-style binary.
				if (binarySize == longHeaderExpectedFileSize) {
					isLinuxStyle = true;
				}
			}
			catch (IOException e) {
				e.printStackTrace();
			}
		}

		if (isLinuxStyle && (exeType == AoutType.ZMAGIC)) {
			// Linux ZMAGICs don't start the .text content until 0x400
			txtOffset = SIZE_OF_LONG_EXEC_HEADER;

		}
		else if ((exeType == AoutType.QMAGIC) ||
			(exeType == AoutType.ZMAGIC)) {
			// ZMAGIC for other platforms (as well as QMAGIC) include the file header itself
			// in the .text content
			txtOffset = 0;

		}
		else {
			// Otherwise, the .text content starts immediately after the 0x20-byte header
			txtOffset = SIZE_OF_EXEC_HEADER;
		}
	}

	/**
	 * Uses the combination of executable type and architecture to set the
	 * appropriate
	 * base address of the .text segment when loaded.
	 */
	private void determineTextAddr() {
		txtAddr = (isSparc && exeType == AoutType.NMAGIC) || isNetBSD || exeType == AoutType.QMAGIC
				? pageSize
				: 0;
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
			((a_trsize == 0) || (txtRelOffset < binarySize)) &&
			((a_drsize == 0) || (datRelOffset < binarySize)) &&
			((a_syms == 0) || (symOffset < binarySize)));
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
		struct.add(DWORD, "a_trsize", "the size in bytes of the text relocation table");
		struct.add(DWORD, "a_drsize", "the size in bytes of the data relocation table");
		return struct;
	}

	public void markup(Program program, Address headerAddress)
			throws CodeUnitInsertionException, DuplicateNameException, IOException {
		Listing listing = program.getListing();
		listing.createData(headerAddress, toDataType());
	}
}
