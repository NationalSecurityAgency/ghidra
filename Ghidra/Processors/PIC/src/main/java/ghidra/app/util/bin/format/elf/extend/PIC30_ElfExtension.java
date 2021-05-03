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
package ghidra.app.util.bin.format.elf.extend;

import java.io.*;

import ghidra.app.util.bin.format.MemoryLoadable;
import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class PIC30_ElfExtension extends ElfExtension {

	public static final int EM_DSPIC30F = 118; /* Microchip Technology dsPIC30F DSC */

	// ELF Header Flags (e_flags)
	public static final int P30F = 1 << 0;
	public static final int P30FSMPS = 1 << 1;
	public static final int P33F = 1 << 2;
	public static final int P24F = 1 << 3;
	public static final int P24H = 1 << 4;
	public static final int P24FK = 1 << 5;
	public static final int P33E = 1 << 6;
	public static final int P24E = 1 << 7;

	// Section Header Flags (sh_flags)
	public static final int SHF_MEMORY = (1 << 18); /* User-defined memory */
	public static final int SHF_UNUSED = (1 << 19); /* Unused */
	/* OS and processor-specific flags start at postion 20 */
	public static final int SHF_SECURE = (1 << 20); /* Secure segment */
	public static final int SHF_BOOT = (1 << 21); /* Boot segment */
	public static final int SHF_DMA = (1 << 22); /* DMA memory */
	public static final int SHF_NOLOAD = (1 << 23); /* Do not allocate or load */
	public static final int SHF_NEAR = (1 << 24); /* Near memory */
	public static final int SHF_PERSIST = (1 << 25); /* Persistent */
	public static final int SHF_XMEM = (1 << 26); /* X Memory */
	public static final int SHF_YMEM = (1 << 27); /* Y Memory */
	public static final int SHF_PSV = (1 << 28); /* Constants in program memory */
	public static final int SHF_EEDATA = (1 << 29); /* Data Flash memory */
	public static final int SHF_ABSOLUTE = (1 << 30); /* Absolute address */
	public static final int SHF_REVERSE = (1 << 31); /* Reverse aligned */

	/**
		NOTES:
		
			EDS/PSV Sections - section data resides with ROM space but is accessable via the
			the RAM data space at 0x8000 - 0xFFFF with the use of page register.  Page use
			may vary by CPU (EDS, PSV low-word access, PSV high-word access). PSV high-word
			access capability is only provided when EDS is supported. See page registers
			DSRPAG and DSWPAG.  Page registers must be non-zero when used.  Page boundary 
			handling must be explicitly handled in code.  EDS memory may be directly 
			accessed provided the page register as been 
			
			Three ways to access page memory:
			
			1. Direct access using DSRPAG/DSWPAGpage registers (PIC24E, dsPIC33E and dsPIC33C).
			   With read/write page register set to non-zero value, offset 0..0x7FFF within
			   the page may be directly accessed by first setting bit-15 of offset before
			   performing a load or store to the range 0x8000..0xFFFF.
			   
			2. Table read/write instruction may be used by setting TBLPAG register and 
			   performing operation with a table offset in the range 0..0x7FFF.
			   
			3. PSV direct access with PSVPAG register (PIC24F, PIC24H, dsPIC30F AND dsPIC33F).
			   Set PSV bit of CORCONL register, set page in PSVPAG register (macro psvpage() used
			   to obtain page from symbol). Access location with offset 0..0x7FFF (macro psvoffset() used
			   to obtain offset from symbol).  Macro produces offset in the range 0x8000..0xFFFF.
				
	
	**/

	@Override
	public boolean canHandle(ElfHeader elf) {
		return elf.e_machine() == EM_DSPIC30F;
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		// TODO: The PIC-30/24 utilize too many different processor names instead of
		// variant names !!
		return canHandle(elfLoadHelper.getElfHeader());
	}

	@Override
	public String getDataTypeSuffix() {
		return "_PIC30";
	}

	@Override
	public void processElf(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {
		// TODO: Create mapped blocks
	}

	@Override
	public AddressSpace getPreferredSegmentAddressSpace(ElfLoadHelper elfLoadHelper,
			ElfProgramHeader elfProgramHeader) {
		Language language = elfLoadHelper.getProgram().getLanguage();
		if (isDataLoad(elfProgramHeader)) {
			return language.getDefaultDataSpace();
		}
		return language.getDefaultSpace();
	}

	@Override
	public AddressSpace getPreferredSectionAddressSpace(ElfLoadHelper elfLoadHelper,
			ElfSectionHeader elfSectionHeader) {
		Language language = elfLoadHelper.getProgram().getLanguage();
		if (isDataLoad(elfSectionHeader)) {
			return language.getDefaultDataSpace();
		}
		return language.getDefaultSpace();
	}

	private long getAdjustedDataLoadSize(long dataLoadFileSize) {
		return dataLoadFileSize / 2;
	}

	private boolean isDataLoad(ElfProgramHeader elfProgramHeader) {
		return !elfProgramHeader.isExecute();
	}

	private boolean isDataLoad(ElfSectionHeader section) {
		if (!section.isAlloc()) {
			return isDebugSection(section);
		}
		return !section.isExecutable();
	}
	
	private boolean isDataLoad(MemoryLoadable loadable) {
		if (loadable instanceof ElfSectionHeader) {
			return isDataLoad((ElfSectionHeader)loadable);
		}
		return isDataLoad((ElfProgramHeader)loadable);
	}
	
	private boolean isDebugSection(ElfSectionHeader section) {
		String name = section.getNameAsString();
		return name.startsWith(".debug_") || ".comment".equals(name);
	}
	
	private boolean isDebugSection(MemoryLoadable loadable) {
		if (loadable instanceof ElfSectionHeader) {
			return isDebugSection((ElfSectionHeader)loadable);
		}
		return false;
	}
	
	@Override
	public long getAdjustedLoadSize(ElfProgramHeader elfProgramHeader) {
		long fileSize = elfProgramHeader.getFileSize();
		return isDataLoad(elfProgramHeader) ? getAdjustedDataLoadSize(fileSize) : fileSize;
	}

	@Override
	public long getAdjustedMemorySize(ElfProgramHeader elfProgramHeader) {
		long rawSize = elfProgramHeader.getMemorySize();
		return isDataLoad(elfProgramHeader) ? getAdjustedDataLoadSize(rawSize) : rawSize;
	}

	@Override
	public long getAdjustedSize(ElfSectionHeader section) {
		long rawSize = section.getSize();
		return isDataLoad(section) ? getAdjustedDataLoadSize(rawSize) : rawSize;
	}

	@Override
	public InputStream getFilteredLoadInputStream(ElfLoadHelper elfLoadHelper,
			MemoryLoadable loadable, Address start, long dataLength, InputStream dataInput) {
		Language language = elfLoadHelper.getProgram().getLanguage();
		if (!isDataLoad(loadable) && !language.getDefaultDataSpace().equals(start.getAddressSpace().getPhysicalSpace())) {
			return dataInput;
		}

		if (loadable instanceof ElfSectionHeader) {
			ElfSectionHeader section = (ElfSectionHeader) loadable;
			if (!elfLoadHelper.getElfHeader().isRelocatable() && (section.getFlags() & SHF_PSV) != 0) {
				// TODO: this is really mapped into ROM space where PT_LOAD was done to physical memory
				// In the absence of suitable mapping, we will load into RAM space
				return new PIC30FilteredPSVDataInputStream(dataInput);
			}
		}
		else {
			return new PIC30FilteredPSVDataInputStream(dataInput);
		}

		// Data space loading pads after every byte with Microchip toolchain 
		// NOTE: this could vary and we may need to improve detection of this situation

		return new PIC30FilteredDataInputStream(dataInput, !isDebugSection(loadable));
	}

	@Override
	public boolean hasFilteredLoadInputStream(ElfLoadHelper elfLoadHelper, MemoryLoadable loadable,
			Address start) {
		if (loadable == null) {
			return false;
		}
		if (isDataLoad(loadable)) {
			return true;
		}
		Language language = elfLoadHelper.getProgram().getLanguage();
		return language.getDefaultDataSpace().equals(start.getAddressSpace().getPhysicalSpace());
	}

	@Override
	public int getDefaultAlignment(ElfLoadHelper elfLoadHelper) {
		return 4; // alignment for external symbol allocation
	}

	private static class PIC30FilteredDataInputStream extends FilterInputStream {

		// BYTES:  <byte> <pad>

		protected boolean padByteToggle;
		protected long pos;
		
		private final boolean checkPadding;
		
		protected PIC30FilteredDataInputStream(InputStream in, boolean checkPadding) {
			super(in);
			padByteToggle = false; // first byte is data not padding
			this.checkPadding = checkPadding;
		}

		protected int readNextByte() throws IOException {
			int r = in.read();
			if (checkPadding && padByteToggle && r != 0) {
				// expected padding - debug sections appear to be inconsistent with filler
				throw new IOException("expected Data padding byte, pos=" + pos);
			}
			++pos;
			padByteToggle = !padByteToggle;
			return r;
		}

		@Override
		public int read() throws IOException {
			while (padByteToggle) {
				int r = readNextByte();
				if (r < 0) {
					return r;
				}
			}
			return readNextByte();
		}

		@Override
		public int read(byte b[], int off, int len) throws IOException {
			if (b == null) {
				throw new NullPointerException();
			}
			else if (off < 0 || len < 0 || len > b.length - off) {
				throw new IndexOutOfBoundsException();
			}
			else if (len == 0) {
				return 0;
			}

			int numRead = -1;
			for (int i = 1; i <= len; i++) {
				int c = read();
				if (c == -1) {
					break;
				}
				b[off++] = (byte) c;
				numRead = i;
			}
			return numRead;
		}

	}

	private static class PIC30FilteredPSVDataInputStream extends PIC30FilteredDataInputStream {

		// BYTES:  <byte0> <byte1> <pad0> <pad1>

		private boolean firstByteToggle; // firstByte of data or pad 

		protected PIC30FilteredPSVDataInputStream(InputStream in) {
			super(in, true);
			firstByteToggle = true;
		}

		@Override
		protected int readNextByte() throws IOException {
			int r = in.read();
			++pos;
			if (!firstByteToggle) {
				padByteToggle = !padByteToggle;
			}
			firstByteToggle = !firstByteToggle;
			return r;
		}

	}

}
