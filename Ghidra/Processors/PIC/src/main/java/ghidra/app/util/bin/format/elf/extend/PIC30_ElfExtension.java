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

	public static final int SHF_PSV = (1 << 28); /* Constants in program memory */

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
			return false;
		}
		return !section.isExecutable();
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
		if (!language.getDefaultDataSpace().equals(start.getAddressSpace().getPhysicalSpace())) {
			return dataInput;
		}

		if (loadable instanceof ElfSectionHeader) {
			ElfSectionHeader section = (ElfSectionHeader) loadable;
			if ((section.getFlags() & SHF_PSV) != 0) {
				// TODO: this is really mapped into ROM space where PT_LOAD was done to physical memory
				// In the absence of suitable mapping, we will load into RAM space
				return new PIC30FilteredPSVDataInputStream(dataInput);
			}
		}

		// Data space loading pads after every byte with Microchip toolchain 
		// NOTE: this could vary and we may need to improve detection of this situation

		return new PIC30FilteredDataInputStream(dataInput);
	}

	@Override
	public boolean hasFilteredLoadInputStream(ElfLoadHelper elfLoadHelper, MemoryLoadable loadable,
			Address start) {
		Language language = elfLoadHelper.getProgram().getLanguage();
		return language.getDefaultDataSpace().equals(start.getAddressSpace().getPhysicalSpace());
	}

	private static class PIC30FilteredDataInputStream extends FilterInputStream {

		// BYTES:  <byte> <pad>

		protected boolean padByteToggle;
		protected long pos;

		protected PIC30FilteredDataInputStream(InputStream in) {
			super(in);
			padByteToggle = false; // first byte is data not padding
		}

		protected int readNextByte() throws IOException {
			int r = in.read();
			if (padByteToggle && r != 0) {
				// expected padding
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
			super(in);
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
