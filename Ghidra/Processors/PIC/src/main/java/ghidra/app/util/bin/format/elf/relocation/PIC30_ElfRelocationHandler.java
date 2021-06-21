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
package ghidra.app.util.bin.format.elf.relocation;

import java.util.Map;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.NotFoundException;

public class PIC30_ElfRelocationHandler extends ElfRelocationHandler {

	/* PIC30 Relocation Types */

	// Numbers found in ./include/elf/pic30.h:
	public static final int R_PIC30_NONE = 0;
	public static final int R_PIC30_8 = 1;
	public static final int R_PIC30_16 = 2;
	public static final int R_PIC30_32 = 3;
	public static final int R_PIC30_FILE_REG_BYTE = 4;
	public static final int R_PIC30_FILE_REG = 5;
	public static final int R_PIC30_FILE_REG_WORD = 6;
	public static final int R_PIC30_FILE_REG_WORD_WITH_DST = 7;
	public static final int R_PIC30_WORD = 8;
	public static final int R_PIC30_PBYTE = 9;
	public static final int R_PIC30_PWORD = 10;
	public static final int R_PIC30_HANDLE = 11;
	public static final int R_PIC30_PADDR = 12;
	public static final int R_PIC30_P_PADDR = 13;
	public static final int R_PIC30_PSVOFFSET = 14;
	public static final int R_PIC30_TBLOFFSET = 15;
	public static final int R_PIC30_WORD_HANDLE = 16;
	public static final int R_PIC30_WORD_PSVOFFSET = 17;
	public static final int R_PIC30_PSVPAGE = 18;
	public static final int R_PIC30_P_PSVPAGE = 19;
	public static final int R_PIC30_WORD_PSVPAGE = 20;
	public static final int R_PIC30_WORD_TBLOFFSET = 21;
	public static final int R_PIC30_TBLPAGE = 22;
	public static final int R_PIC30_P_TBLPAGE = 23;
	public static final int R_PIC30_WORD_TBLPAGE = 24;
	public static final int R_PIC30_P_HANDLE = 25;
	public static final int R_PIC30_P_PSVOFFSET = 26;
	public static final int R_PIC30_P_TBLOFFSET = 27;
	public static final int R_PIC30_PCREL_BRANCH = 28;
	public static final int R_PIC30_BRANCH_ABSOLUTE = 29;
	public static final int R_PIC30_PCREL_DO = 30;
	public static final int R_PIC30_DO_ABSOLUTE = 31;
	public static final int R_PIC30_PGM_ADDR_LSB = 32;
	public static final int R_PIC30_PGM_ADDR_MSB = 33;
	public static final int R_PIC30_UNSIGNED_4 = 34;
	public static final int R_PIC30_UNSIGNED_5 = 35;
	public static final int R_PIC30_BIT_SELECT_3 = 36;
	public static final int R_PIC30_BIT_SELECT_4_BYTE = 37;
	public static final int R_PIC30_BIT_SELECT_4 = 38;
	public static final int R_PIC30_DSP_6 = 39;
	public static final int R_PIC30_DSP_PRESHIFT = 40;
	public static final int R_PIC30_SIGNED_10_BYTE = 41;
	public static final int R_PIC30_UNSIGNED_10 = 42;
	public static final int R_PIC30_UNSIGNED_14 = 43;
	public static final int R_PIC30_FRAME_SIZE = 44;
	public static final int R_PIC30_PWRSAV_MODE = 45;
	public static final int R_PIC30_DMAOFFSET = 46;
	public static final int R_PIC30_P_DMAOFFSET = 47;
	public static final int R_PIC30_WORD_DMAOFFSET = 48;
	public static final int R_PIC30_PSVPTR = 49;
	public static final int R_PIC30_P_PSVPTR = 50;
	public static final int R_PIC30_L_PSVPTR = 51;
	public static final int R_PIC30_WORD_PSVPTR = 52;
	public static final int R_PIC30_CALL_ACCESS = 53;
	public static final int R_PIC30_PCREL_ACCESS = 54;
	public static final int R_PIC30_ACCESS = 55;
	public static final int R_PIC30_P_ACCESS = 56;
	public static final int R_PIC30_L_ACCESS = 57;
	public static final int R_PIC30_WORD_ACCESS = 58;
	public static final int R_PIC30_EDSPAGE = 59;
	public static final int R_PIC30_P_EDSPAGE = 60;
	public static final int R_PIC30_WORD_EDSPAGE = 61;
	public static final int R_PIC30_EDSOFFSET = 62;
	public static final int R_PIC30_P_EDSOFFSET = 63;
	public static final int R_PIC30_WORD_EDSOFFSET = 64;
	public static final int R_PIC30_UNSIGNED_8 = 65;

	// cached state assumes new instance created for each import use
	private Boolean isEDSVariant = null;

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_DSPIC30F;
	}

	@Override
	public PIC30_ElfRelocationContext createRelocationContext(ElfLoadHelper loadHelper,
			ElfRelocationTable relocationTable, Map<ElfSymbol, Address> symbolMap) {
		return new PIC30_ElfRelocationContext(this, loadHelper, relocationTable, symbolMap);
	}
	
	private boolean isEDSVariant(ElfRelocationContext elfRelocationContext) {
		if (isEDSVariant == null) {
			// NOTE: non-EDS variants may improperly define DSRPAG 
			// in register space which should be corrected
			Register reg = elfRelocationContext.program.getRegister("DSRPAG");
			isEDSVariant = reg != null && reg.getAddressSpace().isMemorySpace();
		}
		return isEDSVariant;
	}

	@Override
	public void relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation, Address relocationAddress)
			throws MemoryAccessException, NotFoundException {

		int type = relocation.getType();
		if (type == R_PIC30_NONE) {
			return;
		}

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		int symbolIndex = relocation.getSymbolIndex();

		int addend = (int) relocation.getAddend();

		if (symbolIndex == 0) {// TODO
			return;
		}

		long relocWordOffset = (int) relocationAddress.getAddressableWordOffset();

		ElfSymbol sym = elfRelocationContext.getSymbol(symbolIndex);
		int symbolValue = (int) elfRelocationContext.getSymbolValue(sym); // word offset

		int oldValue = memory.getInt(relocationAddress);
		short oldShortValue = memory.getShort(relocationAddress);

		int newValue;

		ElfHeader elf = elfRelocationContext.getElfHeader();
		if (elf.e_machine() == ElfConstants.EM_DSPIC30F) {
			switch (type) {
			case R_PIC30_16: // 2
			case R_PIC30_FILE_REG_WORD: // 6
				newValue = (symbolValue + addend + oldShortValue);
				memory.setShort(relocationAddress, (short) newValue);
				break;
			case R_PIC30_32: // 3
				newValue = symbolValue + addend + oldValue;
				memory.setInt(relocationAddress, newValue);
				break;
			case R_PIC30_FILE_REG_BYTE: // 4 short
			case R_PIC30_FILE_REG: // 5 short
				int reloc = symbolValue;
				reloc += addend;
				reloc += oldShortValue;
				reloc &= 0x1fff;
				newValue = reloc | (oldShortValue & ~0x1fff);
				memory.setShort(relocationAddress, (short) newValue);
				break;
			case R_PIC30_FILE_REG_WORD_WITH_DST: // 7
				reloc = symbolValue >> 1;
				reloc += addend;
				reloc += oldValue >> 4;
				reloc &= 0x7fff;
				newValue = (reloc << 4) | (oldValue & ~0x7fff0);
				memory.setInt(relocationAddress, newValue);
				break;
			case R_PIC30_WORD: // 8
			case R_PIC30_WORD_TBLOFFSET: // 0x15
				reloc = symbolValue;
				reloc += addend;
				reloc += oldValue >> 4;
				reloc &= 0xffff;
				newValue = (reloc << 4) | (oldValue & ~0x0ffff0);
				memory.setInt(relocationAddress, newValue);
				break;
			case R_PIC30_WORD_TBLPAGE: // 0x18
				reloc = symbolValue >> 16;
				reloc += addend;
				reloc += oldValue >> 4;
				reloc &= 0xffff;
				if (isEDSVariant(elfRelocationContext)) {
					reloc |= 0x100;
				}
				newValue = (reloc << 4) | (oldValue & ~0x0ffff0);
				memory.setInt(relocationAddress, newValue);
				break;
			case R_PIC30_PCREL_BRANCH: // 0x1c
				newValue = (int) (symbolValue - relocWordOffset + oldShortValue - 2);
				newValue >>>= 1;
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;
			default:
				String symbolName = sym.getNameAsString();
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
						elfRelocationContext.getLog());
				break;
			}
		}
	}

}
