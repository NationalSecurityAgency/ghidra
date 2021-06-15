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

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.exception.NotFoundException;

public class ARM_ElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_ARM;
	}

	@Override
	public void relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation,
			Address relocationAddress) throws MemoryAccessException, NotFoundException {

		ElfHeader elf = elfRelocationContext.getElfHeader();
		if (elf.e_machine() != ElfConstants.EM_ARM) {
			return;
		}

		Program program = elfRelocationContext.getProgram();

		Memory memory = program.getMemory();
		
		boolean instructionBigEndian = program.getLanguage().getLanguageDescription().getInstructionEndian().isBigEndian();		
		
		int type = relocation.getType();
		if (type == ARM_ElfRelocationConstants.R_ARM_NONE) {
			return;
		}
		int symbolIndex = relocation.getSymbolIndex();

		long addend = relocation.getAddend(); // will be 0 for REL case

		ElfSymbol sym = elfRelocationContext.getSymbol(symbolIndex);
		String symbolName = sym.getNameAsString();

		boolean isThumb = isThumb(sym);

		long offset = (int) relocationAddress.getOffset();

		Address symbolAddr = elfRelocationContext.getSymbolAddress(sym);
		long symbolValue = elfRelocationContext.getSymbolValue(sym);

		int newValue = 0;

		switch (type) {
			case ARM_ElfRelocationConstants.R_ARM_PC24: { // Target class: ARM Instruction
				int oldValue = memory.getInt(relocationAddress, instructionBigEndian);
				if (elfRelocationContext.extractAddend()) {
					addend = (oldValue << 8 >> 6); // extract addend and sign-extend with *4 factor
				}
				newValue = (int) (symbolValue - offset + addend);
				// if this a BLX instruction, must set bit24 to identify half-word
				if ((oldValue & 0xf0000000) == 0xf0000000) {
					newValue = (oldValue & 0xfe000000) | (((newValue >> 1) & 1) << 24) |
						((newValue >> 2) & 0x00ffffff);
				}
				else {
					newValue = (oldValue & 0xff000000) | ((newValue >> 2) & 0x00ffffff);
				}
				memory.setInt(relocationAddress, newValue, instructionBigEndian);
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_ABS32: { // Target class: Data
				if (elfRelocationContext.extractAddend()) {
					addend = memory.getInt(relocationAddress);
				}
				if (addend != 0 && isUnsupportedExternalRelocation(program, relocationAddress,
					symbolAddr, symbolName, addend, elfRelocationContext.getLog())) {
					addend = 0; // prefer bad fixup for EXTERNAL over really-bad fixup
				}
				newValue = (int) (symbolValue + addend);
				if (isThumb) {
					newValue |= 1;
				}
				memory.setInt(relocationAddress, newValue);
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_REL32: { // Target class: Data
				if (elfRelocationContext.extractAddend()) {
					addend = memory.getInt(relocationAddress);
				}
				newValue = (int) (symbolValue + addend);
				newValue -= offset;  // PC relative
				if (isThumb) {
					newValue |= 1;
				}
				memory.setInt(relocationAddress, newValue);
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_PREL31: { // Target class: Data
				int oldValue = memory.getInt(relocationAddress);
				if (elfRelocationContext.extractAddend()) {
					addend = (oldValue << 1) >> 1;
				}
				newValue = (int) (symbolValue + addend);
				newValue -= offset;  // PC relative
				if (isThumb) {
					newValue |= 1;
				}
				newValue = (newValue & 0x7fffffff) + (oldValue & 0x80000000);
				memory.setInt(relocationAddress, newValue);
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_LDR_PC_G0: { // Target class: ARM Instruction
				int oldValue = memory.getInt(relocationAddress, instructionBigEndian);
				newValue = (int) (symbolValue + addend);
				newValue -= (offset + 8);  // PC relative, PC will be 8 bytes after inst start
				newValue = (oldValue & 0xff7ff000) | ((~(newValue >> 31) & 1) << 23) |
					((newValue >> 2) & 0xfff);
				memory.setInt(relocationAddress, newValue, instructionBigEndian);
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_ABS16: { // Target class: Data
				short sValue = (short) (symbolValue + addend);
				memory.setShort(relocationAddress, sValue);
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_ABS12: { // Target class: ARM Instruction
				int oldValue = memory.getInt(relocationAddress, instructionBigEndian);
				newValue = (int) (symbolValue + addend);
				newValue = (oldValue & 0xfffff000) | (newValue & 0x00000fff);
				memory.setInt(relocationAddress, newValue, instructionBigEndian);
				break;
			}
			/*
			case ARM_ElfRelocationConstants.R_ARM_THM_ABS5: {
				break;
			}
			*/
			case ARM_ElfRelocationConstants.R_ARM_ABS_8: { // Target class: Data
				byte bValue = (byte) (symbolValue + addend);
				memory.setByte(relocationAddress, bValue);
				break;
			}
			/*
			case ARM_ElfRelocationConstants.R_ARM_SBREL32: {
				break;
			}
			*/
			case ARM_ElfRelocationConstants.R_ARM_THM_JUMP24: // // Target class: Thumb32 Instruction
			case ARM_ElfRelocationConstants.R_ARM_THM_CALL: {

				newValue = (int) (symbolValue + addend);
				// since it is adding in the oldvalue below, don't need to add in 4 for pc offset
				newValue -= (offset);

				short oldValueH = memory.getShort(relocationAddress, instructionBigEndian);
				short oldValueL = memory.getShort(relocationAddress.add(2), instructionBigEndian);
				boolean isBLX = (oldValueL & 0x1000) == 0;

				int s = (oldValueH & (1 << 10)) >> 10;
				int upper = oldValueH & 0x3ff;
				int lower = oldValueL & 0x7ff;
				int j1 = (oldValueL & (1 << 13)) >> 13;
				int j2 = (oldValueL & (1 << 11)) >> 11;
				int i1 = (j1 != s) ? 0 : 1;
				int i2 = (j2 != s) ? 0 : 1;
				int origaddend = (i1 << 23) | (i2 << 22) | (upper << 12) | (lower << 1);
				origaddend = (origaddend | ((s ^ 1) << 24)) - (1 << 24);

				newValue = newValue + origaddend;

				newValue = newValue >> 1;
				// for Thumb, have to be careful, LE is swapped on 2 bytes
				short newValueH = (short) ((oldValueH & 0xf800) | (((newValue >> 11) & 0x00007ff)));
				short newValueL = (short) ((oldValueL & 0xf800) | (newValue & 0x00007ff));

				if (isBLX) {
					newValueL &= 0xfffe;
				}

				memory.setShort(relocationAddress, newValueH, instructionBigEndian);
				memory.setShort(relocationAddress.add(2), newValueL, instructionBigEndian);
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_THM_PC8: { // Target class: Thumb16 Instruction
				short oldValue = memory.getShort(relocationAddress, instructionBigEndian);
				newValue = (int) (symbolValue + addend);
				newValue -= (offset + 4);   // PC relative, PC will be 4 bytes past inst start
				newValue = newValue >> 1;
				short sValue = (short) ((oldValue & 0xff00) | (newValue & 0x00ff));
				memory.setShort(relocationAddress, sValue, instructionBigEndian);
				break;
			}
			/*
			case ARM_ElfRelocationConstants.R_ARM_BREL_ADJ: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_TLS_DESC: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_THM_SWI8: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_XPC25: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_THM_XPC22: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_TLS_DTPMOD32: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_TLS_DTPOFF32: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_TLS_TPOFF32: {
				break;
			}
			*/

			case ARM_ElfRelocationConstants.R_ARM_GLOB_DAT: {
				// Corresponds to resolved local/EXTERNAL symbols within GOT
				if (elfRelocationContext.extractAddend()) {
					addend = memory.getInt(relocationAddress);
				}
				newValue = (int) (symbolValue + addend);
				if (isThumb) {
					newValue |= 1;
				}
				memory.setInt(relocationAddress, newValue);
				break;
			}

			case ARM_ElfRelocationConstants.R_ARM_JUMP_SLOT: { // Target class: Data
				// Corresponds to lazy dynamically linked external symbols within
				// GOT/PLT symbolValue corresponds to PLT entry for which we need to
				// create and external function location. Don't bother changing
				// GOT entry bytes if it refers to .plt block
				Address symAddress = elfRelocationContext.getSymbolAddress(sym);
				MemoryBlock block = memory.getBlock(symAddress);
				boolean isPltSym = block != null && block.getName().startsWith(".plt");
				boolean isExternalSym =
					block != null && MemoryBlock.EXTERNAL_BLOCK_NAME.equals(block.getName());
				if (!isPltSym) {
					memory.setInt(relocationAddress, (int) symAddress.getOffset());
				}
				if (isPltSym || isExternalSym) {
					Function extFunction =
						elfRelocationContext.getLoadHelper().createExternalFunctionLinkage(
							symbolName, symAddress, null);
					if (extFunction == null) {
						markAsError(program, relocationAddress, "R_ARM_JUMP_SLOT", symbolName,
							"Failed to create R_ARM_JUMP_SLOT external function",
							elfRelocationContext.getLog());
						return;
					}
				}
				break;
			}

			case ARM_ElfRelocationConstants.R_ARM_RELATIVE: { // Target class: Data
				if (elfRelocationContext.extractAddend()) {
					addend = memory.getInt(relocationAddress);
				}
				newValue =
					(int) elfRelocationContext.getImageBaseWordAdjustmentOffset() + (int) addend;
				memory.setInt(relocationAddress, newValue);
				break;
			}
			/*
			case ARM_ElfRelocationConstants.R_ARM_GOTOFF32: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_BASE_PREL: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_GOT_BREL: {
				break;
			}
			*/

			case ARM_ElfRelocationConstants.R_ARM_JUMP24: // Target class: ARM Instruction
			case ARM_ElfRelocationConstants.R_ARM_CALL:
			case ARM_ElfRelocationConstants.R_ARM_GOT_PLT32:
				int oldValue = memory.getInt(relocationAddress, instructionBigEndian);
				newValue = (int) (symbolValue + addend);

				newValue -= (offset + 8);   // PC relative, PC will be 8 bytes past inst start

				// is this a BLX instruction, must put the lower half word in bit24
				// TODO: this might not appear on a BLX, but just in case
				if ((oldValue & 0xff000000) == 0xfb000000) {
					newValue = (oldValue & 0xfe000000) | (((newValue >> 1) & 1) << 24) |
						((newValue >> 2) & 0x00ffffff);
				}
				else {
					newValue = (oldValue & 0xff000000) | ((newValue >> 2) & 0x00ffffff);
				}
				memory.setInt(relocationAddress, newValue, instructionBigEndian);
				break;

			/*
			case ARM_ElfRelocationConstants.R_ARM_BASE_ABS: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_ALU_PCREL_7_0: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_ALU_PCREL_15_8: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_ALU_PCREL_23_15: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_LDR_SBREL_11_0_NC: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_ALU_SBREL_19_12_NC: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_ALU_SBREL_27_20_CK: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_TARGET1: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_SBREL31: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_V4BX: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_TARGET2: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_PREL31: {
				break;
			}
*/
			case ARM_ElfRelocationConstants.R_ARM_MOVW_ABS_NC: 
			case ARM_ElfRelocationConstants.R_ARM_MOVT_ABS: {	// Target Class: ARM Instruction		
				oldValue = memory.getInt(relocationAddress, instructionBigEndian);
				newValue = oldValue;
				
				oldValue = ((oldValue & 0xf0000) >> 4) | (oldValue & 0xfff);
				oldValue = (oldValue ^ 0x8000) - 0x8000;

				oldValue += symbolValue;
				if (type == ARM_ElfRelocationConstants.R_ARM_MOVT_ABS) {
					oldValue >>= 16;
				}

				newValue &= 0xfff0f000;
				newValue |= ((oldValue & 0xf000) << 4) |
					(oldValue & 0x0fff);

				memory.setInt(relocationAddress, newValue, instructionBigEndian);

				break;
			}
/*
			case ARM_ElfRelocationConstants.R_ARM_MOVW_PREL_NC: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_MOVT_PREL: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_THM_MOVW_ABS_NC: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_THM_MOVT_ABS: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_THM_MOVW_PREL_NC: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_THM_MOVT_PREL: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_THM_JUMP19: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_THM_JUMP6: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_THM_ALU_PREL_11_0: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_THM_PC12: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_ABS32_NOI: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_REL32_NOI: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_ALU_PC_G0_NC: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_ALU_PC_G0: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_ALU_PC_G1_NC: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_ALU_PC_G1: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_ALU_PC_G2: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_LDR_PC_G1: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_LDR_PC_G2: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_LDRS_PC_G0: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_LDRS_PC_G1: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_LDRS_PC_G2: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_LDC_PC_G0: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_LDC_PC_G1: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_LDC_PC_G2: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_ALU_SB_G0_NC: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_ALU_SB_G0: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_ALU_SB_G1_NC: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_ALU_SB_G1: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_ALU_SB_G2: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_LDR_SB_G0: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_LDR_SB_G1: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_LDR_SB_G2: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_LDRS_SB_G0: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_LDRS_SB_G1: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_LDRS_SB_G2: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_LDC_SB_G0: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_LDC_SB_G1: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_LDC_SB_G2: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_MOVW_BREL_NC: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_MOVT_BREL: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_MOVW_BREL: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_THM_MOVW_BREL_NC: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_THM_MOVT_BREL: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_THM_MOVW_BREL: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_TLS_GOTDESC: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_TLS_CALL: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_TLS_DESCSEQ: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_THM_TLS_CALL: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_PLT32_ABS: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_GOT_ABS: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_GOT_PREL: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_GOT_BREL12: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_GOTOFF12: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_GOTRELAX: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_GNU_VTENTRY: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_GNU_VTINHERIT: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_THM_JUMP11: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_THM_JUMP8: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_TLS_GD32: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_TLS_LDM32: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_TLS_LDO32: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_TLS_IE32: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_TLS_LE32: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_TLS_LDO12: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_TLS_LE12: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_TLS_IE12GP: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_0: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_1: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_2: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_3: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_4: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_5: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_6: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_7: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_8: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_9: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_10: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_11: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_12: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_13: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_14: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_PRIVATE_15: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_THM_TLS_DESCSEQ16: {
				break;
			}
			case ARM_ElfRelocationConstants.R_ARM_THM_TLS_DESCSEQ32: {
				break;
			}
			*/

			case ARM_ElfRelocationConstants.R_ARM_COPY: {
				markAsWarning(program, relocationAddress, "R_ARM_COPY", symbolName, symbolIndex,
					"Runtime copy not supported", elfRelocationContext.getLog());
				break;
			}

			default: {
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				break;
			}
		}
	}

	private boolean isThumb(ElfSymbol symbol) {
		if (symbol.isFunction() && (symbol.getValue() % 1) == 1) {
			return true;
		}
		return false;
	}

}
