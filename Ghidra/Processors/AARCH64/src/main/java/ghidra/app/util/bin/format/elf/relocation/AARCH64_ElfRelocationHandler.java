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

public class AARCH64_ElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_AARCH64;
	}

	@Override
	public int getRelrRelocationType() {
		return AARCH64_ElfRelocationConstants.R_AARCH64_RELATIVE;
	}

	@Override
	public void relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation,
			Address relocationAddress) throws MemoryAccessException, NotFoundException {

		ElfHeader elf = elfRelocationContext.getElfHeader();
		if (elf.e_machine() != ElfConstants.EM_AARCH64) {
			return;
		}

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		int type = relocation.getType();
		if (type == AARCH64_ElfRelocationConstants.R_AARCH64_NONE) {
			return;
		}
		int symbolIndex = relocation.getSymbolIndex();

		long addend = relocation.getAddend(); // will be 0 for REL case

		ElfSymbol sym = elfRelocationContext.getSymbol(symbolIndex);
		String symbolName = sym.getNameAsString();

		//boolean isThumb = isThumb(sym);

		long offset = (int) relocationAddress.getOffset();

		boolean isBigEndianInstructions =
			program.getLanguage().getLanguageDescription().getInstructionEndian().isBigEndian();

		Address symbolAddr = elfRelocationContext.getSymbolAddress(sym);
		long symbolValue = elfRelocationContext.getSymbolValue(sym);
		long newValue = 0;

		switch (type) {
			// .xword: (S+A)
			case AARCH64_ElfRelocationConstants.R_AARCH64_ABS64: {
				newValue = (symbolValue + addend);
				memory.setLong(relocationAddress, newValue);
				if (addend != 0) {
					warnExternalOffsetRelocation(program, relocationAddress,
						symbolAddr, symbolName, addend, elfRelocationContext.getLog());
					applyComponentOffsetPointer(program, relocationAddress, addend);
				}
				break;
			}

			// .word: (S+A)
			case AARCH64_ElfRelocationConstants.R_AARCH64_ABS32: {
				newValue = (symbolValue + addend);
				memory.setInt(relocationAddress, (int) (newValue & 0xffffffff));
				break;
			}

			// .half: (S+A)
			case AARCH64_ElfRelocationConstants.R_AARCH64_ABS16: {
				newValue = (symbolValue + addend);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;
			}

			// .xword: (S+A-P)
			case AARCH64_ElfRelocationConstants.R_AARCH64_PREL64: {
				newValue = (symbolValue + addend);
				newValue -= (offset); // PC relative
				memory.setLong(relocationAddress, newValue);
				break;
			}

			// .word: (S+A-P)
			case AARCH64_ElfRelocationConstants.R_AARCH64_PREL32: {
				newValue = (symbolValue + addend);
				newValue -= (offset); // PC relative
				memory.setInt(relocationAddress, (int) (newValue & 0xffffffff));
				break;
			}

			// .half: (S+A-P)
			case AARCH64_ElfRelocationConstants.R_AARCH64_PREL16: {
				newValue = (symbolValue + addend);
				newValue -= (offset); // PC relative
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;
			}

			// ADRH: ((PG(S+A)-PG(P)) >> 12) & 0x1fffff
			case AARCH64_ElfRelocationConstants.R_AARCH64_ADR_PREL_PG_HI21: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				newValue = ((PG(symbolValue + addend) - PG(offset)) >> 12) & 0x1fffff;

				newValue = (oldValue & 0x9f00001f) | ((newValue << 3) & 0xffffe0) |
					((newValue & 0x3) << 29);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// ADD: (S+A) & 0xfff
			case AARCH64_ElfRelocationConstants.R_AARCH64_ADD_ABS_LO12_NC: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				newValue = (int) (symbolValue + addend) & 0xfff;

				newValue = oldValue | (newValue << 10);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// LD/ST8: (S+A) & 0xfff
			case AARCH64_ElfRelocationConstants.R_AARCH64_LDST8_ABS_LO12_NC: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				newValue = (int) (symbolValue + addend) & 0xfff;

				newValue = oldValue | (newValue << 10);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// B:  ((S+A-P) >> 2) & 0x3ffffff.
			// BL: ((S+A-P) >> 2) & 0x3ffffff
			case AARCH64_ElfRelocationConstants.R_AARCH64_JUMP26:
			case AARCH64_ElfRelocationConstants.R_AARCH64_CALL26: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				newValue = (symbolValue + addend);

				newValue -= (offset); // PC relative

				newValue = oldValue | ((newValue >> 2) & 0x03ffffff);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// LD/ST16: (S+A) & 0xffe 
			case AARCH64_ElfRelocationConstants.R_AARCH64_LDST16_ABS_LO12_NC: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				newValue = (int) ((symbolValue + addend) & 0xffe) >> 1;

				newValue = oldValue | (newValue << 10);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// LD/ST32: (S+A) & 0xffc
			case AARCH64_ElfRelocationConstants.R_AARCH64_LDST32_ABS_LO12_NC: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				newValue = (int) ((symbolValue + addend) & 0xffc) >> 2;

				newValue = oldValue | (newValue << 10);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// LD/ST64: (S+A) & 0xff8
			case AARCH64_ElfRelocationConstants.R_AARCH64_LDST64_ABS_LO12_NC:
			case AARCH64_ElfRelocationConstants.R_AARCH64_LD64_GOT_LO12_NC: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				newValue = (int) ((symbolValue + addend) & 0xff8) >> 3;

				newValue = oldValue | (newValue << 10);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// LD/ST128: (S+A) & 0xff0
			case AARCH64_ElfRelocationConstants.R_AARCH64_LDST128_ABS_LO12_NC: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				newValue = (int) ((symbolValue + addend) & 0xff0) >> 4;

				newValue = oldValue | (newValue << 10);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			case AARCH64_ElfRelocationConstants.R_AARCH64_GLOB_DAT: {
				// Corresponds to resolved local/EXTERNAL symbols within GOT
				if (elfRelocationContext.extractAddend()) {
					addend = memory.getLong(relocationAddress);
				}
				newValue = symbolValue + addend;
				memory.setLong(relocationAddress, newValue);
				break;
			}

			case AARCH64_ElfRelocationConstants.R_AARCH64_JUMP_SLOT: {
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
					memory.setLong(relocationAddress, symAddress.getOffset());
				}
				if (isPltSym || isExternalSym) {
					Function extFunction =
						elfRelocationContext.getLoadHelper().createExternalFunctionLinkage(
							symbolName, symAddress, null);
					if (extFunction == null) {
						markAsError(program, relocationAddress, "R_AARCH64_JUMP_SLOT", symbolName,
							"Failed to create R_AARCH64_JUMP_SLOT external function",
							elfRelocationContext.getLog());
						return;
					}
				}
				break;
			}

			case AARCH64_ElfRelocationConstants.R_AARCH64_RELATIVE: {
				if (elfRelocationContext.extractAddend()) {
					addend = memory.getLong(relocationAddress);
				}
				newValue = elfRelocationContext.getImageBaseWordAdjustmentOffset() + addend;
				memory.setLong(relocationAddress, newValue);
				break;
			}

			case AARCH64_ElfRelocationConstants.R_AARCH64_COPY: {
				markAsWarning(program, relocationAddress, "R_AARCH64_COPY", symbolName, symbolIndex,
					"Runtime copy not supported", elfRelocationContext.getLog());
			}

			default: {
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				break;
			}
		}
	}

	long PG(long addr) {
		return addr & (~0xfff);
	}

}
