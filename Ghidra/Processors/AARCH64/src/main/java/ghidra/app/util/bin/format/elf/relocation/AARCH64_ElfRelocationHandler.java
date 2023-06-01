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

import org.apache.commons.lang3.StringUtils;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;
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
	public RelocationResult relocate(ElfRelocationContext elfRelocationContext,
			ElfRelocation relocation,
			Address relocationAddress) throws MemoryAccessException, NotFoundException {

		ElfHeader elf = elfRelocationContext.getElfHeader();
		if (elf.e_machine() != ElfConstants.EM_AARCH64) {
			return RelocationResult.FAILURE;
		}

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		int type = relocation.getType();
		if (type == AARCH64_ElfRelocationConstants.R_AARCH64_NONE) {
			return RelocationResult.SKIPPED;
		}
		int symbolIndex = relocation.getSymbolIndex();

		long addend = relocation.getAddend(); // will be 0 for REL case

		ElfSymbol sym = elfRelocationContext.getSymbol(symbolIndex);
		String symbolName = sym.getNameAsString();

		//boolean isThumb = isThumb(sym);

		long offset = (int) relocationAddress.getOffset();

		boolean isBigEndianInstructions =
			program.getLanguage().getLanguageDescription().getInstructionEndian().isBigEndian();

		boolean is64bit = true;
		
		boolean overflowCheck = true; // *_NC type relocations specify "no overflow check"

		Address symbolAddr = elfRelocationContext.getSymbolAddress(sym);
		long symbolValue = elfRelocationContext.getSymbolValue(sym);
		long newValue = 0;

		int byteLength = 4; // most relocations affect 4-bytes (change if different)

		switch (type) {
			// .xword: (S+A)
			case AARCH64_ElfRelocationConstants.R_AARCH64_ABS64: {
				newValue = (symbolValue + addend);
				memory.setLong(relocationAddress, newValue);
				if (symbolIndex != 0 && addend != 0 && !sym.isSection()) {
					warnExternalOffsetRelocation(program, relocationAddress,
						symbolAddr, symbolName, addend, elfRelocationContext.getLog());
					applyComponentOffsetPointer(program, relocationAddress, addend);
				}
				byteLength = 8;
				break;
			}

			// .word: (S+A)
			case AARCH64_ElfRelocationConstants.R_AARCH64_ABS32:
			case AARCH64_ElfRelocationConstants.R_AARCH64_P32_ABS32:{
				newValue = (symbolValue + addend);
				memory.setInt(relocationAddress, (int) (newValue & 0xffffffff));
				break;
			}

			// .half: (S+A)
			
			case AARCH64_ElfRelocationConstants.R_AARCH64_ABS16:
			case AARCH64_ElfRelocationConstants.R_AARCH64_P32_ABS16: {
				newValue = (symbolValue + addend);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				byteLength = 2;
				break;
			}

			// .xword: (S+A-P)
			case AARCH64_ElfRelocationConstants.R_AARCH64_PREL64: {
				newValue = (symbolValue + addend);
				newValue -= (offset); // PC relative
				memory.setLong(relocationAddress, newValue);
				byteLength = 8;
				break;
			}

			// .word: (S+A-P)
			case AARCH64_ElfRelocationConstants.R_AARCH64_PREL32:
			case AARCH64_ElfRelocationConstants.R_AARCH64_P32_PREL32: {
				newValue = (symbolValue + addend);
				newValue -= (offset); // PC relative
				memory.setInt(relocationAddress, (int) (newValue & 0xffffffff));
				break;
			}

			// .half: (S+A-P)
			case AARCH64_ElfRelocationConstants.R_AARCH64_PREL16:
			case AARCH64_ElfRelocationConstants.R_AARCH64_P32_PREL16: {
				newValue = (symbolValue + addend);
				newValue -= (offset); // PC relative
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				byteLength = 2;
				break;
			}

			// MOV[ZK]:   ((S+A) >>  0) & 0xffff
			case AARCH64_ElfRelocationConstants.R_AARCH64_MOVW_UABS_G0_NC: {
				overflowCheck = false;
				// fall-through
			}
			case AARCH64_ElfRelocationConstants.R_AARCH64_MOVW_UABS_G0: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				long imm = (symbolValue + addend) >> 0;

				oldValue &= ~(0xffff << 5);
				newValue = oldValue | ((imm & 0xffff) << 5);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);

				if (overflowCheck && imm > 0xffffL) {
					// relocation already applied; report overflow condition
					markAsError(program, relocationAddress, "R_AARCH64_MOVW_UABS_G0", symbolName,
						"Failed overflow check for R_AARCH64_MOVW_UABS_G0 immediate value",
						elfRelocationContext.getLog());
				}
				break;
			}

			// MOV[ZK]:   ((S+A) >>  16) & 0xffff
			case AARCH64_ElfRelocationConstants.R_AARCH64_MOVW_UABS_G1_NC: {
				overflowCheck = false;
				// fall-through
			}
			case AARCH64_ElfRelocationConstants.R_AARCH64_MOVW_UABS_G1: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				long imm = (symbolValue + addend) >> 16;

				oldValue &= ~(0xffff << 5);
				newValue = oldValue | ((imm & 0xffff) << 5);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);

				if (overflowCheck && imm > 0xffffL) {
					// relocation already applied; report overflow condition
					markAsError(program, relocationAddress, "R_AARCH64_MOVW_UABS_G0", symbolName,
						"Failed overflow check for R_AARCH64_MOVW_UABS_G0 immediate value",
						elfRelocationContext.getLog());
				}
				break;
			}

			// MOV[ZK]:   ((S+A) >>  32) & 0xffff
			case AARCH64_ElfRelocationConstants.R_AARCH64_MOVW_UABS_G2_NC: {
				overflowCheck = false;
				// fall-through
			}
			case AARCH64_ElfRelocationConstants.R_AARCH64_MOVW_UABS_G2: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				long imm = (symbolValue + addend) >> 32;

				oldValue &= ~(0xffff << 5);
				newValue = oldValue | ((imm & 0xffff) << 5);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);

				if (overflowCheck && imm > 0xffffL) {
					// relocation already applied; report overflow condition
					markAsError(program, relocationAddress, "R_AARCH64_MOVW_UABS_G0", symbolName,
						"Failed overflow check for R_AARCH64_MOVW_UABS_G0 immediate value",
						elfRelocationContext.getLog());
				}
				break;
			}

			// MOV[ZK]:   ((S+A) >>  48) & 0xffff
			case AARCH64_ElfRelocationConstants.R_AARCH64_MOVW_UABS_G3: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				long imm = (symbolValue + addend) >> 48;

				oldValue &= ~(0xffff << 5);
				newValue = oldValue | ((imm & 0xffff) << 5);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// ADRH: ((PG(S+A)-PG(P)) >> 12) & 0x1fffff
			case AARCH64_ElfRelocationConstants.R_AARCH64_ADR_PREL_PG_HI21:
			case AARCH64_ElfRelocationConstants.R_AARCH64_P32_ADR_PREL_PG_HI21: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				newValue = ((PG(symbolValue + addend) - PG(offset)) >> 12) & 0x1fffff;

				newValue = (oldValue & 0x9f00001f) | ((newValue << 3) & 0xffffe0) |
					((newValue & 0x3) << 29);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// ADD: (S+A) & 0xfff
			case AARCH64_ElfRelocationConstants.R_AARCH64_ADD_ABS_LO12_NC:
		    case AARCH64_ElfRelocationConstants.R_AARCH64_P32_ADD_ABS_LO12_NC: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				newValue = (int) (symbolValue + addend) & 0xfff;

				newValue = oldValue | (newValue << 10);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// LD/ST8: (S+A) & 0xfff
			case AARCH64_ElfRelocationConstants.R_AARCH64_LDST8_ABS_LO12_NC:
			case AARCH64_ElfRelocationConstants.R_AARCH64_P32_LDST8_ABS_LO12_NC: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				newValue = (int) (symbolValue + addend) & 0xfff;

				newValue = oldValue | (newValue << 10);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// B:  ((S+A-P) >> 2) & 0x3ffffff.
			// BL: ((S+A-P) >> 2) & 0x3ffffff
			case AARCH64_ElfRelocationConstants.R_AARCH64_JUMP26:
			case AARCH64_ElfRelocationConstants.R_AARCH64_P32_JUMP26:
			case AARCH64_ElfRelocationConstants.R_AARCH64_CALL26:
			case AARCH64_ElfRelocationConstants.R_AARCH64_P32_CALL26: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				newValue = (symbolValue + addend);

				newValue -= (offset); // PC relative

				newValue = oldValue | ((newValue >> 2) & 0x03ffffff);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// LD/ST16: (S+A) & 0xffe 
			case AARCH64_ElfRelocationConstants.R_AARCH64_LDST16_ABS_LO12_NC:
			case AARCH64_ElfRelocationConstants.R_AARCH64_P32_LDST16_ABS_LO12_NC: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				newValue = (int) ((symbolValue + addend) & 0xffe) >> 1;

				newValue = oldValue | (newValue << 10);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// LD/ST32: (S+A) & 0xffc
			case AARCH64_ElfRelocationConstants.R_AARCH64_LDST32_ABS_LO12_NC:
			case AARCH64_ElfRelocationConstants.R_AARCH64_P32_LDST32_ABS_LO12_NC: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				newValue = (int) ((symbolValue + addend) & 0xffc) >> 2;

				newValue = oldValue | (newValue << 10);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// LD/ST64: (S+A) & 0xff8
			case AARCH64_ElfRelocationConstants.R_AARCH64_LDST64_ABS_LO12_NC:
			case AARCH64_ElfRelocationConstants.R_AARCH64_P32_LDST64_ABS_LO12_NC:
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

			case AARCH64_ElfRelocationConstants.R_AARCH64_P32_GLOB_DAT:
				is64bit = false;
			case AARCH64_ElfRelocationConstants.R_AARCH64_GLOB_DAT: {
				// Corresponds to resolved local/EXTERNAL symbols within GOT
				if (elfRelocationContext.extractAddend()) {
					addend = getValue(memory, relocationAddress, is64bit);
				}
				newValue = symbolValue + addend;
				byteLength = setValue(memory, relocationAddress, newValue, is64bit);
				break;
			}

			case AARCH64_ElfRelocationConstants.R_AARCH64_P32_JUMP_SLOT:
				is64bit = false;
			case AARCH64_ElfRelocationConstants.R_AARCH64_JUMP_SLOT: {
				// Corresponds to lazy dynamically linked external symbols within
				// GOT/PLT symbolValue corresponds to PLT entry for which we need to
				// create and external function location. Don't bother changing
				// GOT entry bytes if it refers to .plt block
				Address symAddress = elfRelocationContext.getSymbolAddress(sym);
				MemoryBlock block = memory.getBlock(symAddress);
				// TODO: jump slots are always in GOT - not sure why PLT check is done
				boolean isPltSym = block != null && block.getName().startsWith(".plt");
				boolean isExternalSym =
					block != null && MemoryBlock.EXTERNAL_BLOCK_NAME.equals(block.getName());
				if (!isPltSym) {
					byteLength =
						setValue(memory, relocationAddress, symAddress.getOffset(), is64bit);
				}
				if ((isPltSym || isExternalSym) && !StringUtils.isBlank(symbolName)) {
					Function extFunction =
						elfRelocationContext.getLoadHelper().createExternalFunctionLinkage(
							symbolName, symAddress, null);
					if (extFunction == null) {
						markAsError(program, relocationAddress, "R_AARCH64_JUMP_SLOT", symbolName,
							"Failed to create R_AARCH64_JUMP_SLOT external function",
							elfRelocationContext.getLog());
						// relocation already applied above
					}
				}
				break;
			}

			case AARCH64_ElfRelocationConstants.R_AARCH64_P32_RELATIVE:
				is64bit = false;
			case AARCH64_ElfRelocationConstants.R_AARCH64_RELATIVE: {
				if (elfRelocationContext.extractAddend()) {
					addend = getValue(memory, relocationAddress, is64bit);
				}
				newValue = elfRelocationContext.getImageBaseWordAdjustmentOffset() + addend;
				byteLength = setValue(memory, relocationAddress, newValue, is64bit);
				break;
			}

			case AARCH64_ElfRelocationConstants.R_AARCH64_P32_COPY:
			case AARCH64_ElfRelocationConstants.R_AARCH64_COPY: {
				markAsWarning(program, relocationAddress, "R_AARCH64_COPY", symbolName, symbolIndex,
					"Runtime copy not supported", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
			}

			default: {
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
			}
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}

	/**
	 * Set the new value in memory
	 * @param memory memory
	 * @param addr address to set new value
	 * @param value value
	 * @param is64bit true if value is 64, false if 32bit
	 * return value byte-length
	 * @throws MemoryAccessException on set of value
	 */
	private int setValue(Memory memory, Address addr, long value, boolean is64bit)
			throws MemoryAccessException {
		if (is64bit) {
			memory.setLong(addr, value);
			return 8;
		}

		memory.setInt(addr, (int) value);
		return 4;
	}

	/**
	 * Get a 64 or 32 bit value from memory
	 * @param memory memory
	 * @param addr address in memory
	 * @param is64bit true if 64 bit value, false if 32 bit value
	 * @return value from memory as a long
	 * @throws MemoryAccessException
	 */
	private long getValue(Memory memory, Address addr, boolean is64bit)
			throws MemoryAccessException {
		if (is64bit) {
			return memory.getLong(addr);
		}
		return memory.getInt(addr);
	}

	long PG(long addr) {
		return addr & (~0xfff);
	}

}
