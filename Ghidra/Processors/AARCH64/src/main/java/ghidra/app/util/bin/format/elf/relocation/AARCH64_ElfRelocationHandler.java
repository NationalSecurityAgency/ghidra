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

import org.apache.commons.lang3.StringUtils;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;

public class AARCH64_ElfRelocationHandler extends
		AbstractElfRelocationHandler<AARCH64_ElfRelocationType, AARCH64_ElfRelocationContext> {

	/**
	 * Constructor
	 */
	public AARCH64_ElfRelocationHandler() {
		super(AARCH64_ElfRelocationType.class);
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_AARCH64;
	}

	@Override
	public int getRelrRelocationType() {
		return AARCH64_ElfRelocationType.R_AARCH64_RELATIVE.typeId;
	}

	@Override
	public AARCH64_ElfRelocationContext createRelocationContext(ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		return new AARCH64_ElfRelocationContext(this, loadHelper, symbolMap);
	}

	@Override
	protected RelocationResult relocate(AARCH64_ElfRelocationContext elfRelocationContext,
			ElfRelocation relocation, AARCH64_ElfRelocationType type, Address relocationAddress,
			ElfSymbol sym, Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();
		boolean isBigEndianInstructions =
			program.getLanguage().getLanguageDescription().getInstructionEndian().isBigEndian();

		long addend = relocation.getAddend(); // will be 0 for REL case
		long offset = relocationAddress.getOffset();

		int symbolIndex = relocation.getSymbolIndex();
		boolean is64bit = true;
		boolean overflowCheck = true; // *_NC type relocations specify "no overflow check"
		long newValue = 0;
		int byteLength = 4; // most relocations affect 4-bytes (change if different)

		// Handle relative relocations that do not require symbolAddr or symbolValue 
		switch (type) {
			case R_AARCH64_P32_RELATIVE:
				is64bit = false;
			case R_AARCH64_RELATIVE:
				if (elfRelocationContext.extractAddend()) {
					addend = getValue(memory, relocationAddress, is64bit);
				}
				newValue = elfRelocationContext.getImageBaseWordAdjustmentOffset() + addend;
				byteLength = setValue(memory, relocationAddress, newValue, is64bit);
				return new RelocationResult(Status.APPLIED, byteLength);
			case R_AARCH64_P32_COPY:
			case R_AARCH64_COPY:
				markAsUnsupportedCopy(program, relocationAddress, type, symbolName, symbolIndex,
					sym.getSize(), elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
			default:
				break;
		}

		// Check for unresolved symbolAddr and symbolValue required by remaining relocation types handled below
		if (handleUnresolvedSymbol(elfRelocationContext, relocation, relocationAddress)) {
			return RelocationResult.FAILURE;
		}

		switch (type) {
			// .xword: (S+A)
			case R_AARCH64_ABS64: {
				newValue = (symbolValue + addend);
				memory.setLong(relocationAddress, newValue);
				if (symbolIndex != 0 && addend != 0 && !sym.isSection()) {
					warnExternalOffsetRelocation(program, relocationAddress, symbolAddr, symbolName,
						addend, elfRelocationContext.getLog());
					applyComponentOffsetPointer(program, relocationAddress, addend);
				}
				byteLength = 8;
				break;
			}

			// .word: (S+A)
			case R_AARCH64_ABS32:
			case R_AARCH64_P32_ABS32: {
				newValue = (symbolValue + addend);
				memory.setInt(relocationAddress, (int) (newValue & 0xffffffff));
				break;
			}

			// .half: (S+A)

			case R_AARCH64_ABS16:
			case R_AARCH64_P32_ABS16: {
				newValue = (symbolValue + addend);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				byteLength = 2;
				break;
			}

			// .xword: (S+A-P)
			case R_AARCH64_PREL64: {
				newValue = (symbolValue + addend);
				newValue -= (offset); // PC relative
				memory.setLong(relocationAddress, newValue);
				byteLength = 8;
				break;
			}

			// .word: (S+A-P)
			case R_AARCH64_PREL32:
			case R_AARCH64_P32_PREL32: {
				newValue = (symbolValue + addend);
				newValue -= (offset); // PC relative
				memory.setInt(relocationAddress, (int) (newValue & 0xffffffff));
				break;
			}

			// .half: (S+A-P)
			case R_AARCH64_PREL16:
			case R_AARCH64_P32_PREL16: {
				newValue = (symbolValue + addend);
				newValue -= (offset); // PC relative
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				byteLength = 2;
				break;
			}

			// MOV[ZK]:   ((S+A) >>  0) & 0xffff
			case R_AARCH64_MOVW_UABS_G0_NC: {
				overflowCheck = false;
				// fall-through
			}
			case R_AARCH64_MOVW_UABS_G0: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				long imm = (symbolValue + addend) >> 0;

				oldValue &= ~(0xffff << 5);
				newValue = oldValue | ((imm & 0xffff) << 5);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);

				if (overflowCheck && imm > 0xffffL) {
					// relocation already applied; report overflow condition
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"Failed overflow check for immediate value", elfRelocationContext.getLog());
				}
				break;
			}

			// MOV[ZK]:   ((S+A) >>  16) & 0xffff
			case R_AARCH64_MOVW_UABS_G1_NC: {
				overflowCheck = false;
				// fall-through
			}
			case R_AARCH64_MOVW_UABS_G1: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				long imm = (symbolValue + addend) >> 16;

				oldValue &= ~(0xffff << 5);
				newValue = oldValue | ((imm & 0xffff) << 5);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);

				if (overflowCheck && imm > 0xffffL) {
					// relocation already applied; report overflow condition
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"Failed overflow check for immediate value", elfRelocationContext.getLog());
				}
				break;
			}

			// MOV[ZK]:   ((S+A) >>  32) & 0xffff
			case R_AARCH64_MOVW_UABS_G2_NC: {
				overflowCheck = false;
				// fall-through
			}
			case R_AARCH64_MOVW_UABS_G2: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				long imm = (symbolValue + addend) >> 32;

				oldValue &= ~(0xffff << 5);
				newValue = oldValue | ((imm & 0xffff) << 5);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);

				if (overflowCheck && imm > 0xffffL) {
					// relocation already applied; report overflow condition
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"Failed overflow check for immediate value", elfRelocationContext.getLog());
				}
				break;
			}

			// MOV[ZK]:   ((S+A) >>  48) & 0xffff
			case R_AARCH64_MOVW_UABS_G3: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				long imm = (symbolValue + addend) >> 48;

				oldValue &= ~(0xffff << 5);
				newValue = oldValue | ((imm & 0xffff) << 5);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// ADRH: ((PG(S+A)-PG(P)) >> 12) & 0x1fffff
			case R_AARCH64_ADR_PREL_PG_HI21:
			case R_AARCH64_P32_ADR_PREL_PG_HI21: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				newValue = ((PG(symbolValue + addend) - PG(offset)) >> 12) & 0x1fffff;

				newValue = (oldValue & 0x9f00001f) | ((newValue << 3) & 0xffffe0) |
					((newValue & 0x3) << 29);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// ADD: (S+A) & 0xfff
			case R_AARCH64_ADD_ABS_LO12_NC:
			case R_AARCH64_P32_ADD_ABS_LO12_NC: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				newValue = (int) (symbolValue + addend) & 0xfff;

				newValue = oldValue | (newValue << 10);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// LD/ST8: (S+A) & 0xfff
			case R_AARCH64_LDST8_ABS_LO12_NC:
			case R_AARCH64_P32_LDST8_ABS_LO12_NC: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				newValue = (int) (symbolValue + addend) & 0xfff;

				newValue = oldValue | (newValue << 10);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// B:  ((S+A-P) >> 2) & 0x3ffffff.
			// BL: ((S+A-P) >> 2) & 0x3ffffff
			case R_AARCH64_JUMP26:
			case R_AARCH64_P32_JUMP26:
			case R_AARCH64_CALL26:
			case R_AARCH64_P32_CALL26: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				newValue = (symbolValue + addend);

				newValue -= (offset); // PC relative

				newValue = oldValue | ((newValue >> 2) & 0x03ffffff);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// LD/ST16: (S+A) & 0xffe 
			case R_AARCH64_LDST16_ABS_LO12_NC:
			case R_AARCH64_P32_LDST16_ABS_LO12_NC: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				newValue = (int) ((symbolValue + addend) & 0xffe) >> 1;

				newValue = oldValue | (newValue << 10);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// LD/ST32: (S+A) & 0xffc
			case R_AARCH64_LDST32_ABS_LO12_NC:
			case R_AARCH64_P32_LDST32_ABS_LO12_NC: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				newValue = (int) ((symbolValue + addend) & 0xffc) >> 2;

				newValue = oldValue | (newValue << 10);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// LD/ST64: (S+A) & 0xff8
			case R_AARCH64_LDST64_ABS_LO12_NC:
			case R_AARCH64_P32_LDST64_ABS_LO12_NC: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				newValue = (int) ((symbolValue + addend) & 0xff8) >> 3;

				newValue = oldValue | (newValue << 10);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// LD/ST128: (S+A) & 0xff0
			case R_AARCH64_LDST128_ABS_LO12_NC: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				newValue = (int) ((symbolValue + addend) & 0xff0) >> 4;

				newValue = oldValue | (newValue << 10);

				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// ADRP: Page(G(GDAT(S)))-Page(P)
			// Page of GOT entry address for S minus page of relocation address
			// Set the immediate value of an ADRP to bits [32:12] of X
			case R_AARCH64_ADR_GOT_PAGE:
			case R_AARCH64_P32_ADR_GOT_PAGE: {
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				Address symbolGotAddress = elfRelocationContext.getGotEntryAddress(sym);
				if (symbolGotAddress == null) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"GOT allocation failure", elfRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}
				newValue = page(symbolGotAddress.getOffset()) - page(relocationAddress.getOffset());
				newValue = (newValue & 0x1fffff000L) >>> 12;
				int loBits = (int) newValue & 0x3;
				int hiBits = (int) newValue >>> 2;

				newValue = (oldValue & 0x9f00001fL) | (loBits << 29) | (hiBits << 5);
				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			// LD/ST: G(GDAT(S))
			case R_AARCH64_P32_LD32_GOT_LO12_NC: // Set the LD/ST immediate field to bits [11:2] of X
			case R_AARCH64_LD64_GOT_LO12_NC:     // Set the LD/ST immediate field to bits [11:3] of X
			{
				int oldValue = memory.getInt(relocationAddress, isBigEndianInstructions);
				Address symbolGotAddress = elfRelocationContext.getGotEntryAddress(sym);
				if (symbolGotAddress == null) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"GOT allocation failure", elfRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}
				int lo12bits = (int) (symbolGotAddress.getOffset() & 0xfff);
				if (type == AARCH64_ElfRelocationType.R_AARCH64_P32_LD32_GOT_LO12_NC) {
					lo12bits &= ~0x3;
				}
				else {
					lo12bits &= ~0x7;
				}

				// Bits [21:10] — imm12: 12-bit unsigned immediate offset
				newValue = (oldValue & 0xffc003ffL) | (lo12bits << 10);
				memory.setInt(relocationAddress, (int) newValue, isBigEndianInstructions);
				break;
			}

			case R_AARCH64_P32_GLOB_DAT:
				is64bit = false;
			case R_AARCH64_GLOB_DAT: {
				// Corresponds to resolved local/EXTERNAL symbols within GOT
				if (elfRelocationContext.extractAddend()) {
					addend = getValue(memory, relocationAddress, is64bit);
				}
				newValue = symbolValue + addend;
				byteLength = setValue(memory, relocationAddress, newValue, is64bit);
				break;
			}

			case R_AARCH64_P32_JUMP_SLOT:
				is64bit = false;
			case R_AARCH64_JUMP_SLOT: {
				// Corresponds to lazy dynamically linked external symbols within
				// GOT/PLT symbolValue corresponds to PLT entry for which we need to
				// create and external function location. Don't bother changing
				// GOT entry bytes if it refers to .plt block

				MemoryBlock block = memory.getBlock(symbolAddr);
				// TODO: jump slots are always in GOT - not sure why PLT check is done
				boolean isPltSym = block != null && block.getName().startsWith(".plt");
				boolean isExternalSym =
					block != null && MemoryBlock.EXTERNAL_BLOCK_NAME.equals(block.getName());
				if (!isPltSym) {
					byteLength = setValue(memory, relocationAddress, symbolValue, is64bit);
				}
				if ((isPltSym || isExternalSym) && !StringUtils.isBlank(symbolName)) {
					Function extFunction = elfRelocationContext.getLoadHelper()
							.createExternalFunctionLinkage(symbolName, symbolAddr, null);
					if (extFunction == null) {
						markAsError(program, relocationAddress, type, symbolName, symbolIndex,
							"Failed to create external function", elfRelocationContext.getLog());
						// relocation already applied above
					}
				}
				break;
			}

			default: {
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
			}
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}

	private long page(long offset) {
		return offset & ~0xfff;
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
	 * @throws MemoryAccessException if memory access failed
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
