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

import java.util.Iterator;
import java.util.Map;

import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.extend.MIPS_ElfExtension;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.util.exception.AssertException;

public class MIPS_ElfRelocationHandler extends ElfRelocationHandler {

//	private static final int TP_OFFSET = 0x7000;
//	private static final int DTP_OFFSET = 0x8000;

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_MIPS;
	}

	@Override
	public MIPS_ElfRelocationContext createRelocationContext(ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		return new MIPS_ElfRelocationContext(this, loadHelper, symbolMap);
	}

	@Override
	public RelocationResult relocate(ElfRelocationContext elfRelocationContext,
			ElfRelocation relocation, Address relocationAddress)
			throws MemoryAccessException {

		ElfHeader elf = elfRelocationContext.getElfHeader();

		if (elf.e_machine() != ElfConstants.EM_MIPS) {
			return RelocationResult.FAILURE;
		}

		MIPS_ElfRelocationContext mipsRelocationContext =
			(MIPS_ElfRelocationContext) elfRelocationContext;
		mipsRelocationContext.lastSymbolAddr = null;
		mipsRelocationContext.lastElfSymbol = null;

		int type = relocation.getType();
		int symbolIndex = relocation.getSymbolIndex();

		boolean saveValueForNextReloc =
			mipsRelocationContext.nextRelocationHasSameOffset(relocation);

		RelocationResult lastResult = RelocationResult.FAILURE;
		if (elf.is64Bit()) {

			MIPS_Elf64Relocation mips64Relocation = (MIPS_Elf64Relocation) relocation;

			// Each relocation can pack upto 3 relocations for 64-bit
			for (int n = 0; n < 3; n++) {

				if (n == 0) {
					symbolIndex = mips64Relocation.getSymbolIndex();
				}
				else if (n == 1) {
					symbolIndex = mips64Relocation.getSpecialSymbolIndex();
				}
				else {
					symbolIndex = 0;
				}

				int relocType = type & 0xff;
				type >>= 8;
				int nextRelocType =
					(n < 2) ? (type & 0xff) : MIPS_ElfRelocationConstants.R_MIPS_NONE;

				RelocationResult result = doRelocate(mipsRelocationContext, relocType, symbolIndex,
					mips64Relocation, relocationAddress,
					nextRelocType != MIPS_ElfRelocationConstants.R_MIPS_NONE ||
						saveValueForNextReloc);
				if (result.status() == Status.FAILURE || result.status() == Status.UNSUPPORTED) {
					return result;
				}
				lastResult = result;

				symbolIndex = 0; // set to STN_UNDEF(0) once symbol used by first relocation

				if (nextRelocType == MIPS_ElfRelocationConstants.R_MIPS_NONE) {
					break;
				}
			}
			return lastResult;
		}

		return doRelocate(mipsRelocationContext, type, symbolIndex, relocation, relocationAddress,
			saveValueForNextReloc);
	}

	/**
	 * Perform MIPS ELF relocation
	 * @param mipsRelocationContext MIPS ELF relocation context
	 * @param relocType relocation type (unpacked from relocation r_info)
	 * @param relocation relocation record to be processed (may be compound for 64-bit)
	 * @param relocationAddress address at which relocation is applied (i.e., relocation offset)
	 * @param saveValue true if result value should be stored in mipsRelocationContext.savedAddend
	 * and mipsRelocationContext.useSavedAddend set true.  If false, result value should be written
	 * to relocationAddress per relocation type.
	 * @return applied relocation result
	 * @throws MemoryAccessException memory access error occured
	 */
	private RelocationResult doRelocate(MIPS_ElfRelocationContext mipsRelocationContext,
			int relocType, int symbolIndex, ElfRelocation relocation, Address relocationAddress,
			boolean saveValue) throws MemoryAccessException, AddressOutOfBoundsException {

		if (relocType == MIPS_ElfRelocationConstants.R_MIPS_NONE) {
			return RelocationResult.SKIPPED;
		}

		Program program = mipsRelocationContext.getProgram();
		Memory memory = program.getMemory();
		MessageLog log = mipsRelocationContext.getLog();

		ElfHeader elf = mipsRelocationContext.getElfHeader();

		long offset = (int) relocationAddress.getOffset();

		// Although elfSymbol may be null we assume it will not be when it is required by a reloc
		ElfSymbol elfSymbol = mipsRelocationContext.getSymbol(symbolIndex);

		Address symbolAddr = mipsRelocationContext.getSymbolAddress(elfSymbol);
		long symbolValue = mipsRelocationContext.getSymbolValue(elfSymbol);
		String symbolName = mipsRelocationContext.getSymbolName(symbolIndex);

		if (symbolIndex != 0) {
			mipsRelocationContext.lastSymbolAddr = symbolAddr;
			mipsRelocationContext.lastElfSymbol = elfSymbol;
		}

		long addend = 0;
		if (mipsRelocationContext.useSavedAddend) {
			if (mipsRelocationContext.savedAddendHasError) {
				markAsError(program, relocationAddress, Integer.toString(relocType), symbolName,
					"Stacked relocation failure", log);
				mipsRelocationContext.useSavedAddend = saveValue;
				mipsRelocationContext.savedAddend = 0;
				return RelocationResult.FAILURE;
			}
			addend = mipsRelocationContext.savedAddend;
		}
		else if (relocation.hasAddend()) {
			addend = relocation.getAddend();
		}

		// Treat global GOT_PAGE relocations as GOT_DISP
		if (!elfSymbol.isLocal()) {
			if (relocType == MIPS_ElfRelocationConstants.R_MIPS_GOT_PAGE) {
				relocType = MIPS_ElfRelocationConstants.R_MIPS_GOT_DISP;
				addend = 0; // addend handled by GOT_OFST
			}
			else if (relocType == MIPS_ElfRelocationConstants.R_MICROMIPS_GOT_PAGE) {
				relocType = MIPS_ElfRelocationConstants.R_MICROMIPS_GOT_DISP;
				addend = 0; // addend handled by GOT_OFST
			}
		}

		mipsRelocationContext.savedAddendHasError = false;
		mipsRelocationContext.savedAddend = 0;

		boolean isGpDisp = false;
		if (MIPS_ElfExtension.MIPS_GP_DISP_SYMBOL_NAME.equals(symbolName)) {
			isGpDisp = true;
		}
		else if (MIPS_ElfExtension.MIPS_GP_GNU_LOCAL_SYMBOL_NAME.equals(symbolName)) {
			// TODO: GP based relocation not yet supported - need to evaluate an example
			markAsError(program, relocationAddress, Integer.toString(relocType), symbolName,
				MIPS_ElfExtension.MIPS_GP_GNU_LOCAL_SYMBOL_NAME + " relocation not yet supported",
				log);
			if (saveValue) {
				mipsRelocationContext.savedAddendHasError = true;
			}
			return RelocationResult.FAILURE;
		}

		long oldValue = Integer.toUnsignedLong(
			unshuffle(memory.getInt(relocationAddress), relocType, mipsRelocationContext));

		// Intermediate results are retained as long values so they may be used with 64-bit
		// compound relocation processing

		long value = 0; // computed value which will be used as savedAddend if needed
		long newValue = 0; // value blended with oldValue as appropriate for relocation
		boolean writeNewValue = false;

		Status status = Status.PARTIAL;
		int byteLength = 4; // most relocations affect 4-bytes (change if different)

		switch (relocType) {

			case MIPS_ElfRelocationConstants.R_MIPS_GOT_OFST:
			case MIPS_ElfRelocationConstants.R_MICROMIPS_GOT_OFST:
				if (mipsRelocationContext.extractAddend()) {
					addend = oldValue & 0xffff;
				}

				long pageOffset = (symbolValue + addend + 0x8000) & ~0xffff;
				value = symbolValue + addend - pageOffset;

				newValue = (oldValue & ~0xffff) | (value & 0xffff);
				writeNewValue = true;
				break;

			case MIPS_ElfRelocationConstants.R_MIPS_GOT_PAGE:
			case MIPS_ElfRelocationConstants.R_MICROMIPS_GOT_PAGE:

				if (mipsRelocationContext.extractAddend()) {
					addend = oldValue & 0xffff;
				}

				pageOffset = ((symbolValue + addend + 0x8000) & ~0xffff);

				// Get section GOT entry for local symbol
				Address gotAddr = mipsRelocationContext.getSectionGotAddress(pageOffset);
				if (gotAddr == null) {
					// failed to allocate section GOT entry for symbol
					markAsError(mipsRelocationContext.getProgram(), relocationAddress,
						Integer.toString(relocType), symbolName,
						"Relocation Failed, unable to allocate GOT entry for relocation symbol: " +
							symbolName,
						mipsRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}

				value = getGpOffset(mipsRelocationContext, gotAddr.getOffset());
				if (value == -1) {
					// Unhandled GOT/GP case
					markAsError(mipsRelocationContext.getProgram(), relocationAddress,
						Integer.toString(relocType), symbolName,
						"Failed to perform GP-based relocation", mipsRelocationContext.getLog());
					if (saveValue) {
						mipsRelocationContext.savedAddendHasError = true;
					}
					return RelocationResult.FAILURE;
				}

				newValue = (oldValue & ~0xffff) | (value & 0xffff);
				writeNewValue = true;
				break;

			case MIPS_ElfRelocationConstants.R_MIPS_GOT_DISP:
			case MIPS_ElfRelocationConstants.R_MICROMIPS_GOT_DISP:
			case MIPS_ElfRelocationConstants.R_MIPS_GOT_HI16:
			case MIPS_ElfRelocationConstants.R_MICROMIPS_GOT_HI16:

				// Get section GOT entry for local symbol
				gotAddr = mipsRelocationContext.getSectionGotAddress(symbolValue);
				if (gotAddr == null) {
					// failed to allocate section GOT entry for symbol
					markAsError(mipsRelocationContext.getProgram(), relocationAddress,
						Integer.toString(relocType), symbolName,
						"Relocation Failed, unable to allocate GOT entry for relocation symbol: " +
							symbolName,
						mipsRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}

				// use address offset within section GOT as symbol value
				value = getGpOffset(mipsRelocationContext, gotAddr.getOffset());
				if (value == -1) {
					// Unhandled GOT/GP case
					markAsError(mipsRelocationContext.getProgram(), relocationAddress,
						Integer.toString(relocType), symbolName,
						"Failed to perform GP-based relocation", mipsRelocationContext.getLog());
					if (saveValue) {
						mipsRelocationContext.savedAddendHasError = true;
					}
					return RelocationResult.FAILURE;
				}

				long appliedValue;
				if (relocType == MIPS_ElfRelocationConstants.R_MIPS_GOT_DISP) {
					appliedValue = value & 0xffff;
				}
				else {
					appliedValue = ((value + 0x8000) >> 16) & 0xffff;
				}

				newValue = (oldValue & ~0xffff) | appliedValue;
				writeNewValue = true;
				break;

			case MIPS_ElfRelocationConstants.R_MIPS_GOT16:
			case MIPS_ElfRelocationConstants.R_MIPS16_GOT16:
			case MIPS_ElfRelocationConstants.R_MICROMIPS_GOT16:

				if (elfSymbol.isLocal()) {
					// Defer processing of local GOT16 relocations until suitable LO16 relocation is processed
					MIPS_DeferredRelocation got16reloc = new MIPS_DeferredRelocation(relocType,
						elfSymbol, relocationAddress, oldValue, addend, isGpDisp);
					mipsRelocationContext.addGOT16Relocation(got16reloc);
					break; // report as 4-byte applied even though it is deferred (could still fail)
				}

				// fall-through

			case MIPS_ElfRelocationConstants.R_MIPS_CALL16:
			case MIPS_ElfRelocationConstants.R_MIPS16_CALL16:
			case MIPS_ElfRelocationConstants.R_MICROMIPS_CALL16:

				// Get section GOT entry for local symbol
				gotAddr = mipsRelocationContext.getSectionGotAddress(symbolValue + addend);
				if (gotAddr == null) {
					// failed to allocate section GOT entry for symbol
					markAsError(mipsRelocationContext.getProgram(), relocationAddress,
						Integer.toString(relocType), symbolName,
						"Relocation Failed, unable to allocate GOT entry for relocation symbol: " +
							symbolName,
						mipsRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}

				value = getGpOffset(mipsRelocationContext, gotAddr.getOffset());
				if (value == -1) {
					// Unhandled GOT/GP case
					markAsError(mipsRelocationContext.getProgram(), relocationAddress,
						Integer.toString(relocType), symbolName,
						"Failed to perform GP-based relocation", mipsRelocationContext.getLog());
					if (saveValue) {
						mipsRelocationContext.savedAddendHasError = true;
					}
					return RelocationResult.FAILURE;
				}

				newValue = (oldValue & ~0xffff) | (value & 0xffff);
				writeNewValue = true;
				break;

			case MIPS_ElfRelocationConstants.R_MIPS_CALL_HI16:
			case MIPS_ElfRelocationConstants.R_MICROMIPS_CALL_HI16:

				// Get section GOT entry for local symbol
				gotAddr = mipsRelocationContext.getSectionGotAddress(symbolValue + addend);
				if (gotAddr == null) {
					// failed to allocate section GOT entry for symbol
					markAsError(mipsRelocationContext.getProgram(), relocationAddress,
						Integer.toString(relocType), symbolName,
						"Relocation Failed, unable to allocate GOT entry for relocation symbol: " +
							symbolName,
						mipsRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}

				value = getGpOffset(mipsRelocationContext, gotAddr.getOffset());
				if (value == -1) {
					// Unhandled GOT/GP case
					markAsError(mipsRelocationContext.getProgram(), relocationAddress,
						Integer.toString(relocType), symbolName,
						"Failed to perform GP-based relocation", mipsRelocationContext.getLog());
					if (saveValue) {
						mipsRelocationContext.savedAddendHasError = true;
					}
					return RelocationResult.FAILURE;
				}

				newValue = (oldValue & ~0xffff) | (((value + 0x8000) >> 16) & 0xffff);
				writeNewValue = true;
				break;

			case MIPS_ElfRelocationConstants.R_MIPS_HI16:
			case MIPS_ElfRelocationConstants.R_MIPS16_HI16:
			case MIPS_ElfRelocationConstants.R_MICROMIPS_HI16:
				// Verify the we have GP
				if (mipsRelocationContext.getGPValue() == -1) {
					markAsError(mipsRelocationContext.getProgram(), relocationAddress,
						Integer.toString(relocType), elfSymbol.getNameAsString(),
						"Failed to perform GP-based relocation", mipsRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}

				// Defer processing of HI16 relocations until suitable LO16 relocation is processed
				MIPS_DeferredRelocation hi16reloc = new MIPS_DeferredRelocation(relocType,
					elfSymbol, relocationAddress, oldValue, (int) addend, isGpDisp);
				mipsRelocationContext.addHI16Relocation(hi16reloc);
				break; // report as 4-byte applied even though it is deferred

			case MIPS_ElfRelocationConstants.R_MIPS_LO16:
			case MIPS_ElfRelocationConstants.R_MIPS16_LO16:
			case MIPS_ElfRelocationConstants.R_MICROMIPS_LO16:
			case MIPS_ElfRelocationConstants.R_MICROMIPS_HI0_LO16:

				if (mipsRelocationContext.extractAddend()) {
					addend = (short) (oldValue & 0xffff);  // 16-bit sign extended
				}

				processHI16Relocations(mipsRelocationContext, relocType, elfSymbol, (int) addend);

				processGOT16Relocations(mipsRelocationContext, relocType, elfSymbol, (int) addend);

				if (isGpDisp) {
					value = mipsRelocationContext.getGPValue();
					if (value == -1) {
						markAsError(program, relocationAddress, Integer.toString(relocType),
							symbolName, "Failed to perform GP-based relocation",
							mipsRelocationContext.getLog());
						if (saveValue) {
							mipsRelocationContext.savedAddendHasError = true;
						}
						return RelocationResult.FAILURE;
					}
					if (relocType == MIPS_ElfRelocationConstants.R_MIPS16_LO16) {
						value -= (offset & ~0x3);
					}
					else {
						value -= offset - 4;
					}
				}
				else {
					value = (int) symbolValue;
				}
				value += addend;

				newValue = (oldValue & ~0xffff) | (value & 0xffff);
				writeNewValue = true;
				break;

			case MIPS_ElfRelocationConstants.R_MIPS_REL32:
				if (symbolIndex == 0) {
					symbolValue = mipsRelocationContext.getImageBaseWordAdjustmentOffset();
				}
				value = symbolValue;
				if (mipsRelocationContext.extractAddend()) {
					// extract addend based upon pointer size
					addend = elf.is64Bit() ? (int) memory.getLong(relocationAddress)
							: memory.getInt(relocationAddress);
				}

				newValue = value + addend;

				if (saveValue) {
					mipsRelocationContext.savedAddend = newValue;
				}
				else {
					memory.setInt(relocationAddress, (int) newValue);
					status = Status.APPLIED;

					// Handle possible offset-pointer use
					if (symbolIndex != 0 && addend != 0 && !elfSymbol.isSection()) {
						// create offset-pointer and resulting offset-reference
						warnExternalOffsetRelocation(program, relocationAddress,
							symbolAddr, symbolName, addend, mipsRelocationContext.getLog());
						applyComponentOffsetPointer(program, relocationAddress, addend);
					}
				}
				break;

			case MIPS_ElfRelocationConstants.R_MIPS_32: /* In Elf 64: alias R_MIPS_ADD */
				value = symbolValue;
				if (mipsRelocationContext.extractAddend()) {
					addend = memory.getInt(relocationAddress);
				}

				newValue = value + addend;

				if (saveValue) {
					mipsRelocationContext.savedAddend = newValue;
				}
				else {
					memory.setInt(relocationAddress, (int) newValue);
					status = Status.APPLIED;
				}
				break;

			case MIPS_ElfRelocationConstants.R_MIPS_26:
			case MIPS_ElfRelocationConstants.R_MIPS16_26:
			case MIPS_ElfRelocationConstants.R_MICROMIPS_26_S1:
				int shift = (relocType == MIPS_ElfRelocationConstants.R_MICROMIPS_26_S1) ? 1 : 2;
				if (mipsRelocationContext.extractAddend()) {
					addend = (oldValue & MIPS_ElfRelocationConstants.MIPS_LOW26) << shift;
				}
				if (!elfSymbol.isLocal() && !elfSymbol.isSection()) {
					addend = signExtend((int) addend, 26 + shift);
				}
				// TODO: cross-mode jump detection/handling is unsupported
				value = (addend + symbolValue) >> shift;
				newValue = (oldValue & ~MIPS_ElfRelocationConstants.MIPS_LOW26) |
					(value & MIPS_ElfRelocationConstants.MIPS_LOW26);
				writeNewValue = true;
				break;

			case MIPS_ElfRelocationConstants.R_MIPS_PC21_S2:
				if (mipsRelocationContext.extractAddend()) {
					addend = (oldValue & MIPS_ElfRelocationConstants.MIPS_LOW21) << 2;
				}
				if (!elfSymbol.isLocal() && !elfSymbol.isSection()) {
					addend = signExtend((int) addend, 21 + 2);
				}
				value = (addend + symbolValue - offset) >> 2;
				newValue = (oldValue & ~MIPS_ElfRelocationConstants.MIPS_LOW21) |
					(value & MIPS_ElfRelocationConstants.MIPS_LOW21);
				writeNewValue = true;
				break;

			case MIPS_ElfRelocationConstants.R_MIPS_PC26_S2:
				if (mipsRelocationContext.extractAddend()) {
					addend = (oldValue & MIPS_ElfRelocationConstants.MIPS_LOW26) << 2;
				}
				if (!elfSymbol.isLocal() && !elfSymbol.isSection()) {
					addend = signExtend((int) addend, 26 + 2);
				}
				value = (addend + symbolValue - offset) >> 2;
				newValue = (oldValue & ~MIPS_ElfRelocationConstants.MIPS_LOW26) |
					(value & MIPS_ElfRelocationConstants.MIPS_LOW26);
				writeNewValue = true;
				break;

			case MIPS_ElfRelocationConstants.R_MIPS_PC16:
				if (mipsRelocationContext.extractAddend()) {
					addend = (oldValue & 0xffff) << 2;
				}
				value = symbolValue - offset + signExtend((int) addend, 18);
				newValue = (oldValue & ~0xffff) | ((value >> 2) & 0xffff);
				writeNewValue = true;
				break;

			case MIPS_ElfRelocationConstants.R_MIPS_64:
				if (mipsRelocationContext.extractAddend()) {
					addend = memory.getLong(relocationAddress);
				}
				newValue = symbolValue + addend;
				if (saveValue) {
					mipsRelocationContext.savedAddend = newValue;
				}
				else {
					memory.setLong(relocationAddress, newValue);
					byteLength = 8;
					status = Status.APPLIED;

					// Handle possible offset-pointer use
					boolean isSectionBased = elfSymbol.isSection();
					Address addr = symbolAddr;
					if (symbolIndex == 0 && mipsRelocationContext.lastSymbolAddr != null) {
						// handle compound mips64 relocation
						addr = mipsRelocationContext.lastSymbolAddr;
						symbolName = mipsRelocationContext.lastElfSymbol.getNameAsString();
						isSectionBased = mipsRelocationContext.lastElfSymbol.isSection();
					}
					if (addr != null && !isSectionBased) {
						if (symbolIndex == 0) {
							// compute addend used with compound relocation and lastSymbolAddr 
							addend -= addr.getOffset();
						}
						if (addend != 0) {
							// create offset-pointer and resulting offset-reference
							warnExternalOffsetRelocation(program, relocationAddress,
								addr, symbolName, addend, mipsRelocationContext.getLog());
							if (elf.is64Bit()) {
								applyComponentOffsetPointer(program, relocationAddress, addend);
							}
						}
					}
				}
				break;

			case MIPS_ElfRelocationConstants.R_MIPS_HIGHER:
			case MIPS_ElfRelocationConstants.R_MICROMIPS_HIGHER:
				if (mipsRelocationContext.extractAddend()) {
					addend = oldValue;
				}
				addend &= 0xffff;
				value = symbolValue + 0x080008000L + addend;
				value = (value >> 32) & 0xffff;
				newValue = (oldValue & ~0xffff) | value;
				writeNewValue = true;
				break;

			case MIPS_ElfRelocationConstants.R_MIPS_HIGHEST:
			case MIPS_ElfRelocationConstants.R_MICROMIPS_HIGHEST:
				if (mipsRelocationContext.extractAddend()) {
					addend = oldValue;
				}
				addend &= 0xffff;
				value = symbolValue + 0x080008000L + addend;
				value = (value >> 48) & 0xffff;
				newValue = (oldValue & ~0xffff) | value;
				writeNewValue = true;
				break;

			case MIPS_ElfRelocationConstants.R_MICROMIPS_PC7_S1:
				if (mipsRelocationContext.extractAddend()) {
					addend = (oldValue & 0x7f0000) >> 15;
				}
				value = (((symbolValue + addend) - offset) >> 1) & 0x7f;
				newValue = (oldValue & ~0x7f0000) | (value << 16);
				writeNewValue = true;
				break;

			case MIPS_ElfRelocationConstants.R_MICROMIPS_PC10_S1:
				if (mipsRelocationContext.extractAddend()) {
					addend = (oldValue & 0x3ff0000) >> 15;
				}
				value = (((symbolValue + addend) - offset) >> 1) & 0x3ff;
				newValue = (oldValue & ~0x3ff0000) | (value << 16);
				writeNewValue = true;
				break;

			case MIPS_ElfRelocationConstants.R_MICROMIPS_PC16_S1:
				if (mipsRelocationContext.extractAddend()) {
					addend = (oldValue & 0xffff) << 1;
				}
				value = (((symbolValue + addend) - offset) >> 1) & 0xffff;
				newValue = (oldValue & ~0xffff) | value;
				writeNewValue = true;
				break;

			case MIPS_ElfRelocationConstants.R_MIPS_GPREL16:
			case MIPS_ElfRelocationConstants.R_MIPS_GPREL32:
			case MIPS_ElfRelocationConstants.R_MIPS16_GPREL:
			case MIPS_ElfRelocationConstants.R_MICROMIPS_GPREL16:
			case MIPS_ElfRelocationConstants.R_MICROMIPS_GPREL7_S2:
			case MIPS_ElfRelocationConstants.R_MIPS_LITERAL:
			case MIPS_ElfRelocationConstants.R_MICROMIPS_LITERAL:
				if (mipsRelocationContext.extractAddend()) {
					if (relocType == MIPS_ElfRelocationConstants.R_MIPS_GPREL32) {
						addend = oldValue;
					}
					else {
						addend = oldValue & 0xffff;
						if (relocType == MIPS_ElfRelocationConstants.R_MICROMIPS_GPREL7_S2) {
							addend <<= 2;
						}
						addend = signExtend((int) addend, 16);
					}
				}

				long gp0 = 0;
				if (elfSymbol.isLocal() &&
					(relocType == MIPS_ElfRelocationConstants.R_MIPS_GPREL16 ||
						relocType == MIPS_ElfRelocationConstants.R_MIPS_GPREL32)) {
					gp0 = mipsRelocationContext.getGP0Value();
					if (gp0 == -1) {
						markAsError(mipsRelocationContext.getProgram(), relocationAddress,
							Integer.toString(relocType), symbolName,
							"Failed to perform local GP0-based relocation (requires .reginfo data)",
							mipsRelocationContext.getLog());
						if (saveValue) {
							mipsRelocationContext.savedAddendHasError = true;
						}
						return RelocationResult.FAILURE;
					}
					if (gp0 == 0) {
						gp0 = mipsRelocationContext.getImageBaseWordAdjustmentOffset();
					}
				}

				long gp = mipsRelocationContext.getGPValue();
				if (gp == -1) {
					markAsError(mipsRelocationContext.getProgram(), relocationAddress,
						Integer.toString(relocType), symbolName,
						"Failed to perform GP-based relocation", mipsRelocationContext.getLog());
					if (saveValue) {
						mipsRelocationContext.savedAddendHasError = true;
					}
					return RelocationResult.FAILURE;
				}

				value = (symbolValue + addend - gp + gp0);

				long mask =
					relocType == MIPS_ElfRelocationConstants.R_MIPS_GPREL32 ? 0xffffffffL : 0xffff;
				newValue = (oldValue & ~mask) | (value & mask);
				writeNewValue = true;
				break;

			case MIPS_ElfRelocationConstants.R_MIPS_SUB:
			case MIPS_ElfRelocationConstants.R_MICROMIPS_SUB:
				if (mipsRelocationContext.extractAddend()) {
					addend = oldValue;
				}
				newValue = symbolValue - addend;

				if (saveValue) {
					mipsRelocationContext.savedAddend = newValue;
				}
				else {
					memory.setLong(relocationAddress, newValue);
					byteLength = 8;
					status = Status.APPLIED;
				}
				break;

			case MIPS_ElfRelocationConstants.R_MIPS_COPY:
				// TODO: Requires symbol lookup into dynamic library - not sure what we can do here
				markAsWarning(program, relocationAddress, "R_MIPS_COPY", symbolName, symbolIndex,
					"Runtime copy not supported", log);
				if (saveValue) {
					mipsRelocationContext.savedAddendHasError = true;
				}
				return RelocationResult.UNSUPPORTED;

			case MIPS_ElfRelocationConstants.R_MIPS_JUMP_SLOT:
				if (saveValue) {
					mipsRelocationContext.savedAddend = symbolValue;
				}
				else if (mipsRelocationContext.getElfHeader().is64Bit()) {
					memory.setLong(relocationAddress, symbolValue);
					byteLength = 8;
				}
				else {
					memory.setInt(relocationAddress, (int) symbolValue);
					byteLength = 8;
				}
				status = Status.APPLIED;
				break;

			case MIPS_ElfRelocationConstants.R_MIPS_JALR:
			case MIPS_ElfRelocationConstants.R_MICROMIPS_JALR:

				boolean success = false;
				Address symAddr = mipsRelocationContext.getSymbolAddress(elfSymbol);
				if (symAddr != null) {
					MemoryBlock block = memory.getBlock(symAddr);
					if (block != null) {
						if (MemoryBlock.EXTERNAL_BLOCK_NAME.equals(block.getName())) {

							success = mipsRelocationContext.getLoadHelper()
									.createExternalFunctionLinkage(symbolName, symAddr,
										null) != null;

							if (success) {
								// Inject appropriate JAL instruction
								if (relocType == MIPS_ElfRelocationConstants.R_MICROMIPS_JALR) {
									int offsetBits = (int) (symAddr.getOffset() >> 1) & 0x3ffffff;
									// TODO: upper bits should really come from delay slot
									int microJalrBits = 0xf4000000 | offsetBits;
									memory.setShort(relocationAddress,
										(short) (microJalrBits >>> 16));
									memory.setShort(relocationAddress.add(2),
										(short) microJalrBits);
								}
								else {
									int offsetBits = (int) (symAddr.getOffset() >> 2) & 0x3ffffff;
									// TODO: upper bits should really come from delay slot
									int jalrBits = 0x0c000000 | offsetBits;
									memory.setInt(relocationAddress, jalrBits);
								}
								status = Status.APPLIED;
							}
						}
						else {
							// assume OK for internal function linkage
							return RelocationResult.SKIPPED;
						}
					}
				}
				if (!success) {
					markAsError(program, relocationAddress,
						relocType == MIPS_ElfRelocationConstants.R_MIPS_JALR ? "R_MIPS_JALR"
								: "R_MICROMIPS_JALR",
						symbolName, "Failed to establish external linkage", log);
					return RelocationResult.FAILURE;
				}
				break;

			default:
				markAsUnhandled(program, relocationAddress, relocType, symbolIndex,
					symbolName, log);
				if (saveValue) {
					mipsRelocationContext.savedAddendHasError = true;
				}
				return RelocationResult.UNSUPPORTED;
		}

		if (writeNewValue) {
			if (saveValue) {
				// Save "value" as addend for next relocation
				mipsRelocationContext.savedAddend = value;
			}
			else {
				// Write 32-bit memory location at relocationAddress using "newValue".
				// Each relocation which sets writeNewValue must establish a 32-bit newValue
				// to be written to relocationAddress.
				memory.setInt(relocationAddress,
					shuffle((int) newValue, relocType, mipsRelocationContext));
				status = Status.APPLIED;
			}
		}

		mipsRelocationContext.useSavedAddend = saveValue;
		return new RelocationResult(status, byteLength);
	}

	private boolean isMIPS16Reloc(int type) {
		return type >= MIPS_ElfRelocationConstants.R_MIPS16_LO &&
			type <= MIPS_ElfRelocationConstants.R_MIPS16_HI;
	}

	private boolean isMicroMIPSReloc(int type) {
		return type >= MIPS_ElfRelocationConstants.R_MICROMIPS_LO &&
			type <= MIPS_ElfRelocationConstants.R_MICROMIPS_HI;
	}

	private boolean shuffleRequired(int type) {
		return isMIPS16Reloc(type) ||
			(isMicroMIPSReloc(type) && type != MIPS_ElfRelocationConstants.R_MICROMIPS_PC7_S1 &&
				type != MIPS_ElfRelocationConstants.R_MICROMIPS_PC10_S1);
	}

	private boolean isMIPS16_26_JAL_Reloc(int type, ElfRelocationContext elfRelocationContext) {
		return (type == MIPS_ElfRelocationConstants.R_MIPS16_26 &&
			elfRelocationContext.getElfHeader().isRelocatable());
	}

	private int unshuffle(int value, int type, ElfRelocationContext elfRelocationContext) {
		if (!shuffleRequired(type)) {
			return value;
		}

		int first;
		int second;
		if (elfRelocationContext.isBigEndian()) {
			first = value >>> 16;
			second = value & 0xffff;
		}
		else {
			first = value & 0xffff;
			second = value >>> 16;
		}

		if (isMIPS16_26_JAL_Reloc(type, elfRelocationContext)) {
			value = (((first & 0xf800) << 16) | ((second & 0xffe0) << 11) | ((first & 0x1f) << 11) |
				(first & 0x7e0) | (second & 0x1f));
		}
		else if (isMicroMIPSReloc(type) || type == MIPS_ElfRelocationConstants.R_MIPS16_26) {
			value = first << 16 | second;
		}
		else {
			value = (((first & 0xfc00) << 16) | ((first & 0x3e0) << 11) | ((first & 0x1f) << 21) |
				second);
		}
		return value;
	}

	private int shuffle(int value, int type, ElfRelocationContext elfRelocationContext) {
		if (!shuffleRequired(type)) {
			return value;
		}

		short first;
		short second;
		if (isMIPS16_26_JAL_Reloc(type, elfRelocationContext)) {
			first = (short) (((value >> 16) & 0xf800) | ((value >> 11) & 0x1f) | (value & 0x7e0));
			second = (short) (((value >> 11) & 0xffe0) | (value & 0x1f));
		}
		else if (isMicroMIPSReloc(type) || type == MIPS_ElfRelocationConstants.R_MIPS16_26) {
			first = (short) (value >> 16);
			second = (short) value;
		}
		else {
			first = (short) (((value >> 16) & 0xfc00) | ((value >> 11) & 0x3e0) |
				((value >> 21) & 0x1f));
			second = (short) value;
		}

		if (elfRelocationContext.isBigEndian()) {
			value = (first << 16) | (second & 0xffff);
		}
		else {
			value = (second << 16) | (first & 0xffff);
		}

		return value;
	}

	private boolean matchingHiLo16Types(int hi16Type, int lo16Type) {
		switch (hi16Type) {
			case MIPS_ElfRelocationConstants.R_MIPS_HI16:
			case MIPS_ElfRelocationConstants.R_MIPS_GOT16:
				return lo16Type == MIPS_ElfRelocationConstants.R_MIPS_LO16;
			case MIPS_ElfRelocationConstants.R_MIPS16_HI16:
			case MIPS_ElfRelocationConstants.R_MIPS16_GOT16:
				return lo16Type == MIPS_ElfRelocationConstants.R_MIPS16_LO16;
			case MIPS_ElfRelocationConstants.R_MICROMIPS_HI16:
			case MIPS_ElfRelocationConstants.R_MICROMIPS_GOT16:
				return lo16Type == MIPS_ElfRelocationConstants.R_MICROMIPS_LO16;
		}
		return false;
	}

	private int signExtend(int val, int bits) {
		int shift = 32 - bits;
		return (val << shift) >> shift;
	}

	/**
	 * Processes all pending HI16 relocations which match with the specified LO16 relocation
	 * @param mipsRelocationContext
	 * @param lo16RelocType
	 * @param lo16ElfSymbol
	 * @param lo16Addend
	 */
	private void processHI16Relocations(MIPS_ElfRelocationContext mipsRelocationContext,
			int lo16RelocType, ElfSymbol lo16ElfSymbol, int lo16Addend) {

		Iterator<MIPS_DeferredRelocation> iterateHi16 = mipsRelocationContext.iterateHi16();
		while (iterateHi16.hasNext()) {
			MIPS_DeferredRelocation hi16reloc = iterateHi16.next();
			if (matchingHiLo16Types(hi16reloc.relocType, lo16RelocType) &&
				hi16reloc.elfSymbol == lo16ElfSymbol) {
				processHI16Relocation(mipsRelocationContext, hi16reloc, lo16Addend);
				iterateHi16.remove(); // remove queued HI16 relocation if processed
			}
		}
	}

	/**
	 * Complete HI16 relocation (R_MIPS_HI16, R_MIPS16_HI16, R_MICROMIPS_HI16) using
	 * specified LO16 relocation data
	 * @param mipsRelocationContext
	 * @param hi16reloc
	 * @param lo16Addend
	 * @return true if successful or false if unsupported
	 */
	private void processHI16Relocation(MIPS_ElfRelocationContext mipsRelocationContext,
			MIPS_DeferredRelocation hi16reloc, long lo16Addend) {

		long newValue;
		if (hi16reloc.isGpDisp) {

			newValue = (int) mipsRelocationContext.getGPValue();
			if (newValue == -1) {
				markAsError(mipsRelocationContext.getProgram(), hi16reloc.relocAddr,
					Integer.toString(hi16reloc.relocType), hi16reloc.elfSymbol.getNameAsString(),
					"Failed to perform GP-based relocation", mipsRelocationContext.getLog());
				return;
			}
			if (hi16reloc.relocType == MIPS_ElfRelocationConstants.R_MIPS16_HI16) {
				newValue -= (hi16reloc.relocAddr.getOffset() + 4) & ~0x3;
			}
			else {
				newValue -= hi16reloc.relocAddr.getOffset();
			}
		}
		else {
			newValue = (int) mipsRelocationContext.getSymbolValue(hi16reloc.elfSymbol);
		}
// FIXME: should always use hi16reloc.addend - figure out at time of deferral
		long addend;
		if (mipsRelocationContext.extractAddend()) {
			addend = ((hi16reloc.oldValueL & 0xffff) << 16) + lo16Addend;
		}
		else {
			addend = hi16reloc.addendL;
		}

		newValue = (newValue + addend + 0x8000) >> 16;
		newValue = (hi16reloc.oldValueL & ~0xffff) | (newValue & 0xffff);
		Memory memory = mipsRelocationContext.getProgram().getMemory();
		try {
			memory.setInt(hi16reloc.relocAddr,
				shuffle((int) newValue, hi16reloc.relocType, mipsRelocationContext));
		}
		catch (MemoryAccessException e) {
			// Unexpected since we did a previous getInt without failure
			throw new AssertException(e);
		}
	}

	/**
	 * Processes all pending GOT16 relocations which match with the specified LO16 relocation
	 * @param mipsRelocationContext
	 * @param lo16RelocType
	 * @param lo16SymIndex
	 * @param lo16Addend
	 */
	private void processGOT16Relocations(MIPS_ElfRelocationContext mipsRelocationContext,
			int lo16RelocType, ElfSymbol lo16ElfSymbol, int lo16Addend) {

		Iterator<MIPS_DeferredRelocation> iterateGot16 = mipsRelocationContext.iterateGot16();
		while (iterateGot16.hasNext()) {
			MIPS_DeferredRelocation hi16reloc = iterateGot16.next();
			if (matchingHiLo16Types(hi16reloc.relocType, lo16RelocType) &&
				hi16reloc.elfSymbol == lo16ElfSymbol) {
				processGOT16Relocation(mipsRelocationContext, hi16reloc, lo16Addend);
				iterateGot16.remove(); // remove queued GOT16 relocation if processed
			}
		}
	}

	/**
	 * Complete Local GOT16 relocation (R_MIPS_GOT16, R_MIPS16_GOT16, R_MICROMIPS_GOT16) using
	 * specified LO16 relocation data.  Section GOT entry will be utilized.
	 * @param mipsRelocationContext
	 * @param got16reloc
	 * @param lo16Addend
	 * @return true if successful or false if unsupported
	 */
	private void processGOT16Relocation(MIPS_ElfRelocationContext mipsRelocationContext,
			MIPS_DeferredRelocation got16reloc, long lo16Addend) {

		long addend;
		if (mipsRelocationContext.extractAddend()) {
			addend = ((got16reloc.oldValueL & 0xffff) << 16) + lo16Addend;
		}
		else {
			addend = got16reloc.addendL;
		}

		long symbolValue = (int) mipsRelocationContext.getSymbolValue(got16reloc.elfSymbol);
		String symbolName = got16reloc.elfSymbol.getNameAsString();

		long value = (symbolValue + addend + 0x8000) & ~0xffff; // generate page offset

		// Get section GOT entry for local symbol
		Address gotAddr = mipsRelocationContext.getSectionGotAddress(value);
		if (gotAddr == null) {
			// failed to allocate section GOT entry for symbol
			markAsError(mipsRelocationContext.getProgram(), got16reloc.relocAddr,
				Integer.toString(got16reloc.relocType), symbolName,
				"Relocation Failed, unable to allocate GOT entry for relocation symbol",
				mipsRelocationContext.getLog());
			return;
		}

		// use address offset within section GOT as value
		value = getGpOffset(mipsRelocationContext, gotAddr.getOffset());
		if (value == -1) {
			// Unhandled GOT/GP case
			markAsError(mipsRelocationContext.getProgram(), got16reloc.relocAddr,
				Integer.toString(got16reloc.relocType), symbolName,
				"Failed to perform GP-based relocation", mipsRelocationContext.getLog());
			return;
		}

		long newValue = (got16reloc.oldValueL & ~0xffff) | ((int) value & 0xffff);

		Memory memory = mipsRelocationContext.getProgram().getMemory();
		try {
			memory.setInt(got16reloc.relocAddr,
				shuffle((int) newValue, got16reloc.relocType, mipsRelocationContext));
		}
		catch (MemoryAccessException e) {
			// Unexpected since we did a previous getInt without failure
			throw new AssertException(e);
		}
	}

	private long getGpOffset(MIPS_ElfRelocationContext mipsRelocationContext, long value) {
		// TODO: this is a simplified use of GP and could be incorrect when multiple GPs exist
		long gp = mipsRelocationContext.getGPValue();
		if (gp == -1) {
			return -1;
		}

		return value - gp;
	}

	/**
	 * <code>MIPS_DeferredRelocation</code> is used to capture a relocation whose processing
	 * must be deferred.
	 */
	static class MIPS_DeferredRelocation {

		final int relocType;
		final ElfSymbol elfSymbol;
		final Address relocAddr;
		final long oldValueL;
		final long addendL;
		final boolean isGpDisp;

		MIPS_DeferredRelocation(int relocType, ElfSymbol elfSymbol, Address relocAddr,
				long oldValue, long addend, boolean isGpDisp) {
			this.relocType = relocType;
			this.elfSymbol = elfSymbol;
			this.relocAddr = relocAddr;
			this.oldValueL = oldValue;
			this.addendL = addend;
			this.isGpDisp = isGpDisp;
		}

		void markUnprocessed(MIPS_ElfRelocationContext mipsRelocationContext,
				String missingDependencyName) {
			markAsError(mipsRelocationContext.getProgram(), relocAddr, Integer.toString(relocType),
				elfSymbol.getNameAsString(), "Relocation missing required " + missingDependencyName,
				mipsRelocationContext.getLog());
		}
	}
}
