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
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;

public class AVR8_ElfRelocationHandler
		extends AbstractElfRelocationHandler<AVR8_ElfRelocationType, ElfRelocationContext<?>> {

	/**
	 * Constructor
	 */
	public AVR8_ElfRelocationHandler() {
		super(AVR8_ElfRelocationType.class);
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_AVR;
	}

	@Override
	protected RelocationResult relocate(ElfRelocationContext<?> elfRelocationContext,
			ElfRelocation relocation, AVR8_ElfRelocationType type, Address relocationAddress,
			ElfSymbol elfSymbol, Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		// WARNING: symbolValue is not in bytes.
		// It is an addressable word offset within the symbols address space

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		long addend = relocation.getAddend(); // will be 0 for REL case

		// WARNING: offset is in bytes be careful, word address potentially with byte indexes
		long offset = relocationAddress.getOffset();

		int symbolIndex = relocation.getSymbolIndex();
		int oldValue = memory.getShort(relocationAddress);

		int newValue = 0;
		int byteLength = 2; // most relocations affect 2-bytes (change if different)

		switch (type) {
			case R_AVR_NONE:
				return RelocationResult.SKIPPED;

			case R_AVR_32:
				newValue = (((int) symbolValue + (int) addend) & 0xffffffff);
				memory.setInt(relocationAddress, newValue);
				break;

			case R_AVR_7_PCREL:
				newValue = (int) ((symbolValue * 2 + (int) addend - offset));
				newValue -= 2; // branch PC is offset+2

				if ((newValue & 1) == 1) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"Relocation out of range", elfRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}
				if (newValue > ((1 << 7) - 1) || (newValue < -(1 << 7))) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"Relocation overflow", elfRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}
				newValue = (oldValue & 0xfc07) | (((newValue >> 1) << 3) & 0x3f8);
				memory.setShort(relocationAddress, (short) newValue);
				break;

			case R_AVR_13_PCREL:
				newValue = (int) ((symbolValue * 2 + (int) addend - offset));
				newValue -= 2; // branch PC is offset+2

				if ((newValue & 1) == 1) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"Relocation out of range", elfRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}
				newValue >>= 1;

				if (newValue < -2048 || newValue > 2047) {
					markAsWarning(program, relocationAddress, type, symbolName, symbolIndex,
						"Possible relocation error", elfRelocationContext.getLog());
				}

				newValue = (oldValue & 0xf000) | (newValue & 0xfff);
				memory.setShort(relocationAddress, (short) newValue);
				break;

			case R_AVR_16:
				newValue = ((int) symbolValue + (int) addend);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case R_AVR_16_PM:
				newValue = (((int) symbolValue * 2 + (int) addend));
				newValue >>= 1;
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case R_AVR_LO8_LDI:
				newValue = (((int) symbolValue + (int) addend));
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case R_AVR_HI8_LDI:
				newValue = (((int) symbolValue + (int) addend));
				newValue = (newValue >> 8) & 0xff;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case R_AVR_HH8_LDI:
				newValue = (((int) symbolValue + (int) addend));
				newValue = (newValue >> 16) & 0xff;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case R_AVR_LO8_LDI_NEG:
				newValue = (((int) symbolValue + (int) addend));
				newValue = -newValue;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case R_AVR_HI8_LDI_NEG:
				newValue = (((int) symbolValue + (int) addend));
				newValue = -newValue;
				newValue = (newValue >> 8) & 0xff;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case R_AVR_HH8_LDI_NEG:
				newValue = (((int) symbolValue + (int) addend));
				newValue = -newValue;
				newValue = (newValue >> 16) & 0xff;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case R_AVR_LO8_LDI_PM:
				newValue = (((int) symbolValue * 2 + (int) addend));
				if ((newValue & 1) == 1) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"Relocation out of range", elfRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}
				newValue >>= 1;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case R_AVR_HI8_LDI_PM:
				newValue = (((int) symbolValue * 2 + (int) addend));
				if ((newValue & 1) == 1) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"Relocation out of range", elfRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}
				newValue >>= 1;
				newValue = (newValue >> 8) & 0xff;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case R_AVR_HH8_LDI_PM:
				newValue = (((int) symbolValue * 2 + (int) addend));
				if ((newValue & 1) == 1) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"Relocation out of range", elfRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}
				newValue >>= 1;
				newValue = (newValue >> 16) & 0xff;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case R_AVR_LO8_LDI_PM_NEG:
				newValue = (((int) symbolValue * 2 + (int) addend));
				newValue = -newValue;
				if ((newValue & 1) == 1) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"Relocation out of range", elfRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}
				newValue >>= 1;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case R_AVR_HI8_LDI_PM_NEG:
				newValue = (((int) symbolValue * 2 + (int) addend));
				newValue = -newValue;
				if ((newValue & 1) == 1) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"Relocation out of range", elfRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}
				newValue >>= 1;
				newValue = (newValue >> 8) & 0xff;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case R_AVR_HH8_LDI_PM_NEG:
				newValue = (((int) symbolValue * 2 + (int) addend));
				newValue = -newValue;
				if ((newValue & 1) == 1) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"Relocation out of range", elfRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}
				newValue >>= 1;
				newValue = (newValue >> 16) & 0xff;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case R_AVR_CALL:
				newValue = (int) symbolValue * 2 + (int) addend;

				if ((newValue & 1) == 1) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"Relocation out of range", elfRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}
				newValue >>= 1;

				int hiValue =
					oldValue | ((newValue & 0x10000) | ((newValue << 3) & 0x1f00000)) >> 16;
				memory.setShort(relocationAddress, (short) (hiValue & 0xffff));
				memory.setShort(relocationAddress.add(2), (short) (newValue & 0xffff));
				byteLength = 4;
				break;

			case R_AVR_LDI: /* data/eeprom */
				newValue = (((int) symbolValue + (int) addend));

				if ((newValue & 0xffff) > 255) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"Relocation out of range", elfRelocationContext.getLog());
					// continue to apply
				}

				newValue = (newValue >> 8) & 0xff;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case R_AVR_6: /* data/eeprom **/
				newValue = (((int) symbolValue + (int) addend));

				if (((newValue & 0xffff) > 63) || (newValue < 0)) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"Relocation out of range", elfRelocationContext.getLog());
					// continue to apply
				}

				newValue = (oldValue & 0xd3f8) | (newValue & 7) | ((newValue & (3 << 3)) << 7) |
					((newValue & (1 << 5)) << 8);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case R_AVR_6_ADIW:
				newValue = (((int) symbolValue + (int) addend));

				if (((newValue & 0xffff) > 63) || (newValue < 0)) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"Relocation out of range", elfRelocationContext.getLog());
					// continue to apply
				}

				newValue = (oldValue & 0xff30) | (newValue & 0xF) | ((newValue & 0x30) << 2);

				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case R_AVR_DIFF8:
			case R_AVR_DIFF16:
			case R_AVR_DIFF32:
				// nothing to do
				break;

			case R_AVR_LDS_STS_16:
				newValue = (((int) symbolValue + (int) addend));

				if (((newValue & 0xffff) < 0x40) || (newValue & 0xFFFF) > 0xbf) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"Relocation out of range", elfRelocationContext.getLog());
					// continue to apply
				}

				newValue = newValue & 0x7f;
				newValue = (oldValue & 0x0f) | ((newValue & 0x30) << 5) | ((newValue & 0x40) << 2);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case R_AVR_PORT6:
				newValue = (((int) symbolValue + (int) addend));

				if ((newValue & 0xffff) > 0x3f) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"Relocation out of range", elfRelocationContext.getLog());
					// continue to apply
				}

				newValue = (oldValue & 0xf9f0) | ((newValue & 0x30) << 5) | (newValue & 0x0f);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case R_AVR_PORT5:
				newValue = (((int) symbolValue + (int) addend));

				if ((newValue & 0xffff) > 0x1f) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"Relocation out of range", elfRelocationContext.getLog());
					// continue to apply
				}

				newValue = (oldValue & 0xff07) | ((newValue & 0x1f) << 3);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case R_AVR_MS8_LDI:
			case R_AVR_MS8_LDI_NEG:
			case R_AVR_LO8_LDI_GS:
			case R_AVR_HI8_LDI_GS:
			case R_AVR_8:
			case R_AVR_8_LO8:
			case R_AVR_8_HI8:
			case R_AVR_8_HLO8:
			default:
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}

}
