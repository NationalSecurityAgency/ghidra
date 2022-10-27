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
import ghidra.util.exception.NotFoundException;

public class AVR8_ElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_AVR;
	}

	@Override
	public void relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation,
			Address relocationAddress) throws MemoryAccessException, NotFoundException {

		Program program = elfRelocationContext.getProgram();

		Memory memory = program.getMemory();

		int type = relocation.getType();
		int symbolIndex = relocation.getSymbolIndex();

		long addend = relocation.getAddend(); // will be 0 for REL case

		ElfHeader elf = elfRelocationContext.getElfHeader();

		// WARNING: offset is in bytes
		//     be careful, word address potentially with byte indexes
		long offset = relocationAddress.getOffset();

		ElfSymbol sym = elfRelocationContext.getSymbol(symbolIndex); // may be null
		// WARNING: symbolValue here is not in bytes.
		// it is an addressable word offset for the symbols address space
		long symbolValue = elfRelocationContext.getSymbolValue(sym);
		String symbolName = elfRelocationContext.getSymbolName(symbolIndex);

		int oldValue = memory.getShort(relocationAddress);

		if (elf.e_machine() != ElfConstants.EM_AVR) {
			return;
		}

		int newValue = 0;

		switch (type) {
			case AVR8_ElfRelocationConstants.R_AVR_NONE:
				break;

			case AVR8_ElfRelocationConstants.R_AVR_32:
				newValue = (((int) symbolValue + (int) addend) & 0xffffffff);
				memory.setInt(relocationAddress, newValue);
				break;

			case AVR8_ElfRelocationConstants.R_AVR_7_PCREL:
				newValue = (int) ((symbolValue * 2 + (int) addend - offset));
				newValue -= 2; // branch PC is offset+2

				if ((newValue & 1) == 1) {
					markAsError(program, relocationAddress, type, symbolName,
						"relocation out of range", elfRelocationContext.getLog());
					return;
				}
				if (newValue > ((1 << 7) - 1) || (newValue < -(1 << 7))) {
					markAsError(program, relocationAddress, type, symbolName, "relocation overflow",
						elfRelocationContext.getLog());
					return;
				}
				newValue = (oldValue & 0xfc07) | (((newValue >> 1) << 3) & 0x3f8);
				memory.setShort(relocationAddress, (short) newValue);
				break;

			case AVR8_ElfRelocationConstants.R_AVR_13_PCREL:
				newValue = (int) ((symbolValue * 2 + (int) addend - offset));
				newValue -= 2; // branch PC is offset+2

				if ((newValue & 1) == 1) {
					markAsError(program, relocationAddress, type, symbolName,
						"relocation out of range", elfRelocationContext.getLog());
					return;
				}
				newValue >>= 1;

				if (newValue < -2048 || newValue > 2047) {
					markAsWarning(program, relocationAddress, symbolName, symbolName, symbolIndex,
						"possible relocation error", elfRelocationContext.getLog());
				}

				newValue = (oldValue & 0xf000) | (newValue & 0xfff);
				memory.setShort(relocationAddress, (short) newValue);
				break;

			case AVR8_ElfRelocationConstants.R_AVR_16:
				newValue = ((int) symbolValue + (int) addend);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case AVR8_ElfRelocationConstants.R_AVR_16_PM:
				newValue = (((int) symbolValue * 2 + (int) addend));
				newValue >>= 1;
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case AVR8_ElfRelocationConstants.R_AVR_LO8_LDI:
				newValue = (((int) symbolValue + (int) addend));
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case AVR8_ElfRelocationConstants.R_AVR_HI8_LDI:
				newValue = (((int) symbolValue + (int) addend));
				newValue = (newValue >> 8) & 0xff;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case AVR8_ElfRelocationConstants.R_AVR_HH8_LDI:
				newValue = (((int) symbolValue + (int) addend));
				newValue = (newValue >> 16) & 0xff;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case AVR8_ElfRelocationConstants.R_AVR_LO8_LDI_NEG:
				newValue = (((int) symbolValue + (int) addend));
				newValue = -newValue;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case AVR8_ElfRelocationConstants.R_AVR_HI8_LDI_NEG:
				newValue = (((int) symbolValue + (int) addend));
				newValue = -newValue;
				newValue = (newValue >> 8) & 0xff;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case AVR8_ElfRelocationConstants.R_AVR_HH8_LDI_NEG:
				newValue = (((int) symbolValue + (int) addend));
				newValue = -newValue;
				newValue = (newValue >> 16) & 0xff;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case AVR8_ElfRelocationConstants.R_AVR_LO8_LDI_PM:
				newValue = (((int) symbolValue * 2 + (int) addend));
				if ((newValue & 1) == 1) {
					markAsError(program, relocationAddress, type, symbolName,
						"relocation out of range", elfRelocationContext.getLog());
					return;
				}
				newValue >>= 1;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case AVR8_ElfRelocationConstants.R_AVR_HI8_LDI_PM:
				newValue = (((int) symbolValue * 2 + (int) addend));
				if ((newValue & 1) == 1) {
					markAsError(program, relocationAddress, type, symbolName,
						"relocation out of range", elfRelocationContext.getLog());
					return;
				}
				newValue >>= 1;
				newValue = (newValue >> 8) & 0xff;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case AVR8_ElfRelocationConstants.R_AVR_HH8_LDI_PM:
				newValue = (((int) symbolValue * 2 + (int) addend));
				if ((newValue & 1) == 1) {
					markAsError(program, relocationAddress, type, symbolName,
						"relocation out of range", elfRelocationContext.getLog());
					return;
				}
				newValue >>= 1;
				newValue = (newValue >> 16) & 0xff;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case AVR8_ElfRelocationConstants.R_AVR_LO8_LDI_PM_NEG:
				newValue = (((int) symbolValue * 2 + (int) addend));
				newValue = -newValue;
				if ((newValue & 1) == 1) {
					markAsError(program, relocationAddress, type, symbolName,
						"relocation out of range", elfRelocationContext.getLog());
					return;
				}
				newValue >>= 1;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case AVR8_ElfRelocationConstants.R_AVR_HI8_LDI_PM_NEG:
				newValue = (((int) symbolValue * 2 + (int) addend));
				newValue = -newValue;
				if ((newValue & 1) == 1) {
					markAsError(program, relocationAddress, type, symbolName,
						"relocation out of range", elfRelocationContext.getLog());
					return;
				}
				newValue >>= 1;
				newValue = (newValue >> 8) & 0xff;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case AVR8_ElfRelocationConstants.R_AVR_HH8_LDI_PM_NEG:
				newValue = (((int) symbolValue * 2 + (int) addend));
				newValue = -newValue;
				if ((newValue & 1) == 1) {
					markAsError(program, relocationAddress, type, symbolName,
						"relocation out of range", elfRelocationContext.getLog());
					return;
				}
				newValue >>= 1;
				newValue = (newValue >> 16) & 0xff;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case AVR8_ElfRelocationConstants.R_AVR_CALL:
				newValue = (int) symbolValue * 2 + (int) addend;

				if ((newValue & 1) == 1) {
					markAsError(program, relocationAddress, type, symbolName,
						"relocation out of range", elfRelocationContext.getLog());
					return;
				}
				newValue >>= 1;

				int hiValue =
					oldValue | ((newValue & 0x10000) | ((newValue << 3) & 0x1f00000)) >> 16;
				memory.setShort(relocationAddress, (short) (hiValue & 0xffff));
				memory.setShort(relocationAddress.add(2), (short) (newValue & 0xffff));
				break;

			case AVR8_ElfRelocationConstants.R_AVR_LDI: /* data/eeprom */
				newValue = (((int) symbolValue + (int) addend));

				if ((newValue & 0xffff) > 255) {
					markAsError(program, relocationAddress, type, symbolName,
						"relocation out of range", elfRelocationContext.getLog());
				}

				newValue = (newValue >> 8) & 0xff;
				newValue = (oldValue & 0xf0f0) | (newValue & 0xf) | ((newValue << 4) & 0xf00);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case AVR8_ElfRelocationConstants.R_AVR_6: /* data/eeprom **/
				newValue = (((int) symbolValue + (int) addend));

				if (((newValue & 0xffff) > 63) || (newValue < 0)) {
					markAsError(program, relocationAddress, type, symbolName,
						"relocation out of range", elfRelocationContext.getLog());
				}

				newValue = (oldValue & 0xd3f8) | (newValue & 7) | ((newValue & (3 << 3)) << 7) |
					((newValue & (1 << 5)) << 8);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case AVR8_ElfRelocationConstants.R_AVR_6_ADIW:
				newValue = (((int) symbolValue + (int) addend));

				if (((newValue & 0xffff) > 63) || (newValue < 0)) {
					markAsError(program, relocationAddress, type, symbolName,
						"relocation out of range", elfRelocationContext.getLog());
				}

				newValue = (oldValue & 0xff30) | (newValue & 0xF) | ((newValue & 0x30) << 2);

				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case AVR8_ElfRelocationConstants.R_AVR_DIFF8:
			case AVR8_ElfRelocationConstants.R_AVR_DIFF16:
			case AVR8_ElfRelocationConstants.R_AVR_DIFF32:
				// nothing to do
				break;

			case AVR8_ElfRelocationConstants.R_AVR_LDS_STS_16:
				newValue = (((int) symbolValue + (int) addend));

				if (((newValue & 0xffff) < 0x40) || (newValue & 0xFFFF) > 0xbf) {
					markAsError(program, relocationAddress, type, symbolName,
						"relocation out of range", elfRelocationContext.getLog());
				}

				newValue = newValue & 0x7f;
				newValue = (oldValue & 0x0f) | ((newValue & 0x30) << 5) | ((newValue & 0x40) << 2);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case AVR8_ElfRelocationConstants.R_AVR_PORT6:
				newValue = (((int) symbolValue + (int) addend));

				if ((newValue & 0xffff) > 0x3f) {
					markAsError(program, relocationAddress, type, symbolName,
						"relocation out of range", elfRelocationContext.getLog());
				}

				newValue = (oldValue & 0xf9f0) | ((newValue & 0x30) << 5) | (newValue & 0x0f);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case AVR8_ElfRelocationConstants.R_AVR_PORT5:
				newValue = (((int) symbolValue + (int) addend));

				if ((newValue & 0xffff) > 0x1f) {
					markAsError(program, relocationAddress, type, symbolName,
						"relocation out of range", elfRelocationContext.getLog());
				}

				newValue = (oldValue & 0xff07) | ((newValue & 0x1f) << 3);
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;

			case AVR8_ElfRelocationConstants.R_AVR_MS8_LDI:
			case AVR8_ElfRelocationConstants.R_AVR_MS8_LDI_NEG:
			case AVR8_ElfRelocationConstants.R_AVR_LO8_LDI_GS:
			case AVR8_ElfRelocationConstants.R_AVR_HI8_LDI_GS:
			case AVR8_ElfRelocationConstants.R_AVR_8:
			case AVR8_ElfRelocationConstants.R_AVR_8_LO8:
			case AVR8_ElfRelocationConstants.R_AVR_8_HI8:
			case AVR8_ElfRelocationConstants.R_AVR_8_HLO8:
			default:
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				break;
		}
	}

}
