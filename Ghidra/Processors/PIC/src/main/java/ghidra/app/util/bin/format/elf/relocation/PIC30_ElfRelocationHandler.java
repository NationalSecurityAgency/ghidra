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

public class PIC30_ElfRelocationHandler extends ElfRelocationHandler {

	/* ARC Relocations */

	//Numbers found in ./include/elf/arc.h:
	public static final int R_PIC30_NONE = 0;
	public static final int R_PIC30_8 = 1;
	public static final int R_PIC30_16 = 2;
	public static final int R_PIC30_32 = 3;
	public static final int R_PIC30_FILE_REG_WORD_WITH_DST = 7;
	public static final int R_PIC30_WORD = 8;
	public static final int R_PIC30_PCREL_BRANCH = 28;

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_DSPIC30F;
	}

	@Override
	public void relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation,
			Address relocationAddress) throws MemoryAccessException, NotFoundException {

		int type = relocation.getType();
		if (type == R_PIC30_NONE) {
			return;
		}

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		int symbolIndex = relocation.getSymbolIndex();

		long addend = relocation.getAddend(); // will be 0 for REL case

		if (symbolIndex == 0) {//TODO
			return;
		}

		long offset = (int) relocationAddress.getOffset();

		ElfSymbol sym = elfRelocationContext.getSymbol(symbolIndex);
		long symbolValue = elfRelocationContext.getSymbolValue(sym);

		int oldValue = memory.getInt(relocationAddress);
		int newValue;

		ElfHeader elf = elfRelocationContext.getElfHeader();
		if (elf.e_machine() == ElfConstants.EM_DSPIC30F) {//Defined in ./bfd/elf32-arc.c:
			switch (type) {
				case R_PIC30_32:
					newValue = (((int) symbolValue + (int) addend + oldValue) & 0xffffffff);
					memory.setInt(relocationAddress, newValue);
					break;
				case R_PIC30_PCREL_BRANCH:
					int offsetValue = memory.getShort(relocationAddress) + 1;
					offsetValue = offsetValue * 2;  // make it byte oriented - this should normally be 0
					newValue = (int) (((symbolValue + (int) addend - (offset + 4))));
					newValue >>>= 2;  // turn it into word offset, and align to even address, actually an error if it isn't aligned
					// work it into the instruction
					memory.setShort(relocationAddress, (short) (newValue & 0xffff));
					break;
				case R_PIC30_16:
					short oldShortValue = memory.getShort(relocationAddress);
					newValue = ((((int) symbolValue + (int) addend + oldShortValue) >> 1) & 0xffff);
					memory.setShort(relocationAddress, (short) newValue);
					break;
				case R_PIC30_FILE_REG_WORD_WITH_DST:
					newValue = ((((int) symbolValue + (int) addend) >> 1) & 0x7fff);
					int dst = (oldValue >> 4) & 0x7fff;
					newValue = ((newValue + dst) << 4) | (oldValue & 0xfff1000f);
					memory.setInt(relocationAddress, newValue);
					break;
				case R_PIC30_WORD:
					newValue = ((((int) symbolValue + (int) addend) >> 1) & 0xffff);
					newValue = (newValue << 4) | oldValue;
					memory.setInt(relocationAddress, newValue);
					break;
				case R_PIC30_8:
				default:
					String symbolName = sym.getNameAsString();
					markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
						elfRelocationContext.getLog());
					break;
			}
		}
	}

}
