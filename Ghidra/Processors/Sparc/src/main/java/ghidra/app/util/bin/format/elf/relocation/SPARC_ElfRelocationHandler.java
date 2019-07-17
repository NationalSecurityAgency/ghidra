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

public class SPARC_ElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_SPARC ||
			elf.e_machine() == ElfConstants.EM_SPARC32PLUS ||
			elf.e_machine() == ElfConstants.EM_SPARCV9;
	}

	@Override
	public void relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation,
			Address relocationAddress) throws MemoryAccessException, NotFoundException {

		ElfHeader elf = elfRelocationContext.getElfHeader();
		if (elf.e_machine() != ElfConstants.EM_SPARC &&
			elf.e_machine() != ElfConstants.EM_SPARC32PLUS) {
			return;
		}

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		int type = relocation.getType();
		if (type == SPARC_ElfRelocationConstants.R_SPARC_NONE) {
			return;
		}

		int symbolIndex = relocation.getSymbolIndex();

		long addend = relocation.getAddend(); // will be 0 for REL case

		long offset = (int) relocationAddress.getOffset();

		ElfSymbol sym = elfRelocationContext.getSymbol(symbolIndex);
		String symbolName = sym != null ? sym.getNameAsString() : null;

		long symbolValue = elfRelocationContext.getSymbolValue(sym);

		int oldValue = memory.getInt(relocationAddress);
		int newValue = 0;

		switch (type) {
			case SPARC_ElfRelocationConstants.R_SPARC_DISP32:
				newValue = (int) (symbolValue + addend - offset);
				memory.setInt(relocationAddress, oldValue | newValue);
				break;
			case SPARC_ElfRelocationConstants.R_SPARC_WDISP30:
				newValue = (int) (symbolValue + addend - offset) >>> 2;
				memory.setInt(relocationAddress, oldValue | newValue);
				break;
			case SPARC_ElfRelocationConstants.R_SPARC_HI22:
				newValue = ((int) symbolValue + (int) addend) >>> 10;
				memory.setInt(relocationAddress, oldValue | newValue);
				break;
			case SPARC_ElfRelocationConstants.R_SPARC_LO10:
				newValue = ((int) symbolValue + (int) addend) & 0x3FF;
				memory.setInt(relocationAddress, oldValue | newValue);
				break;
			case SPARC_ElfRelocationConstants.R_SPARC_JMP_SLOT:
				// should copy address of symbol in EXTERNAL block
			case SPARC_ElfRelocationConstants.R_SPARC_32:
				newValue = (int) symbolValue + (int) addend;
				memory.setInt(relocationAddress, newValue);
				break;
			// we punt on this because it's not linked yet!
			case SPARC_ElfRelocationConstants.R_SPARC_GLOB_DAT:
				newValue = (int) symbolValue;
				memory.setInt(relocationAddress, newValue);
				break;
			case SPARC_ElfRelocationConstants.R_SPARC_RELATIVE:
				newValue = (int) elf.getImageBase() + (int) addend;
				memory.setInt(relocationAddress, newValue);
				break;
			case SPARC_ElfRelocationConstants.R_SPARC_UA32:
				newValue = (int) symbolValue + (int) addend;
				memory.setInt(relocationAddress, newValue);
				break;
			case SPARC_ElfRelocationConstants.R_SPARC_COPY:
				markAsWarning(program, relocationAddress, "R_SPARC_COPY", symbolName, symbolIndex,
					"Runtime copy not supported", elfRelocationContext.getLog());
				break;
			default:
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				break;
		}
	}

}
