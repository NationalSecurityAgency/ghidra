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
import ghidra.util.exception.NotFoundException;

public class SH_ElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_SH && elf.is32Bit();
	}

	@Override
	public RelocationResult relocate(ElfRelocationContext elfRelocationContext,
			ElfRelocation relocation,
			Address relocationAddress) throws MemoryAccessException, NotFoundException {

		ElfHeader elf = elfRelocationContext.getElfHeader();
		if (elf.e_machine() != ElfConstants.EM_SH || !elf.is32Bit()) {
			return RelocationResult.FAILURE;
		}

		Program program = elfRelocationContext.getProgram();

		Memory memory = program.getMemory();
		
		int type = relocation.getType();
		if (type == SH_ElfRelocationConstants.R_SH_NONE) {
			return RelocationResult.SKIPPED;
		}
		int symbolIndex = relocation.getSymbolIndex();

		int addend = (int) relocation.getAddend();

		ElfSymbol sym = elfRelocationContext.getSymbol(symbolIndex); // may be null
		String symbolName = elfRelocationContext.getSymbolName(symbolIndex);

		int offset = (int) relocationAddress.getOffset();

		Address symbolAddr = elfRelocationContext.getSymbolAddress(sym);
		int symbolValue = (int) elfRelocationContext.getSymbolValue(sym);

		int newValue = 0;
		int oldValue;

		int byteLength = 4; // most relocations affect 4-bytes (change if different)

		switch (type) {
			case SH_ElfRelocationConstants.R_SH_DIR32:
				// 32-bit absolute relocation w/ addend
				if (elfRelocationContext.extractAddend()) {
					addend = memory.getInt(relocationAddress);
				}
				newValue = symbolValue + addend;
				memory.setInt(relocationAddress, newValue);
				if (symbolIndex != 0 && addend != 0 && !sym.isSection()) {
					warnExternalOffsetRelocation(program, relocationAddress,
						symbolAddr, symbolName, addend, elfRelocationContext.getLog());
					applyComponentOffsetPointer(program, relocationAddress, addend);
				}
				break;
			case SH_ElfRelocationConstants.R_SH_GLOB_DAT:
			case SH_ElfRelocationConstants.R_SH_JMP_SLOT:
				// 32-bit absolute relocations, no addend
				memory.setInt(relocationAddress, symbolValue);
				break;

			case SH_ElfRelocationConstants.R_SH_REL32:  // 32-bit PC relative relocation
				if (elfRelocationContext.extractAddend()) {
					addend = memory.getInt(relocationAddress);
				}
				newValue = (symbolValue + addend) - offset;
				memory.setInt(relocationAddress, newValue);
				break;

			case SH_ElfRelocationConstants.R_SH_DIR8WPN:  // 8-bit PC relative branch divided by 2
			case SH_ElfRelocationConstants.R_SH_DIR8WPZ:  // 8-bit PC unsigned-relative branch divided by 2
				oldValue = memory.getShort(relocationAddress);
				if (elfRelocationContext.extractAddend()) {
					addend = oldValue & 0xff;
					if (type == SH_ElfRelocationConstants.R_SH_DIR8WPN && (addend & 0x80) != 0) {
						addend -= 0x100; // sign-extend addend for R_SH_DIR8WPN
					}
				}
				newValue = ((symbolValue + addend) - offset) >> 1;
				newValue = (oldValue & 0xff00) | (newValue & 0xff);
				memory.setShort(relocationAddress, (short) newValue);
				byteLength = 2;
				break;

			case SH_ElfRelocationConstants.R_SH_IND12W:  // 12-bit PC relative branch divided by 2
				oldValue = memory.getShort(relocationAddress);
				if (elfRelocationContext.extractAddend()) {
					addend = oldValue & 0xfff;
					if ((addend & 0x800) != 0) {
						addend -= 0x1000; // sign-extend addend
					}
				}
				newValue = ((symbolValue + addend) - offset) >> 1;
				newValue = (oldValue & 0xf000) | (newValue & 0xfff);
				memory.setShort(relocationAddress, (short) newValue);
				byteLength = 2;
				break;

			case SH_ElfRelocationConstants.R_SH_DIR8WPL:  // 8-bit PC unsigned-relative branch divided by 4
				oldValue = memory.getShort(relocationAddress);
				if (elfRelocationContext.extractAddend()) {
					addend = oldValue & 0xff;
				}
				newValue = ((symbolValue + addend) - offset) >> 2;
				newValue = (oldValue & 0xff00) | (newValue & 0xff);
				memory.setShort(relocationAddress, (short) newValue);
				byteLength = 2;
				break;

			case SH_ElfRelocationConstants.R_SH_COPY:
				markAsWarning(program, relocationAddress, "R_SH_COPY", symbolName, symbolIndex,
					"Runtime copy not supported", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case SH_ElfRelocationConstants.R_SH_RELATIVE:
				if (elfRelocationContext.extractAddend()) {
					addend = memory.getInt(relocationAddress);
				}
				newValue = (int) (elfRelocationContext.getImageBaseWordAdjustmentOffset()) + addend;
				memory.setInt(relocationAddress, newValue);
				break;

			default:
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}

}
