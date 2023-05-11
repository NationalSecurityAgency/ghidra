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

public class X86_32_ElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_386;
	}

	@Override
	public int getRelrRelocationType() {
		return X86_32_ElfRelocationConstants.R_386_RELATIVE;
	}

	@Override
	public RelocationResult relocate(ElfRelocationContext elfRelocationContext,
			ElfRelocation relocation,
			Address relocationAddress) throws MemoryAccessException, NotFoundException {

		ElfHeader elf = elfRelocationContext.getElfHeader();
		if (elf.e_machine() != ElfConstants.EM_386) {
			return RelocationResult.FAILURE;
		}

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		int type = relocation.getType();
		if (type == X86_32_ElfRelocationConstants.R_386_NONE) {
			return RelocationResult.SKIPPED;
		}

		int symbolIndex = relocation.getSymbolIndex();

		// addend is either pulled from the relocation or the bytes in memory
		long addend =
			relocation.hasAddend() ? relocation.getAddend() : memory.getInt(relocationAddress);

		ElfSymbol sym = elfRelocationContext.getSymbol(symbolIndex);
		Address symbolAddr = elfRelocationContext.getSymbolAddress(sym);
		long symbolValue = elfRelocationContext.getSymbolValue(sym);
		String symbolName = elfRelocationContext.getSymbolName(symbolIndex);

		long offset = (int) relocationAddress.getOffset();

		int byteLength = 4; // most relocations affect 4-bytes (change if different)
		int value;

		switch (type) {
			case X86_32_ElfRelocationConstants.R_386_32:
				value = (int) (symbolValue + addend);
				memory.setInt(relocationAddress, value);
				if (symbolIndex != 0 && addend != 0 && !sym.isSection()) {
					warnExternalOffsetRelocation(program, relocationAddress,
						symbolAddr, symbolName, addend, elfRelocationContext.getLog());
					applyComponentOffsetPointer(program, relocationAddress, addend);
				}
				break;
			case X86_32_ElfRelocationConstants.R_386_PC32:
				value = (int) (symbolValue + addend - offset);
				memory.setInt(relocationAddress, value);
				break;
			// we punt on these because they're not linked yet!
			case X86_32_ElfRelocationConstants.R_386_GOT32:
				value = (int) (symbolValue + addend);
				memory.setInt(relocationAddress, value);
				break;
			case X86_32_ElfRelocationConstants.R_386_PLT32:
				value = (int) (symbolValue + addend - offset);
				memory.setInt(relocationAddress, value);
				break;
			case X86_32_ElfRelocationConstants.R_386_GLOB_DAT:
			case X86_32_ElfRelocationConstants.R_386_JMP_SLOT:
				value = (int) symbolValue;
				memory.setInt(relocationAddress, value);
				break;
			case X86_32_ElfRelocationConstants.R_386_GOTOFF:
				try {
					long dotgot = elfRelocationContext.getGOTValue();
					value = (int) symbolValue + (int) addend - (int) dotgot;
					memory.setInt(relocationAddress, value);
				}
				catch (NotFoundException e) {
					markAsError(program, relocationAddress, "R_386_GOTOFF", symbolName,
						e.getMessage(), elfRelocationContext.getLog());
				}
				break;
			case X86_32_ElfRelocationConstants.R_386_COPY:
				markAsWarning(program, relocationAddress, "R_386_COPY", symbolName, symbolIndex,
					"Runtime copy not supported", elfRelocationContext.getLog());
				break;
			// Thread Local Symbol relocations (unimplemented concept)
			case X86_32_ElfRelocationConstants.R_386_TLS_DTPMOD32:
				markAsWarning(program, relocationAddress, "R_386_TLS_DTPMOD32", symbolName,
					symbolIndex, "Thread Local Symbol relocation not supported",
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
			case X86_32_ElfRelocationConstants.R_386_TLS_DTPOFF32:
				markAsWarning(program, relocationAddress, "R_386_TLS_DTPOFF32", symbolName,
					symbolIndex, "Thread Local Symbol relocation not supported",
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
			case X86_32_ElfRelocationConstants.R_386_TLS_TPOFF32:
				markAsWarning(program, relocationAddress, "R_386_TLS_TPOFF32", symbolName,
					symbolIndex, "Thread Local Symbol relocation not supported",
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
			case X86_32_ElfRelocationConstants.R_386_TLS_TPOFF:
				markAsWarning(program, relocationAddress, "R_386_TLS_TPOFF", symbolName,
					symbolIndex, "Thread Local Symbol relocation not supported",
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			// cases which do not use symbol value

			case X86_32_ElfRelocationConstants.R_386_RELATIVE:
				long base = program.getImageBase().getOffset();
				if (elf.isPreLinked()) {
					// adjust prelinked value that is already in memory
					value = memory.getInt(relocationAddress) +
						(int) elfRelocationContext.getImageBaseWordAdjustmentOffset();
				}
				else {
					value = (int) (base + addend);
				}
				memory.setInt(relocationAddress, value);
				break;

			case X86_32_ElfRelocationConstants.R_386_IRELATIVE:
				// NOTE: We don't support this since the code actually uses a function to 
				// compute the relocation value (i.e., indirect)
				markAsError(program, relocationAddress, "R_386_IRELATIVE", symbolName,
					"indirect computed relocation not supported", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case X86_32_ElfRelocationConstants.R_386_GOTPC:
				// similar to R_386_PC32 but uses .got address instead of symbol address
				try {
					long dotgot = elfRelocationContext.getGOTValue();
					value = (int) (dotgot + addend - offset);
					memory.setInt(relocationAddress, value);
				}
				catch (NotFoundException e) {
					markAsError(program, relocationAddress, "R_386_GOTPC", symbolName,
						e.getMessage(), elfRelocationContext.getLog());
				}
				break;

			// TODO: Cases not yet examined
			// case ElfRelocationConstants.R_386_32PLT
			// case ElfRelocationConstants.R_386_TLS_IE:
			// case ElfRelocationConstants.R_386_TLS_GOTIE:
			// case ElfRelocationConstants.R_386_TLS_LE:
			// case ElfRelocationConstants.R_386_TLS_GD:
			// case ElfRelocationConstants.R_386_TLS_LDM:
			// case ElfRelocationConstants.R_386_TLS_GD_32:
			// case ElfRelocationConstants.R_386_TLS_GD_PUSH:
			// case ElfRelocationConstants.R_386_TLS_GD_CALL:
			// case ElfRelocationConstants.R_386_TLS_GD_POP:
			// case ElfRelocationConstants.R_386_TLS_LDM_32:
			// case ElfRelocationConstants.R_386_TLS_LDM_PUSH:
			// case ElfRelocationConstants.R_386_TLS_LDO_32:
			// case ElfRelocationConstants.R_386_TLS_IE_32:
			// case ElfRelocationConstants.R_386_TLS_LE_32:
			// case ElfRelocationConstants.R_386_TLS_GOTDESC:
			// case ElfRelocationConstants.R_386_TLS_GOTDESC:
			// case ElfRelocationConstants.R_386_TLS_DESC_CALL:
			// case ElfRelocationConstants.R_386_TLS_DESC:

			default:
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}
}
