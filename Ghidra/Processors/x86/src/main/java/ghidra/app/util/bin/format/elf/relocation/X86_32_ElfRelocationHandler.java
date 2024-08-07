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

public class X86_32_ElfRelocationHandler
		extends AbstractElfRelocationHandler<X86_32_ElfRelocationType, ElfRelocationContext<?>> {

	/**
	 * Constructor
	 */
	public X86_32_ElfRelocationHandler() {
		super(X86_32_ElfRelocationType.class);
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_386;
	}

	@Override
	public int getRelrRelocationType() {
		return X86_32_ElfRelocationType.R_386_RELATIVE.typeId;
	}

	@Override
	protected RelocationResult relocate(ElfRelocationContext<?> elfRelocationContext,
			ElfRelocation relocation, X86_32_ElfRelocationType type, Address relocationAddress,
			ElfSymbol sym, Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		// addend is either pulled from the relocation or the bytes in memory
		long addend =
			relocation.hasAddend() ? relocation.getAddend() : memory.getInt(relocationAddress);

		long offset = (int) relocationAddress.getOffset();
		int symbolIndex = relocation.getSymbolIndex();
		int byteLength = 4; // most relocations affect 4-bytes (change if different)
		int value;

		// Handle relative relocations that do not require symbolAddr or symbolValue 
		switch (type) {
			case R_386_RELATIVE:
				long base = program.getImageBase().getOffset();
				if (elfRelocationContext.getElfHeader().isPreLinked()) {
					// adjust prelinked value that is already in memory
					value = memory.getInt(relocationAddress) +
						(int) elfRelocationContext.getImageBaseWordAdjustmentOffset();
				}
				else {
					value = (int) (base + addend);
				}
				memory.setInt(relocationAddress, value);
				return new RelocationResult(Status.APPLIED, byteLength);

			case R_386_IRELATIVE:
				// NOTE: We don't support this since the code actually uses a function to 
				// compute the relocation value (i.e., indirect)
				markAsError(program, relocationAddress, type, symbolName, symbolIndex,
					"Indirect computed relocation not supported", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case R_386_GOTPC:
				// similar to R_386_PC32 but uses .got address instead of symbol address
				try {
					long dotgot = elfRelocationContext.getGOTValue();
					value = (int) (dotgot + addend - offset);
					memory.setInt(relocationAddress, value);
				}
				catch (NotFoundException e) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						e.getMessage(), elfRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}
				return new RelocationResult(Status.APPLIED, byteLength);

			case R_386_COPY:
				markAsUnsupportedCopy(program, relocationAddress, type, symbolName, symbolIndex,
					sym.getSize(), elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
				
			// Thread Local Symbol relocations (unimplemented concept)
			case R_386_TLS_DTPMOD32:
			case R_386_TLS_DTPOFF32:
			case R_386_TLS_TPOFF32:
			case R_386_TLS_TPOFF:
				markAsWarning(program, relocationAddress, type, symbolName, symbolIndex,
					"Thread Local Symbol relocation not supported", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
				
			default:
				break;
		}
		
		// Check for unresolved symbolAddr and symbolValue required by remaining relocation types handled below
		if (handleUnresolvedSymbol(elfRelocationContext, relocation, relocationAddress)) {
			return RelocationResult.FAILURE;
		}
				
		switch (type) {
			case R_386_32:
				value = (int) (symbolValue + addend);
				memory.setInt(relocationAddress, value);
				if (symbolIndex != 0 && addend != 0 && !sym.isSection()) {
					warnExternalOffsetRelocation(program, relocationAddress, symbolAddr, symbolName,
						addend, elfRelocationContext.getLog());
					applyComponentOffsetPointer(program, relocationAddress, addend);
				}
				break;
			case R_386_PC32:
				value = (int) (symbolValue + addend - offset);
				memory.setInt(relocationAddress, value);
				break;
			// we punt on these because they're not linked yet!
			case R_386_GOT32:
				value = (int) (symbolValue + addend);
				memory.setInt(relocationAddress, value);
				break;
			case R_386_PLT32:
				value = (int) (symbolValue + addend - offset);
				memory.setInt(relocationAddress, value);
				break;
			case R_386_GLOB_DAT:
			case R_386_JMP_SLOT:
				value = (int) symbolValue;
				memory.setInt(relocationAddress, value);
				break;
			case R_386_GOTOFF:
				try {
					long dotgot = elfRelocationContext.getGOTValue();
					value = (int) symbolValue + (int) addend - (int) dotgot;
					memory.setInt(relocationAddress, value);
				}
				catch (NotFoundException e) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						e.getMessage(), elfRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}
				break;

			// TODO: Cases not yet examined
			// case R_386_32PLT
			// case R_386_TLS_IE:
			// case R_386_TLS_GOTIE:
			// case R_386_TLS_LE:
			// case R_386_TLS_GD:
			// case R_386_TLS_LDM:
			// case R_386_TLS_GD_32:
			// case R_386_TLS_GD_PUSH:
			// case R_386_TLS_GD_CALL:
			// case R_386_TLS_GD_POP:
			// case R_386_TLS_LDM_32:
			// case R_386_TLS_LDM_PUSH:
			// case R_386_TLS_LDO_32:
			// case R_386_TLS_IE_32:
			// case R_386_TLS_LE_32:
			// case R_386_TLS_GOTDESC:
			// case R_386_TLS_GOTDESC:
			// case R_386_TLS_DESC_CALL:
			// case R_386_TLS_DESC:

			default:
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}

}
