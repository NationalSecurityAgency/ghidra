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

public class SPARC_ElfRelocationHandler
		extends AbstractElfRelocationHandler<SPARC_ElfRelocationType, ElfRelocationContext<?>> {

	/**
	 * Constructor
	 */
	public SPARC_ElfRelocationHandler() {
		super(SPARC_ElfRelocationType.class);
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_SPARC ||
			elf.e_machine() == ElfConstants.EM_SPARC32PLUS ||
			elf.e_machine() == ElfConstants.EM_SPARCV9;
	}

	@Override
	protected RelocationResult relocate(ElfRelocationContext<?> elfRelocationContext,
			ElfRelocation relocation, SPARC_ElfRelocationType type, Address relocationAddress,
			ElfSymbol sym, Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		long addend = relocation.getAddend(); // will be 0 for REL case

		// TODO: possible sign-extension seems wrong; there are both 32-bit and 64-bit variants
		long offset = (int) relocationAddress.getOffset();

		int symbolIndex = relocation.getSymbolIndex();
		int oldValue = memory.getInt(relocationAddress);
		int newValue = 0;
		int byteLength = 4; // most relocations affect 4-bytes (change if different)

		switch (type) {
			case R_SPARC_DISP32:
				newValue = (int) (symbolValue + addend - offset);
				memory.setInt(relocationAddress, oldValue | newValue);
				break;
			case R_SPARC_WDISP30:
				newValue = (int) (symbolValue + addend - offset) >>> 2;
				memory.setInt(relocationAddress, oldValue | newValue);
				break;
			case R_SPARC_HI22:
				newValue = ((int) symbolValue + (int) addend) >>> 10;
				memory.setInt(relocationAddress, oldValue | newValue);
				break;
			case R_SPARC_LO10:
				newValue = ((int) symbolValue + (int) addend) & 0x3FF;
				memory.setInt(relocationAddress, oldValue | newValue);
				break;
			case R_SPARC_JMP_SLOT:
				// should copy address of symbol in EXTERNAL block
			case R_SPARC_32:
				newValue = (int) symbolValue + (int) addend;
				memory.setInt(relocationAddress, newValue);
				break;
			// we punt on this because it's not linked yet!
			case R_SPARC_GLOB_DAT:
				newValue = (int) symbolValue;
				memory.setInt(relocationAddress, newValue);
				break;
			case R_SPARC_RELATIVE:
				newValue = (int) elfRelocationContext.getElfHeader().getImageBase() + (int) addend;
				memory.setInt(relocationAddress, newValue);
				break;
			case R_SPARC_UA32:
				newValue = (int) symbolValue + (int) addend;
				memory.setInt(relocationAddress, newValue);
				break;
			case R_SPARC_COPY:
				markAsUnsupportedCopy(program, relocationAddress, type, symbolName, symbolIndex,
					sym.getSize(), elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
			default:
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}

}
