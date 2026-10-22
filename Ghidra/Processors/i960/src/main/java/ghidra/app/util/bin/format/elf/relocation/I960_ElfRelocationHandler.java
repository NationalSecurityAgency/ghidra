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

import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfRelocation;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.NotFoundException;

public class I960_ElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_960;
	}

	@Override
	public void relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation, Address relocationAddress)
			throws MemoryAccessException, NotFoundException {
		if (!canRelocate(elfRelocationContext.getElfHeader())) {
			return;
		}
		int type = relocation.getType();
		if (I960_ElfRelocationConstants.R_960_NONE == type) {
			return;
		}
		
		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		ElfSymbol sym = null;
		long symbolValue = 0;
		Address symbolAddr = null;
		String symbolName = null;
		int symbolIndex = relocation.getSymbolIndex();
		if (symbolIndex != 0) {
			sym = elfRelocationContext.getSymbol(symbolIndex);
		}

		if (null != sym) {
			symbolAddr = elfRelocationContext.getSymbolAddress(sym);
			symbolValue = elfRelocationContext.getSymbolValue(sym);
			symbolName = sym.getNameAsString();
		}
		
		switch (type) {
		default:
			markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName, elfRelocationContext.getLog());
			break;
		case I960_ElfRelocationConstants.R_960_12:
			markAsWarning(program, relocationAddress, "R_960_12", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case I960_ElfRelocationConstants.R_960_32:
			markAsWarning(program, relocationAddress, "R_960_32", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case I960_ElfRelocationConstants.R_960_IP24:
			markAsWarning(program, relocationAddress, "R_960_IP24", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case I960_ElfRelocationConstants.R_960_SUB:
			markAsWarning(program, relocationAddress, "R_960_SUB", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case I960_ElfRelocationConstants.R_960_OPTCALL:
			markAsWarning(program, relocationAddress, "R_960_OPTCALL", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case I960_ElfRelocationConstants.R_960_OPTCALLX:
			markAsWarning(program, relocationAddress, "R_960_OPTCALLX", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case I960_ElfRelocationConstants.R_960_OPTCALLXA:
			markAsWarning(program, relocationAddress, "R_960_OPTCALLXA", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		}

	}

}
