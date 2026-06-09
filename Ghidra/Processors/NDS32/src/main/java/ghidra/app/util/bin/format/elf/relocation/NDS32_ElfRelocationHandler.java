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

import java.util.Map;

import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.program.model.reloc.Relocation.Status;

public class NDS32_ElfRelocationHandler extends AbstractElfRelocationHandler<NDS32_ElfRelocationType, ElfRelocationContext<?>> {

	public NDS32_ElfRelocationHandler() {
		super(NDS32_ElfRelocationType.class);
	}


	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_NDS32;
	}

	@Override
	public int getRelrRelocationType() {
		return NDS32_ElfRelocationType.R_NDS32_RELATIVE.typeId;
	}

	@Override
	protected RelocationResult relocate(ElfRelocationContext<?> elfRelocationContext,
			ElfRelocation relocation, NDS32_ElfRelocationType type, Address relocationAddress,
			ElfSymbol sym, Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {
		
		ElfRelocationContext<?> nds32RelocationContext = elfRelocationContext;

		int symbolIndex = relocation.getSymbolIndex();		
		return doRelocate(nds32RelocationContext, type, symbolIndex, relocation, relocationAddress);
		
	}

	private RelocationResult doRelocate(ElfRelocationContext<?> nds32RelocationContext, NDS32_ElfRelocationType type,
			int symbolIndex, ElfRelocation relocation, Address relocationAddress)
			throws MemoryAccessException {
		Program program = nds32RelocationContext.getProgram();
		Memory memory = program.getMemory();
		MessageLog log = nds32RelocationContext.getLog();
		ElfSymbol elfSymbol = nds32RelocationContext.getSymbol(symbolIndex);
		long symbolValue = nds32RelocationContext.getSymbolValue(elfSymbol);
		String symbolName = elfSymbol.getNameAsString();

		// Read instruction as big endian
		int oldValue = memory.getInt(relocationAddress, true);
		
		long addend = 0;
		if(relocation.hasAddend()) {
			addend = relocation.getAddend();
		}
		
		int value = 0;
		int newValue = 0;
		int byteLength = 4;
		
		switch(type) {
		case R_NDS32_HI20_RELA:
			value = (int)(symbolValue + addend);
			newValue = (oldValue & 0xfff00000) | (value >> 12);
			memory.setInt(relocationAddress, newValue, true);
			return new RelocationResult(Status.APPLIED, byteLength);
		case R_NDS32_LO12S0_RELA:
			value = (int)(symbolValue + addend);
			newValue = (oldValue & 0xfffff000) | (value & 0xfff);
			memory.setInt(relocationAddress, newValue, true);
			return new RelocationResult(Status.APPLIED, byteLength);
		default:
			return RelocationResult.UNSUPPORTED;
		}
	}
}
