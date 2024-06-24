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
import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.app.util.bin.format.elf.ElfRelocation;
import ghidra.app.util.bin.format.elf.ElfRelocationTable;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.NotFoundException;

public class NDS32_ElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_NDS32;
	}

	@Override
	public NDS32_ElfRelocationContext createRelocationContext(ElfLoadHelper loadHelper,
			ElfRelocationTable relocationTable, Map<ElfSymbol, Address> symbolMap) {
		return new NDS32_ElfRelocationContext(this, loadHelper, relocationTable, symbolMap);
	}

	@Override
	public void relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation, Address relocationAddress)
			throws MemoryAccessException, NotFoundException {
		ElfHeader elf = elfRelocationContext.getElfHeader();

		if (elf.e_machine() != ElfConstants.EM_NDS32) {
			return;
		}
		
		if (!elf.is32Bit()) {
			return;
		}
		
		NDS32_ElfRelocationContext nds32RelocationContext =
				(NDS32_ElfRelocationContext) elfRelocationContext;

		int type = relocation.getType();
		int symbolIndex = relocation.getSymbolIndex();		
		doRelocate(nds32RelocationContext, type, symbolIndex, relocation, relocationAddress);
	}

	private void doRelocate(NDS32_ElfRelocationContext nds32RelocationContext, int relocType,
			int symbolIndex, ElfRelocation relocation, Address relocationAddress)
			throws MemoryAccessException, NotFoundException, AddressOutOfBoundsException {
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

		switch(relocType) {
		case NDS32_ElfRelocationConstants.R_NDS32_HI20_RELA:
			value = (int)(symbolValue + addend);
			newValue = (oldValue & 0xfff00000) | (value >> 12);
			memory.setInt(relocationAddress, newValue, true);
			break;
		case NDS32_ElfRelocationConstants.R_NDS32_LO12S0_RELA:
			value = (int)(symbolValue + addend);
			newValue = (oldValue & 0xfffff000) | (value & 0xfff);
			memory.setInt(relocationAddress, newValue, true);
			break;
		default:
			markAsUnhandled(program, relocationAddress, relocType, symbolIndex, symbolName, log);
		}
	}
	
	private static class NDS32_ElfRelocationContext extends ElfRelocationContext {

		protected NDS32_ElfRelocationContext(ElfRelocationHandler handler, ElfLoadHelper loadHelper,
				ElfRelocationTable relocationTable, Map<ElfSymbol, Address> symbolMap) {
			super(handler, loadHelper, relocationTable, symbolMap);
		}
	}
}
