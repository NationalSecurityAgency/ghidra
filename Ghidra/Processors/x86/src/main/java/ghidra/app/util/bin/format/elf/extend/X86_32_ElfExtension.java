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
package ghidra.app.util.bin.format.elf.extend;

import java.math.BigInteger;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class X86_32_ElfExtension extends ElfExtension {

	@Override
	public boolean canHandle(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_386 && elf.is32Bit();
	}
	
	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		Language language = elfLoadHelper.getProgram().getLanguage();
		return canHandle(elfLoadHelper.getElfHeader()) && 
				"x86".equals(language.getProcessor().toString()) &&
						language.getLanguageDescription().getSize() == 32;
	}

	@Override
	public String getDataTypeSuffix() {
		return "_x86";
	}

	@Override
	public void processGotPlt(ElfLoadHelper elfLoadHelper, TaskMonitor monitor) throws CancelledException {
		
		if (!canHandle(elfLoadHelper)) {
			return;
		}
		
		super.processGotPlt(elfLoadHelper, monitor);
		
		processX86Plt(elfLoadHelper, monitor);
	}

	/**
	 * Handle the case where GOT entry offset are computed based upon EBX.  
	 * This implementation replaces the old "magic map" which had previously been used.
	 * @param elfLoadHelper
	 * @param monitor
	 * @throws CancelledException
	 */
	private void processX86Plt(ElfLoadHelper elfLoadHelper, TaskMonitor monitor) throws CancelledException {
		
		// TODO: Does 64-bit have a similar mechanism?

		// TODO: Would be better to use only dynamic table entries since sections may be stripped -
		// the unresolved issue is to determine the length of the PLT area without a section
		
		ElfHeader elfHeader = elfLoadHelper.getElfHeader();
		ElfSectionHeader pltSection = elfHeader.getSection(ElfSectionHeaderConstants.dot_plt);
		if (pltSection == null || !pltSection.isExecutable()) {
			return;
		}
		
		ElfDynamicTable dynamicTable = elfHeader.getDynamicTable();
		if (dynamicTable == null || !dynamicTable.containsDynamicValue(ElfDynamicType.DT_PLTGOT)) {
			return; // avoid NotFoundException which causes issues for importer
		}
		
		Program program = elfLoadHelper.getProgram();
		Memory memory = program.getMemory();
		
		// MemoryBlock pltBlock = getBlockPLT(pltSection);
		MemoryBlock pltBlock = memory.getBlock(pltSection.getNameAsString());
		if (pltBlock == null) {
			return;
		}

		// Paint pltgot base over .plt section to allow thunks to be resolved during analysis
		Register ebxReg = program.getRegister("EBX");
		try {
			long pltgotOffset = elfHeader.adjustAddressForPrelink(dynamicTable.getDynamicValue(
					ElfDynamicType.DT_PLTGOT));
			pltgotOffset = elfLoadHelper.getDefaultAddress(pltgotOffset).getOffset(); // adjusted for image base
			RegisterValue pltgotValue = new RegisterValue(ebxReg, BigInteger.valueOf(pltgotOffset));
			program.getProgramContext().setRegisterValue(pltBlock.getStart(), pltBlock.getEnd(), pltgotValue);
		} catch (NotFoundException | ContextChangeException e) {
			throw new AssertException("unexpected", e);
		}

	}

}
