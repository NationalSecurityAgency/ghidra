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

public class eBPF_ElfRelocationHandler
		extends AbstractElfRelocationHandler<eBPF_ElfRelocationType, ElfRelocationContext<?>> {

	/**
	 * Constructor
	 */
	public eBPF_ElfRelocationHandler() {
		super(eBPF_ElfRelocationType.class);
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_BPF;
	}

	@Override
	protected RelocationResult relocate(ElfRelocationContext<?> elfRelocationContext,
			ElfRelocation relocation, eBPF_ElfRelocationType type, Address relocationAddress,
			ElfSymbol symbol, Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		String section_name =
			elfRelocationContext.relocationTable.getSectionToBeRelocated().getNameAsString();
		if (section_name.toString().contains("debug")) {
			return RelocationResult.SKIPPED;
		}

		int symbolIndex = relocation.getSymbolIndex();
		long new_value = 0;
		int byteLength = 8;

		switch (type) {
			case R_BPF_64_64: {
				new_value = symbolAddr.getAddressableWordOffset();
				Byte dst = memory.getByte(relocationAddress.add(0x1));
				memory.setLong(relocationAddress.add(0x4), new_value);
				memory.setByte(relocationAddress.add(0x1), (byte) (dst + 0x10));
				break;
			}
			case R_BPF_64_32: {

				// if we have, e.g, non-static function, it will be marked in the relocation table
				// and indexed in the symbol table and it's easy to calculate the pc-relative offset
				long instr_next = relocationAddress.add(0x8).getAddressableWordOffset();
				if (symbol.isFunction()) {
					new_value = symbolAddr.getAddressableWordOffset();
					int offset = (int) (new_value - instr_next);
					memory.setInt(relocationAddress.add(0x4), offset);
				}
				else if (symbol.isSection()) {
					if (memory.getInt(relocationAddress) == 0x1085) {
						ElfSectionHeader sectionHeader =
							elfRelocationContext.getElfHeader().getSection(symbolName);
						long section_start =
							program.getImageBase().getOffset() + sectionHeader.getAddress();

						// getting call instruction offset (current imm)
						int current_imm = memory.getInt(relocationAddress.add(0x4));

						// calculate the call target section offset  
						// according to formula in "kernel.org" docs: https://www.kernel.org/doc/html/latest/bpf/llvm_reloc.html
						int func_sec_offset = (current_imm + 1) * 8;
						long func_addr = section_start + func_sec_offset;
						int offset = (int) (func_addr - instr_next);
						memory.setInt(relocationAddress.add(0x4), offset);
					}
				}
				break;
			}
			default: {
				if (symbolIndex == 0) {
					markAsWarning(program, relocationAddress, type, symbolName, symbolIndex,
						"applied relocation with symbol-index of 0", elfRelocationContext.getLog());
				}
				return RelocationResult.UNSUPPORTED;
			}
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}
}
