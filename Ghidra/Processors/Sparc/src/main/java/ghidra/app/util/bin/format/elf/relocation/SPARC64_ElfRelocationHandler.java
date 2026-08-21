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
import ghidra.program.model.reloc.RelocationResult;
import ghidra.program.model.reloc.Relocation.Status;

public class SPARC64_ElfRelocationHandler extends SPARC_ElfRelocationHandler {
	@Override
	public boolean canRelocate(ElfHeader elf) {
		boolean handleMachine = elf.e_machine() == ElfConstants.EM_SPARCV9;
		return handleMachine && elf.is64Bit();
	}

	@Override
	protected RelocationResult relocate(ElfRelocationContext<?> elfRelocationContext,
			ElfRelocation relocation, SPARC_ElfRelocationType type, Address relocationAddress,
			ElfSymbol sym, Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		long addend = relocation.getAddend();

		long pc = relocationAddress.getOffset();

		int oldIntValue = memory.getInt(relocationAddress);
		long newValue = 0;
		int  mask = 0;
		int byteLength = 8; // most relocations affect 8-bytes (change if different)
		
		// Handle relative relocations that do not require symbolAddr or symbolValue 
		switch (type) {
			case R_SPARC_RELATIVE:
				newValue = elfRelocationContext.getImageBaseWordAdjustmentOffset() + addend;
				memory.setLong(relocationAddress, newValue);
				return new RelocationResult(Status.APPLIED, byteLength);
				
			case R_SPARC_COPY:
				int symbolIndex = relocation.getSymbolIndex();
				markAsUnsupportedCopy(program, relocationAddress, type, symbolName, symbolIndex,
					sym.getSize(), elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
				
			case R_SPARC_SIZE64:
				newValue = sym.getSize() + addend;
				memory.setLong(relocationAddress, newValue);
				break;
				
			default:
				break;
		}
		
		// Check for unresolved symbolAddr and symbolValue required by remaining relocation types handled below
		if (handleUnresolvedSymbol(elfRelocationContext, relocation, relocationAddress)) {
			return RelocationResult.FAILURE;
		}
		
		// Relocation docs: https://docs.oracle.com/cd/E19120-01/open.solaris/819-0690/chapter6-24-1/index.html
		//
		switch (type) {
			case R_SPARC_HI22:
				newValue = (int) ((symbolValue + addend) >>> 10);
				mask = 0x003fffff;
				oldIntValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldIntValue | (int) newValue);
				byteLength = 4;
				break;
				
			case R_SPARC_OLO10:
				newValue = (int) ((symbolValue + addend) & 0x3FF) + (int)((relocation.getRelocationInfo()<<32)>>40);
				mask = 0x00001fff;
				oldIntValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldIntValue | (int) newValue);
				byteLength = 4;
				break;
				
			case R_SPARC_GLOB_DAT:
				newValue = symbolValue + addend;
				memory.setLong(relocationAddress, newValue);
				break;
				
			case R_SPARC_64:
				newValue = symbolValue + addend;
				memory.setLong(relocationAddress, newValue);
				break;

			case R_SPARC_DISP64:
				newValue = symbolValue + addend - pc;
				memory.setLong(relocationAddress, newValue);
				break;

			case R_SPARC_UA64:
			case R_SPARC_REGISTER:
				newValue = symbolValue + addend;
				memory.setLong(relocationAddress, newValue);
				break;
			
			case R_SPARC_H34:
				newValue = (int) ((symbolValue + addend) >>> 12);
				mask = 0x003fffff;
				oldIntValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldIntValue | (int) newValue);
				byteLength = 4;
				break;
			
			case R_SPARC_JMP_SLOT:
				final int sparc_sethi_g1 = 0x03000000;         // sethi   %hi(0x123),g1
				final int sparc_sethi_g5 = 0x0b000000;         // sethi   %hi(0x123),g5
				final int sparc_or_g5_immed_g5 = 0x8a116000;   // or      g5,0x123,g5
				final int sparc_or_g1_immed_g1 = 0x82106000;   // or      g1,0x123,g1
				final int sparc_sllx_g1_0x20 = 0x83287020;     // sllx    g1,32,g1
				final int sparc_jmpl_g1_g5 = 0x81c04005;       // jmpl    g1+g5
				final int sparc_nop = 0x01000000;              // nop
				

				// this is not the way JMP_SLOT is always done, but it should work in all cases of a large 64-bit address
			    // other variants are optimized to handle smaller address values
				newValue = (symbolValue + addend);
				
				long hh = newValue >> 42;
				long hl = (newValue >> 32) & 0x3ff;
				long lh = (newValue & 0xffffffff) >> 10; 
				long ll = newValue & 0x3ff;
				
				memory.setInt(relocationAddress,         (int) (sparc_sethi_g1 | hh));
				memory.setInt(relocationAddress.add(4),  (int) (sparc_sethi_g5 | lh));
				memory.setInt(relocationAddress.add(8),  (int) (sparc_or_g1_immed_g1 | hl));
				memory.setInt(relocationAddress.add(12), (int) (sparc_or_g5_immed_g5 | ll));
				memory.setInt(relocationAddress.add(16),       (sparc_sllx_g1_0x20));
				memory.setInt(relocationAddress.add(20),       (sparc_jmpl_g1_g5));
				memory.setInt(relocationAddress.add(24),        sparc_nop);
				break;

			case R_SPARC_PLT64:

			default:
				// other relocations handled by base SPARC relocation handler, including marking unhandled relocations
				return super.relocate(elfRelocationContext, relocation, type, relocationAddress, sym, symbolAddr, symbolValue, symbolName);
						
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}
}
