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
		boolean handleMachine = elf.e_machine() == ElfConstants.EM_SPARC ||
				elf.e_machine() == ElfConstants.EM_SPARC32PLUS ||
				elf.e_machine() == ElfConstants.EM_SPARCV9;
		return handleMachine && elf.is32Bit();
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

		int symbolIndex = relocation.getSymbolIndex();
		int oldValue = memory.getInt(relocationAddress);
		long newValue = 0;
		int mask = 0;
		int byteLength = 4; // most relocations affect 4-bytes (change if different)
		
		// Handle relative relocations that do not require symbolAddr or symbolValue 
		switch (type) {
			case R_SPARC_RELATIVE:
				newValue = elfRelocationContext.getImageBaseWordAdjustmentOffset() + addend;
				memory.setInt(relocationAddress, (int) newValue);
				return new RelocationResult(Status.APPLIED, byteLength);
				
			case R_SPARC_COPY:
				markAsUnsupportedCopy(program, relocationAddress, type, symbolName, symbolIndex,
					sym.getSize(), elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
				
			default:
				break;
		}
		
		// Check for unresolved symbolAddr and symbolValue required by remaining relocation types handled below
		if (handleUnresolvedSymbol(elfRelocationContext, relocation, relocationAddress)) {
			return RelocationResult.FAILURE;
		}
	
		// Relocation docs: https://docs.oracle.com/cd/E19120-01/open.solaris/819-0690/chapter6-24/index.html
		//

		switch (type) {
			case R_SPARC_8:
				newValue = symbolValue + addend;
				mask = 0x000000ff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;
				
			case R_SPARC_16:
				newValue = symbolValue + addend;
				mask = 0x0000ffff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;
				
			case R_SPARC_32:
				newValue = symbolValue + addend;
				memory.setInt(relocationAddress, (int) newValue);
				break;
				
			case R_SPARC_DISP8:
				newValue = (symbolValue + addend - pc);
				mask = 0x000000ff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;

			case R_SPARC_DISP16:
				newValue = (symbolValue + addend - pc);
				mask = 0x0000ffff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;
				
			case R_SPARC_DISP32:
				newValue = symbolValue + addend - pc;
				memory.setInt(relocationAddress, (int) newValue);
				break;
				
			case R_SPARC_WDISP30:
				newValue = (symbolValue + addend - pc) >>> 2;
				mask = 0x3fffffff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;
				
			case R_SPARC_WDISP22:
				newValue = (symbolValue + addend - pc) >>> 2;
				mask = 0x003fffff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;

			case R_SPARC_HI22:
				newValue = (symbolValue + addend) >>> 10;
				mask = 0x003fffff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;
				
			case R_SPARC_22:
				newValue = (symbolValue + addend);
				mask = 0x003fffff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;
				
			case R_SPARC_13:
				newValue = (symbolValue + addend);
				mask = 0x001fff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;

			case R_SPARC_LO10:
				newValue = (symbolValue + addend);
				mask = 0x000003ff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;
				
			case R_SPARC_PC10:
				newValue = (symbolValue + addend - pc);
				mask = 0x00003ff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;		
				
			case R_SPARC_PC22:
				newValue = (symbolValue + addend - pc) >> 10;
				mask = 0x003fffff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;
				
			case R_SPARC_JMP_SLOT:
				final int sparc_sethi_g1 = 0x03000000;         // sethi   %hi(0x123),g1
				final int sparc_jmpl_g1_immed_o1 = 0x81c06000; // jmpl    g1+0x123
				final int sparc_nop = 0x01000000;              // nop
				
				// this is not the way JMP_SLOT is always done, but it should work in all cases
				newValue = (symbolValue + addend);
				memory.setInt(relocationAddress, (int) (sparc_sethi_g1 | (newValue >> 10)));
				memory.setInt(relocationAddress.add(4), (int) (sparc_jmpl_g1_immed_o1 | (newValue & 0x3ff)));
				memory.setInt(relocationAddress.add(8), sparc_nop);
				break;

			case R_SPARC_GLOB_DAT:
				newValue = symbolValue;
				memory.setInt(relocationAddress, (int) newValue);
				break;
				
			case R_SPARC_UA32:
				newValue = symbolValue + addend;
				memory.setInt(relocationAddress, (int) newValue);
				break;

			case R_SPARC_10:
				newValue = (symbolValue + addend);
				mask = 0x0000003ff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;

			case R_SPARC_11:
				newValue = (symbolValue + addend);
				mask = 0x0000007ff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;

			case R_SPARC_HH22:
				newValue = (symbolValue + addend) >> 42;
				mask = 0x003fffff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;
				
			case R_SPARC_HM10:
				newValue = (symbolValue + addend) >> 32;
				mask = 0x000003ff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;

			case R_SPARC_LM22:
				newValue = (symbolValue + addend) >>> 10;
				mask = 0x003fffff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;
				
			case R_SPARC_PC_HH22:
				newValue = (symbolValue + addend - pc) >> 42;
				mask = 0x003fffff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;
				
			case R_SPARC_PC_HM10:
				newValue = (symbolValue + addend - pc) >> 32;
				mask = 0x000003ff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;
				
			case R_SPARC_PC_LM22:
				newValue = (symbolValue + addend - pc) >> 10;
				mask = 0x003fffff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;
				
			case R_SPARC_WDISP16:				
				newValue = (symbolValue + addend - pc) >>> 2;
				oldValue &= 0x303fff;
				newValue = ((newValue & 0xc000) << 6) | (newValue & 0x3fff);
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;

			case R_SPARC_WDISP19:
				newValue = (symbolValue + addend - pc) >>> 2;
				mask = 0x0007ffff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;
				
			case R_SPARC_7:
				newValue = (symbolValue + addend);
				mask = 0x0000007f;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;
				
			case R_SPARC_5:
				newValue = (symbolValue + addend);
				mask = 0x0000001f;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;
				
			case R_SPARC_6:
				newValue = (symbolValue + addend);
				mask = 0x0000003f;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;
				
			case R_SPARC_HIX22:
				newValue = ( (symbolValue + addend) ^ (-1) ) >> 10;
				mask = 0x003fffff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;

			case R_SPARC_LOX10:
				newValue = ( (symbolValue + addend) & 0x3ff ) | 0x1c00;
				mask = 0x001fff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;

			case R_SPARC_H44:
				newValue = (symbolValue + addend) >> 22;
				mask = 0x003fffff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;

			case R_SPARC_M44:
				newValue = (symbolValue + addend) >> 12;
				mask = 0x000003ff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;

			case R_SPARC_L44:
				newValue = (symbolValue + addend);
				mask = 0x00000fff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;

			case R_SPARC_UA16:
				newValue = (symbolValue + addend);
				mask = 0x0000ffff;
				oldValue &= ~(mask);
				newValue &= mask;
				memory.setInt(relocationAddress, oldValue | (int) newValue);
				break;

			default:
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}

}
