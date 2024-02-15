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
import ghidra.app.util.bin.format.elf.extend.MSP430_ElfExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;

public class MSP430_ElfRelocationHandler
		extends AbstractElfRelocationHandler<MSP430_ElfRelocationType, ElfRelocationContext<?>> {

	/**
	 * Constructor
	 */
	public MSP430_ElfRelocationHandler() {
		super(MSP430_ElfRelocationType.class);
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return (elf.e_machine() == ElfConstants.EM_MSP430) && ((elf.e_flags() &
			MSP430_ElfExtension.E_MSP430_MACH) != MSP430_ElfExtension.E_MSP430_MACH_MSP430X);
	}

	@Override
	protected RelocationResult relocate(ElfRelocationContext<?> elfRelocationContext,
			ElfRelocation relocation, MSP430_ElfRelocationType type, Address relocationAddress,
			ElfSymbol sym, Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();
		int symbolIndex = relocation.getSymbolIndex();
		long addend = relocation.getAddend(); // will be 0 for REL case
		long offset = relocationAddress.getOffset();
		int byteLength;

		switch (type) {
			case R_MSP430_32:
				int newIntValue = (int) (symbolValue + addend);
				memory.setInt(relocationAddress, newIntValue);
				byteLength = 4;
				break;
			case R_MSP430_10_PCREL:
				short oldShortValue = memory.getShort(relocationAddress);
				oldShortValue &= 0xfc00;
				short newShortValue = (short) (symbolValue + addend - offset - 2);
				newShortValue >>= 1;
				newShortValue &= 0x3ff;
				newShortValue = (short) (oldShortValue | newShortValue);
				memory.setShort(relocationAddress, newShortValue);
				byteLength = 2;
				break;
			case R_MSP430_16:
				newShortValue = (short) (symbolValue + addend);
				memory.setShort(relocationAddress, newShortValue);
				byteLength = 2;
				break;
			//case TI_R_MSP430_16_PCREL:
			case R_MSP430_16_BYTE:
				newShortValue = (short) (symbolValue + addend);
				memory.setShort(relocationAddress, newShortValue);
				byteLength = 2;
				break;
			case R_MSP430_16_PCREL_BYTE:
				newShortValue = (short) (symbolValue + addend - offset);
				memory.setShort(relocationAddress, newShortValue);
				byteLength = 2;
				break;
			//case TI_R_MSP430_2X_PCREL:
			//case TI_R_MSP430_RL_PCREL:
			case R_MSP430_8:
				byte newByteValue = (byte) (symbolValue + addend);
				memory.setByte(relocationAddress, newByteValue);
				byteLength = 1;
				break;
			//case TI_R_MSP430_SYM_DIFF:
			//case TI_R_MSP430_SET_ULEB128:
			//case TI_R_MSP430_SUB_ULEB128:
			default:
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}
}
