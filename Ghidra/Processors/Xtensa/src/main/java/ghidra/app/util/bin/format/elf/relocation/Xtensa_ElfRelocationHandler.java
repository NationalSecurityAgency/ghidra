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

public class Xtensa_ElfRelocationHandler
		extends AbstractElfRelocationHandler<Xtensa_ElfRelocationType, ElfRelocationContext<?>> {

	/* Xtensa processor ELF architecture-magic number */
	// EM_XTENSA is already definded
	public static final int EM_XTENSA_OLD = 0xABC7;

	/**
	 * Constructor
	 */
	public Xtensa_ElfRelocationHandler() {
		super(Xtensa_ElfRelocationType.class);
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_XTENSA || elf.e_machine() == EM_XTENSA_OLD;
	}

	@Override
	protected RelocationResult relocate(ElfRelocationContext<?> elfRelocationContext,
			ElfRelocation relocation, Xtensa_ElfRelocationType type, Address relocationAddress,
			ElfSymbol elfSymbol, Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		int addend = (int) relocation.getAddend();

		//int offset = (int) relocationAddress.getOffset();

		int byteLength = -1;
		int newValue;

		int diff_mask = 0;
		boolean neg = false;

		switch (type) {
			case R_XTENSA_32:
				newValue = memory.getInt(relocationAddress);
				newValue += (symbolValue + addend);
				memory.setInt(relocationAddress, newValue);
				byteLength = 4;
				break;

//			case R_XTENSA_RTLD:

			case R_XTENSA_RELATIVE:
				newValue = ((int) elfRelocationContext.getImageBaseWordAdjustmentOffset() + addend);
				memory.setInt(relocationAddress, newValue);
				byteLength = 4;
				break;

			case R_XTENSA_GLOB_DAT:
			case R_XTENSA_JMP_SLOT:
			case R_XTENSA_PLT:
				newValue = ((int) symbolValue + addend);
				memory.setInt(relocationAddress, newValue);
				byteLength = 4;
				break;

//			case R_XTENSA_OP0:
//			case R_XTENSA_OP1:
//			case R_XTENSA_OP2:
//			case R_XTENSA_ASM_EXPAND:
//			case R_XTENSA_ASM_SIMPLIFY:
//			case R_XTENSA_GNU_VTINHERIT:
//			case R_XTENSA_GNU_VTENTRY:

			case R_XTENSA_DIFF8:
				diff_mask = 0x7f;
				byteLength = 1;
				break;
			case R_XTENSA_DIFF16:
				diff_mask = 0x7fff;
				byteLength = 2;
				break;
			case R_XTENSA_DIFF32:
				diff_mask = 0x7fffffff;
				byteLength = 4;
				break;

//			case R_XTENSA_SLOT0_OP:
//			case R_XTENSA_SLOT1_OP:
//			case R_XTENSA_SLOT2_OP:
//			case R_XTENSA_SLOT3_OP:
//			case R_XTENSA_SLOT4_OP:
//			case R_XTENSA_SLOT5_OP:
//			case R_XTENSA_SLOT6_OP:
//			case R_XTENSA_SLOT7_OP:
//			case R_XTENSA_SLOT8_OP:
//			case R_XTENSA_SLOT9_OP:
//			case R_XTENSA_SLOT10_OP:
//			case R_XTENSA_SLOT11_OP:
//			case R_XTENSA_SLOT12_OP:
//			case R_XTENSA_SLOT13_OP:
//			case R_XTENSA_SLOT14_OP:
//			case R_XTENSA_SLOT0_ALT:
//			case R_XTENSA_SLOT1_ALT:
//			case R_XTENSA_SLOT2_ALT:
//			case R_XTENSA_SLOT3_ALT:
//			case R_XTENSA_SLOT4_ALT:
//			case R_XTENSA_SLOT5_ALT:
//			case R_XTENSA_SLOT6_ALT:
//			case R_XTENSA_SLOT7_ALT:
//			case R_XTENSA_SLOT8_ALT:
//			case R_XTENSA_SLOT9_ALT:
//			case R_XTENSA_SLOT10_ALT:
//			case R_XTENSA_SLOT11_ALT:
//			case R_XTENSA_SLOT12_ALT:
//			case R_XTENSA_SLOT13_ALT:
//			case R_XTENSA_SLOT14_ALT:

			case R_XTENSA_TLSDESC_FN:
			case R_XTENSA_TLSDESC_ARG:
			case R_XTENSA_TLS_DTPOFF:
			case R_XTENSA_TLS_TPOFF:
			case R_XTENSA_TLS_FUNC:
			case R_XTENSA_TLS_ARG:
			case R_XTENSA_TLS_CALL:
				markAsWarning(program, relocationAddress, type, symbolName,
					relocation.getSymbolIndex(), "Thread Local Symbol relocation not supported",
					elfRelocationContext.getLog());
				break;

			case R_XTENSA_NDIFF8:
				neg = true;
				// fall-through
			case R_XTENSA_PDIFF8:
				diff_mask = 0xff;
				byteLength = 1;
				break;
			case R_XTENSA_NDIFF16:
				neg = true;
				// fall-through
			case R_XTENSA_PDIFF16:
				diff_mask = 0xffff;
				byteLength = 2;
				break;
			case R_XTENSA_NDIFF32:
				neg = true;
				// fall-through
			case R_XTENSA_PDIFF32:
				diff_mask = 0xffffffff;
				byteLength = 4;
				break;
			default:
				markAsUnhandled(program, relocationAddress, type, relocation.getSymbolIndex(),
					symbolName, elfRelocationContext.getLog());
		}

		if (diff_mask != 0) {
			//TODO: Not sure if they can all be done here, handle DIFF relocations
			//See values: diff_mask, neg, and byteLength
			markAsUnhandled(program, relocationAddress, type, relocation.getSymbolIndex(),
				symbolName, elfRelocationContext.getLog());
			byteLength = -1; // not yet implemented
		}

		if (byteLength < 0) {
			return RelocationResult.UNSUPPORTED;
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}

}
