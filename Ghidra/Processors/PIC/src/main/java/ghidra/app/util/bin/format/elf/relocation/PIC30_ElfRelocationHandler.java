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
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;

public class PIC30_ElfRelocationHandler
		extends AbstractElfRelocationHandler<PIC30_ElfRelocationType, PIC30_ElfRelocationContext> {

	/**
	 * Constructor
	 */
	public PIC30_ElfRelocationHandler() {
		super(PIC30_ElfRelocationType.class);
	}

	// cached state assumes new instance created for each import use
	private Boolean isEDSVariant = null;

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_DSPIC30F;
	}

	@Override
	public PIC30_ElfRelocationContext createRelocationContext(ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		return new PIC30_ElfRelocationContext(this, loadHelper, symbolMap);
	}

	private boolean isEDSVariant(PIC30_ElfRelocationContext elfRelocationContext) {
		if (isEDSVariant == null) {
			// NOTE: non-EDS variants may improperly define DSRPAG 
			// in register space which should be corrected
			Register reg = elfRelocationContext.program.getRegister("DSRPAG");
			isEDSVariant = reg != null && reg.getAddressSpace().isMemorySpace();
		}
		return isEDSVariant;
	}

	@Override
	protected RelocationResult relocate(PIC30_ElfRelocationContext elfRelocationContext,
			ElfRelocation relocation, PIC30_ElfRelocationType type, Address relocationAddress,
			ElfSymbol elfSymbol, Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		int addend = (int) relocation.getAddend();

		long relocWordOffset = (int) relocationAddress.getAddressableWordOffset();

		int oldValue = memory.getInt(relocationAddress);
		short oldShortValue = memory.getShort(relocationAddress);
		int newValue;
		int byteLength = 2; // most relocations affect 2-bytes (change if different)

		switch (type) {
			case R_PIC30_16: // 2
			case R_PIC30_FILE_REG_WORD: // 6
				newValue = ((int) symbolValue + addend + oldShortValue);
				memory.setShort(relocationAddress, (short) newValue);
				break;
			case R_PIC30_32: // 3
				newValue = (int) symbolValue + addend + oldValue;
				memory.setInt(relocationAddress, newValue);
				byteLength = 4;
				break;
			case R_PIC30_FILE_REG_BYTE: // 4 short
			case R_PIC30_FILE_REG: // 5 short
				int reloc = (int) symbolValue;
				reloc += addend;
				reloc += oldShortValue;
				reloc &= 0x1fff;
				newValue = reloc | (oldShortValue & ~0x1fff);
				memory.setShort(relocationAddress, (short) newValue);
				break;
			case R_PIC30_FILE_REG_WORD_WITH_DST: // 7
				reloc = (int) symbolValue >> 1;
				reloc += addend;
				reloc += oldValue >> 4;
				reloc &= 0x7fff;
				newValue = (reloc << 4) | (oldValue & ~0x7fff0);
				memory.setInt(relocationAddress, newValue);
				byteLength = 4;
				break;
			case R_PIC30_WORD: // 8
			case R_PIC30_WORD_TBLOFFSET: // 0x15
				reloc = (int) symbolValue;
				reloc += addend;
				reloc += oldValue >> 4;
				reloc &= 0xffff;
				newValue = (reloc << 4) | (oldValue & ~0x0ffff0);
				memory.setInt(relocationAddress, newValue);
				byteLength = 4;
				break;
			case R_PIC30_WORD_TBLPAGE: // 0x18
				reloc = (int) symbolValue >> 16;
				reloc += addend;
				reloc += oldValue >> 4;
				reloc &= 0xffff;
				if (isEDSVariant(elfRelocationContext)) {
					reloc |= 0x100;
				}
				newValue = (reloc << 4) | (oldValue & ~0x0ffff0);
				memory.setInt(relocationAddress, newValue);
				byteLength = 4;
				break;
			case R_PIC30_PCREL_BRANCH: // 0x1c
				newValue = (int) (symbolValue - relocWordOffset + oldShortValue - 2);
				newValue >>>= 1;
				memory.setShort(relocationAddress, (short) (newValue & 0xffff));
				break;
			default:
				markAsUnhandled(program, relocationAddress, type, relocation.getSymbolIndex(),
					symbolName, elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}

}
