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

public class SH_ElfRelocationHandler
		extends AbstractElfRelocationHandler<SH_ElfRelocationType, ElfRelocationContext<?>> {

	/**
	 * Constructor
	 */
	public SH_ElfRelocationHandler() {
		super(SH_ElfRelocationType.class);
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_SH && elf.is32Bit();
	}

	@Override
	protected RelocationResult relocate(ElfRelocationContext<?> elfRelocationContext,
			ElfRelocation relocation, SH_ElfRelocationType type, Address relocationAddress,
			ElfSymbol sym, Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		int addend = (int) relocation.getAddend();

		int offset = (int) relocationAddress.getOffset();
		int symbolIndex = relocation.getSymbolIndex();
		int newValue = 0;
		int oldValue;
		int byteLength = 4; // most relocations affect 4-bytes (change if different)

		// Handle relative relocations that do not require symbolAddr or symbolValue 
		switch (type) {

			case R_SH_RELATIVE:
				if (elfRelocationContext.extractAddend()) {
					addend = memory.getInt(relocationAddress);
				}
				newValue = (int) (elfRelocationContext.getImageBaseWordAdjustmentOffset()) + addend;
				memory.setInt(relocationAddress, newValue);
				return new RelocationResult(Status.APPLIED, byteLength);

			case R_SH_COPY:
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

		switch (type) {
			case R_SH_DIR32: // 32-bit absolute relocation w/ addend
				// Use partially-linked value as addend for RELA case when based on section 
				// symbol with a RELA addend of 0.
				if (elfRelocationContext.extractAddend() || (sym.isSection() && addend == 0)) {
					addend = memory.getInt(relocationAddress);
				}
				newValue = (int) symbolValue + addend;
				memory.setInt(relocationAddress, newValue);
				if (symbolIndex != 0 && addend != 0 && !sym.isSection()) {
					warnExternalOffsetRelocation(program, relocationAddress, symbolAddr, symbolName,
						addend, elfRelocationContext.getLog());
					applyComponentOffsetPointer(program, relocationAddress, addend);
				}
				break;
			case R_SH_GLOB_DAT:
			case R_SH_JMP_SLOT:
				// 32-bit absolute relocations, no addend
				memory.setInt(relocationAddress, (int) symbolValue);
				break;

			case R_SH_REL32:  // 32-bit PC relative relocation
				// Use partially-linked value as addend for RELA case when based on section 
				// symbol with a RELA addend of 0.
				if (elfRelocationContext.extractAddend() || (sym.isSection() && addend == 0)) {
					addend = memory.getInt(relocationAddress);
				}
				newValue = ((int) symbolValue + addend) - offset;
				memory.setInt(relocationAddress, newValue);
				break;

			case R_SH_DIR8WPN:  // 8-bit PC relative branch divided by 2
			case R_SH_DIR8WPZ:  // 8-bit PC unsigned-relative branch divided by 2
				oldValue = memory.getShort(relocationAddress);
				if (elfRelocationContext.extractAddend()) {
					addend = oldValue & 0xff;
					if (type == SH_ElfRelocationType.R_SH_DIR8WPN && (addend & 0x80) != 0) {
						addend -= 0x100; // sign-extend addend for R_SH_DIR8WPN
					}
				}
				newValue = (((int) symbolValue + addend) - offset) >> 1;
				newValue = (oldValue & 0xff00) | (newValue & 0xff);
				memory.setShort(relocationAddress, (short) newValue);
				byteLength = 2;
				break;

			case R_SH_IND12W:  // 12-bit PC relative branch divided by 2
				oldValue = memory.getShort(relocationAddress);
				if (elfRelocationContext.extractAddend()) {
					addend = oldValue & 0xfff;
					if ((addend & 0x800) != 0) {
						addend -= 0x1000; // sign-extend addend
					}
				}
				newValue = (((int) symbolValue + addend) - offset) >> 1;
				newValue = (oldValue & 0xf000) | (newValue & 0xfff);
				memory.setShort(relocationAddress, (short) newValue);
				byteLength = 2;
				break;

			case R_SH_DIR8WPL:  // 8-bit PC unsigned-relative branch divided by 4
				oldValue = memory.getShort(relocationAddress);
				if (elfRelocationContext.extractAddend()) {
					addend = oldValue & 0xff;
				}
				newValue = (((int) symbolValue + addend) - offset) >> 2;
				newValue = (oldValue & 0xff00) | (newValue & 0xff);
				memory.setShort(relocationAddress, (short) newValue);
				byteLength = 2;
				break;

			default:
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}

}
