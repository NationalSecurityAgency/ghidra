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
import ghidra.util.exception.NotFoundException;

public class X86_64_ElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_X86_64;
	}

	@Override
	public int getRelrRelocationType() {
		return X86_64_ElfRelocationConstants.R_X86_64_RELATIVE;
	}

	@Override
	public void relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation,
			Address relocationAddress) throws MemoryAccessException, NotFoundException {

		ElfHeader elf = elfRelocationContext.getElfHeader();
		if (elf.e_machine() != ElfConstants.EM_X86_64) {
			return;
		}

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		int type = relocation.getType();
		if (type == X86_64_ElfRelocationConstants.R_X86_64_NONE) {
			return;
		}

		int symbolIndex = relocation.getSymbolIndex();

		// addend is either pulled from the relocation or the bytes in memory
		long addend =
			relocation.hasAddend() ? relocation.getAddend() : memory.getLong(relocationAddress);

		ElfSymbol sym = null;
		long symbolValue = 0;
		Address symbolAddr = null;
		String symbolName = null;
		long symbolSize = 0;

		if (symbolIndex != 0) {
			sym = elfRelocationContext.getSymbol(symbolIndex);
		}

		if (sym != null) {
			symbolAddr = elfRelocationContext.getSymbolAddress(sym);
			symbolValue = elfRelocationContext.getSymbolValue(sym);
			symbolName = sym.getNameAsString();
			symbolSize = sym.getSize();
		}

		long offset = relocationAddress.getOffset();

		long value;

		boolean appliedSymbol = true;

		switch (type) {
			case X86_64_ElfRelocationConstants.R_X86_64_COPY:
				appliedSymbol = false;
				markAsWarning(program, relocationAddress, "R_X86_64_COPY", symbolName, symbolIndex,
					"Runtime copy not supported", elfRelocationContext.getLog());
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_64:
				if (addend != 0 && isUnsupportedExternalRelocation(program, relocationAddress,
					symbolAddr, symbolName, addend, elfRelocationContext.getLog())) {
					addend = 0; // prefer bad fixup for EXTERNAL over really-bad fixup
				}
				value = symbolValue + addend;
				memory.setLong(relocationAddress, value);
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_16:
				value = symbolValue + addend;
				value = value & 0xffff;
				memory.setShort(relocationAddress, (short) value);
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_8:
				value = symbolValue + addend;
				value = value & 0xff;
				memory.setByte(relocationAddress, (byte) value);
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_PC32:
				value = symbolValue + addend - offset;
				value = value & 0xffffffff;
				memory.setInt(relocationAddress, (int) value);
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_PC16:
				value = symbolValue + addend - offset;
				value = value & 0xffff;
				memory.setShort(relocationAddress, (short) value);
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_PC8:
				value = symbolValue + addend - offset;
				value = value & 0xff;
				memory.setByte(relocationAddress, (byte) value);
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_GOT32:
				value = symbolValue + addend;
				memory.setInt(relocationAddress, (int) value);
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_PLT32:
				value = symbolValue + addend - offset;
				memory.setInt(relocationAddress, (int) value);
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_GLOB_DAT:
			case X86_64_ElfRelocationConstants.R_X86_64_JUMP_SLOT:
				value = symbolValue + addend;
				memory.setLong(relocationAddress, value);
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_GOTOFF64:
				long dotgot = elfRelocationContext.getGOTValue();
				value = symbolValue + addend - dotgot;
				memory.setLong(relocationAddress, value);
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_32:  // this one complains for unsigned overflow
			case X86_64_ElfRelocationConstants.R_X86_64_32S: // this one complains for signed overflow
				symbolValue += addend;
				value = (symbolValue & 0xffffffff);
				memory.setInt(relocationAddress, (int) value);
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_SIZE32:
				value = symbolSize + addend;
				value = (value & 0xffffffff);
				memory.setInt(relocationAddress, (int) value);
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_SIZE64:
				value = symbolSize + addend;
				memory.setLong(relocationAddress, value);
				break;

			// Thread Local Symbol relocations (unimplemented concept)
			case X86_64_ElfRelocationConstants.R_X86_64_DTPMOD64:
				appliedSymbol = false;
				markAsWarning(program, relocationAddress, "R_X86_64_DTPMOD64", symbolName,
					symbolIndex, "Thread Local Symbol relocation not support",
					elfRelocationContext.getLog());
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_DTPOFF64:
				appliedSymbol = false;
				markAsWarning(program, relocationAddress, "R_X86_64_DTPOFF64", symbolName,
					symbolIndex, "Thread Local Symbol relocation not support",
					elfRelocationContext.getLog());
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_TPOFF64:
				appliedSymbol = false;
				markAsWarning(program, relocationAddress, "R_X86_64_TPOFF64", symbolName,
					symbolIndex, "Thread Local Symbol relocation not support",
					elfRelocationContext.getLog());
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_TLSDESC:
				appliedSymbol = false;
				markAsWarning(program, relocationAddress, "R_X86_64_TLSDESC", symbolName,
					symbolIndex, "Thread Local Symbol relocation not support",
					elfRelocationContext.getLog());
				break;

			// cases which do not use symbol value

			case X86_64_ElfRelocationConstants.R_X86_64_GOTPC32:
				appliedSymbol = false; // symbol not used, symbolIndex of 0 expected
				dotgot = elfRelocationContext.getGOTValue();
				value = dotgot + addend - offset;
				memory.setInt(relocationAddress, (int) value);
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_GOTPCREL:
				dotgot = elfRelocationContext.getGOTValue();
				value = symbolValue + dotgot + addend - offset;
				memory.setInt(relocationAddress, (int) value);
				break;

			case X86_64_ElfRelocationConstants.R_X86_64_RELATIVE:
				// word64 for LP64 and specifies word32 for ILP32,
				// we assume LP64 only.  We probably need a hybrid
				// variant to handle the ILP32 case.
			case X86_64_ElfRelocationConstants.R_X86_64_RELATIVE64:
				// dl_machine.h
				// value = (Elf64_64Addr) map->l_addr + reloc->r_addend
				appliedSymbol = false; // symbol not used, symbolIndex of 0 expected
				long imageBaseAdjustment = elfRelocationContext.getImageBaseWordAdjustmentOffset();
				if (elf.isPreLinked()) {
					// adjust prelinked value that is already in memory
					value = memory.getLong(relocationAddress) + imageBaseAdjustment;
				}
				else {
					value = addend + imageBaseAdjustment;
				}
				memory.setLong(relocationAddress, value);
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_IRELATIVE:
				value = addend + elfRelocationContext.getImageBaseWordAdjustmentOffset();
				memory.setLong(relocationAddress, value);
				break;

//			case ElfRelocationConstants.R_X86_64_TLSGD:
//			case ElfRelocationConstants.R_X86_64_TLSLD:
//			case ElfRelocationConstants.R_X86_64_DTPOFF32:
//			case ElfRelocationConstants.R_X86_64_GOTTPOFF:
//			case ElfRelocationConstants.R_X86_64_TPOFF32:
//			case ElfRelocationConstants.R_X86_64_GOTPC32_TLSDESC:
//			case ElfRelocationConstants.R_X86_64_TLSDESC_CALL:

			default:
				appliedSymbol = false;
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				break;
		}

		if (appliedSymbol && symbolIndex == 0) {
			markAsWarning(program, relocationAddress, Long.toString(type),
				"applied relocation with symbol-index of 0", elfRelocationContext.getLog());
		}

	}
}
