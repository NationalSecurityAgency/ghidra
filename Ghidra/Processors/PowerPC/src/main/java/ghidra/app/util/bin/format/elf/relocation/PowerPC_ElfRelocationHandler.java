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
import ghidra.app.util.bin.format.elf.extend.PowerPC_ElfExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.NotFoundException;

public class PowerPC_ElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_PPC && elf.is32Bit();
	}

	@Override
	public void relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation,
			Address relocationAddress) throws MemoryAccessException, NotFoundException {

		ElfHeader elf = elfRelocationContext.getElfHeader();
		if (elf.e_machine() != ElfConstants.EM_PPC || !elf.is32Bit()) {
			return;
		}

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		int type = relocation.getType();
		if (type == PowerPC_ElfRelocationConstants.R_PPC_NONE) {
			return;
		}
		int symbolIndex = relocation.getSymbolIndex();

		Language language = elfRelocationContext.getProgram().getLanguage();
		if (!"PowerPC".equals(language.getProcessor().toString()) ||
			language.getLanguageDescription().getSize() != 32) {
			markAsError(program, relocationAddress, Long.toString(type), null,
				"Unsupported language for 32-bit PowerPC relocation",
				elfRelocationContext.getLog());
		}

		// NOTE: Based upon glibc source it appears that PowerPC only uses RELA relocations
		int addend = (int) relocation.getAddend();

		int offset = (int) relocationAddress.getOffset();

		ElfSymbol sym = elfRelocationContext.getSymbol(symbolIndex);

//		if (sym.isLocal() && sym.getSectionHeaderIndex() != ElfSectionHeaderConstants.SHN_UNDEF) {
//
//			// see glibc - sysdeps/powerpc/powerpc32/dl-machine.h elf_machine_rela
//			
//			// TODO: Unclear if this logic is complete.  Need to find example where this is necessary.
//
//			// Relocation addend already includes original symbol value but needs to account 
//			// for any image base adjustment
//			symbolValue = (int) elfRelocationContext.getImageBaseWordAdjustmentOffset();
//		}
//		else {
		Address symbolAddr = (elfRelocationContext.getSymbolAddress(sym));
		int symbolValue = (int) elfRelocationContext.getSymbolValue(sym);
//		}
		String symbolName = sym.getNameAsString();

		int oldValue = memory.getInt(relocationAddress);
		int newValue = 0;

		switch (type) {
			case PowerPC_ElfRelocationConstants.R_PPC_COPY:
				markAsWarning(program, relocationAddress, "R_PPC_COPY", symbolName,
					symbolIndex, "Runtime copy not supported", elfRelocationContext.getLog());
				break;
			case PowerPC_ElfRelocationConstants.R_PPC_ADDR32:
			case PowerPC_ElfRelocationConstants.R_PPC_UADDR32:
			case PowerPC_ElfRelocationConstants.R_PPC_GLOB_DAT:
				newValue = symbolValue + addend;
				memory.setInt(relocationAddress, newValue);
				if (addend != 0) {
					warnExternalOffsetRelocation(program, relocationAddress,
						symbolAddr, symbolName, addend, elfRelocationContext.getLog());
					applyComponentOffsetPointer(program, relocationAddress, addend);
				}
				break;
			case PowerPC_ElfRelocationConstants.R_PPC_ADDR24:
				newValue = (symbolValue + addend) >> 2;
				newValue = (oldValue & ~PowerPC_ElfRelocationConstants.PPC_LOW24) | (newValue << 2);
				memory.setInt(relocationAddress, newValue);
				break;
			case PowerPC_ElfRelocationConstants.R_PPC_ADDR16:
			case PowerPC_ElfRelocationConstants.R_PPC_UADDR16:
			case PowerPC_ElfRelocationConstants.R_PPC_ADDR16_LO:
				newValue = symbolValue + addend;
				memory.setShort(relocationAddress, (short) newValue);
				break;
			case PowerPC_ElfRelocationConstants.R_PPC_ADDR16_HI:
				newValue = (symbolValue + addend) >> 16;
				memory.setShort(relocationAddress, (short) newValue);
				break;
			/**
			 * 
			R_POWERPC_ADDR16_HA: ((Symbol + Addend + 0x8000) >> 16) & 0xffff
			static inline void addr16_ha(unsigned char* view, Address value)
			{ This::addr16_hi(view, value + 0x8000); }
			
			static inline void
			addr16_hi(unsigned char* view, Address value)
			{ This::template rela<16,16>(view, 16, 0xffff, value + 0x8000, CHECK_NONE); }
			
			rela(unsigned char* view,
			unsigned int right_shift,
			typename elfcpp::Valtype_base<fieldsize>::Valtype dst_mask,
			Address value,
			Overflow_check overflow)
			{
			typedef typename elfcpp::Swap<fieldsize, big_endian>::Valtype Valtype;
			Valtype* wv = reinterpret_cast<Valtype*>(view);
			Valtype val = elfcpp::Swap<fieldsize, big_endian>::readval(wv);  // original bytes
			
			Valtype reloc = value >> 16;
			val &= ~0xffff;
			reloc &= dst_mask;
			elfcpp::Swap<fieldsize, big_endian>::writeval(wv, val | reloc); // write instr btes
			return overflowed<valsize>(value >> 16, overflow);
			}
			
			
			 */
			case PowerPC_ElfRelocationConstants.R_PPC_ADDR16_HA:
				newValue = (symbolValue + addend + 0x8000) >> 16;
				memory.setShort(relocationAddress, (short) newValue);
				break;
			case PowerPC_ElfRelocationConstants.R_PPC_ADDR14:
			case PowerPC_ElfRelocationConstants.R_PPC_ADDR14_BRTAKEN:
			case PowerPC_ElfRelocationConstants.R_PPC_ADDR14_BRNTAKEN:
				newValue = (symbolValue + addend) >> 2;
				newValue = (oldValue & ~PowerPC_ElfRelocationConstants.PPC_LOW14) |
					((newValue << 2) & PowerPC_ElfRelocationConstants.PPC_LOW24);
				memory.setInt(relocationAddress, newValue);
				break;
			case PowerPC_ElfRelocationConstants.R_PPC_REL24:
				newValue = (symbolValue + addend - offset) >> 2;
				newValue = ((newValue << 2) & PowerPC_ElfRelocationConstants.PPC_LOW24);
				newValue = (oldValue & ~PowerPC_ElfRelocationConstants.PPC_LOW24) | newValue;
				memory.setInt(relocationAddress, newValue);
				break;
			case PowerPC_ElfRelocationConstants.R_PPC_RELATIVE:
				newValue = (int) elfRelocationContext.getImageBaseWordAdjustmentOffset() + addend;
				memory.setInt(relocationAddress, newValue);
				break;
			case PowerPC_ElfRelocationConstants.R_PPC_REL32:
				newValue = (symbolValue + addend - offset);
				memory.setInt(relocationAddress, newValue);
				break;
			case PowerPC_ElfRelocationConstants.R_PPC_REL14:
			case PowerPC_ElfRelocationConstants.R_PPC_REL14_BRTAKEN:
			case PowerPC_ElfRelocationConstants.R_PPC_REL14_BRNTAKEN:
				newValue = (symbolValue + addend - offset) >> 2;
				newValue = (oldValue & ~PowerPC_ElfRelocationConstants.PPC_LOW14) |
					((newValue << 2) & PowerPC_ElfRelocationConstants.PPC_LOW14);
				memory.setInt(relocationAddress, newValue);
				break;
			case PowerPC_ElfRelocationConstants.R_PPC_JMP_SLOT:
				int value = symbolValue + addend;
				ElfDynamicTable dynamicTable = elf.getDynamicTable();
				if (dynamicTable != null &&
					dynamicTable.containsDynamicValue(PowerPC_ElfExtension.DT_PPC_GOT)) {
					// Old ABI - presence of dynamic entry DT_PPC_GOT used as indicator
					memory.setInt(relocationAddress, value);
					break;
				}
				int displacement = value - offset;
				if ((displacement << 6 >> 6) == displacement) {
					// inject branch relative instruction
					newValue = 0x48000000 | (displacement & 0x3fffffc);
					memory.setInt(relocationAddress, newValue);
				}
				else if ((value > 0 && value <= 0x1fffffc) || (value < 0 && value >= 0xfe000000)) {
					// inject branch absolute instruction
					newValue = 0x48000002 | (value & 0x3fffffc);
					memory.setInt(relocationAddress, newValue);
				}
				else {
					// TODO: Handle this case if needed - hopefully the EXTERNAL block is 
					// not too far away since a fabricated GOT would be in the same block
					// and we may only have room in the plt for two instructions.
					markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
						elfRelocationContext.getLog());
				}
				break;
			default:
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				break;
		}

	}

}
