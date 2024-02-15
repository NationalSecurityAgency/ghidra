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
import ghidra.app.util.bin.format.elf.extend.PowerPC_ElfExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;

public class PowerPC_ElfRelocationHandler extends
		AbstractElfRelocationHandler<PowerPC_ElfRelocationType, PowerPC_ElfRelocationContext> {

	// Masks for manipulating Power PC relocation targets
	private static final int PPC_WORD32 = 0xFFFFFFFF;
	private static final int PPC_WORD30 = 0xFFFFFFFC;
	private static final int PPC_LOW24 = 0x03FFFFFC;
	private static final int PPC_LOW14 = 0x0020FFFC;
	private static final int PPC_HALF16 = 0xFFFF;

	/**
	 * Constructor
	 */
	public PowerPC_ElfRelocationHandler() {
		super(PowerPC_ElfRelocationType.class);
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_PPC && elf.is32Bit();
	}

	@Override
	public PowerPC_ElfRelocationContext createRelocationContext(ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		return new PowerPC_ElfRelocationContext(this, loadHelper, symbolMap);
	}

	@Override
	protected RelocationResult relocate(PowerPC_ElfRelocationContext elfRelocationContext,
			ElfRelocation relocation, PowerPC_ElfRelocationType type, Address relocationAddress,
			ElfSymbol sym, Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		int symbolIndex = relocation.getSymbolIndex();

		// NOTE: Based upon glibc source it appears that PowerPC only uses RELA relocations
		int addend = (int) relocation.getAddend();

//		if (sym.isLocal() && sym.getSectionHeaderIndex() != ElfSectionHeaderConstants.SHN_UNDEF) {
//
//			// see glibc - sysdeps/powerpc/powerpc32/dl-machine.h elf_machine_rela
//			
//			// TODO: Unclear if this logic is complete.  Need to find example where this is necessary.
//
//			// Relocation addend already includes original symbol value but needs to account 
//			// for any image base adjustment
//			symbolValue = elfRelocationContext.getImageBaseWordAdjustmentOffset();
//		}

		int offset = (int) relocationAddress.getOffset();
		int oldValue = memory.getInt(relocationAddress);
		int newValue = 0;
		int byteLength = 4; // most relocations affect 4-bytes (change if different)

		switch (type) {
			case R_PPC_COPY:
				markAsWarning(program, relocationAddress, type, symbolName, symbolIndex,
					"Runtime copy not supported", elfRelocationContext.getLog());
				return RelocationResult.SKIPPED;
			case R_PPC_ADDR32:
			case R_PPC_UADDR32:
			case R_PPC_GLOB_DAT:
				newValue = (int) symbolValue + addend;
				memory.setInt(relocationAddress, newValue);
				if (symbolIndex != 0 && addend != 0 && !sym.isSection()) {
					warnExternalOffsetRelocation(program, relocationAddress, symbolAddr, symbolName,
						addend, elfRelocationContext.getLog());
					applyComponentOffsetPointer(program, relocationAddress, addend);
				}
				break;
			case R_PPC_ADDR24:
				newValue = ((int) symbolValue + addend) >> 2;
				newValue = (oldValue & ~PPC_LOW24) | (newValue << 2);
				memory.setInt(relocationAddress, newValue);
				break;
			case R_PPC_ADDR16:
			case R_PPC_UADDR16:
			case R_PPC_ADDR16_LO:
				newValue = (int) symbolValue + addend;
				memory.setShort(relocationAddress, (short) newValue);
				byteLength = 2;
				break;
			case R_PPC_ADDR16_HI:
				newValue = ((int) symbolValue + addend) >> 16;
				memory.setShort(relocationAddress, (short) newValue);
				byteLength = 2;
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
			case R_PPC_ADDR16_HA:
				newValue = ((int) symbolValue + addend + 0x8000) >> 16;
				memory.setShort(relocationAddress, (short) newValue);
				byteLength = 2;
				break;
			case R_PPC_ADDR14:
			case R_PPC_ADDR14_BRTAKEN:
			case R_PPC_ADDR14_BRNTAKEN:
				newValue = ((int) symbolValue + addend) >> 2;
				newValue = (oldValue & ~PPC_LOW14) | ((newValue << 2) & PPC_LOW24);
				memory.setInt(relocationAddress, newValue);
				break;
			case R_PPC_REL24:
				newValue = ((int) symbolValue + addend - offset) >> 2;
				newValue = ((newValue << 2) & PPC_LOW24);
				newValue = (oldValue & ~PPC_LOW24) | newValue;
				memory.setInt(relocationAddress, newValue);
				break;
			case R_PPC_RELATIVE:
				newValue = (int) elfRelocationContext.getImageBaseWordAdjustmentOffset() + addend;
				memory.setInt(relocationAddress, newValue);
				break;
			case R_PPC_REL32:
				newValue = ((int) symbolValue + addend - offset);
				memory.setInt(relocationAddress, newValue);
				break;
			case R_PPC_REL14:
			case R_PPC_REL14_BRTAKEN:
			case R_PPC_REL14_BRNTAKEN:
				newValue = ((int) symbolValue + addend - offset) >> 2;
				newValue = (oldValue & ~PPC_LOW14) | ((newValue << 2) & PPC_LOW14);
				memory.setInt(relocationAddress, newValue);
				break;
			case R_PPC_JMP_SLOT:
				int value = (int) symbolValue + addend;
				ElfDynamicTable dynamicTable =
					elfRelocationContext.getElfHeader().getDynamicTable();
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
					return RelocationResult.FAILURE;
				}
				break;
			case R_PPC_EMB_SDA21:
				// NOTE: PPC EABI V1.0 specifies this relocation on a 24-bit field address while 
				// GNU assumes a 32-bit field address.  We cope with this difference by 
				// forcing a 32-bit alignment of the relocation address. 
				long alignedRelocOffset = relocationAddress.getOffset() & ~3;
				relocationAddress = relocationAddress.getNewAddress(alignedRelocOffset);

				oldValue = memory.getInt(relocationAddress);

				Address symAddr = elfRelocationContext.getSymbolAddress(sym);
				MemoryBlock block = memory.getBlock(symAddr);
				Integer sdaBase = null;
				Integer gprID = null;

				if (block != null) {
					String blockName = block.getName();
					if (".sdata".equals(blockName) || ".sbss".equals(blockName)) {
						sdaBase = elfRelocationContext.getSDABase();
						gprID = 13;
					}
					else if (".sdata2".equals(blockName) || ".sbss2".equals(blockName)) {
						sdaBase = elfRelocationContext.getSDA2Base();
						gprID = 2;
					}
					else if (".PPC.EMB.sdata0".equals(blockName) ||
						".PPC.EMB.sbss0".equals(blockName)) {
						sdaBase = 0;
						gprID = 0;
					}
					else if (MemoryBlock.EXTERNAL_BLOCK_NAME.equals(blockName)) {
						markAsError(program, relocationAddress, type, symbolName, symbolIndex,
							"Unsupported relocation for external symbol",
							elfRelocationContext.getLog());
						return RelocationResult.FAILURE;
					}
				}
				if (gprID == null || sdaBase == null) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"Failed to identfy appropriate data block", elfRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}

				newValue = ((int) symbolValue - sdaBase + addend) & 0xffff;
				newValue |= gprID << 16;
				newValue |= oldValue & 0xffe00000;
				memory.setInt(relocationAddress, newValue);
				break;

			default:
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}

}
