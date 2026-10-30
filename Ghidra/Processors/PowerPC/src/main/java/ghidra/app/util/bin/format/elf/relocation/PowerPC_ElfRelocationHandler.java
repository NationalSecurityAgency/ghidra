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

	// VLE split-immediate field masks (per Power ISA VLE Extension / binutils elf32-ppc.c)
	// split16a: UI[0:4] in instruction bits 20:16, UI[5:15] in bits 10:0
	private static final int VLE_SPLIT16A_MASK = 0x001F07FF; // (0xF800 << 5) | 0x7FF
	// split16d: UI[0:4] in instruction bits 25:21, UI[5:15] in bits 10:0
	private static final int VLE_SPLIT16D_MASK = 0x03E007FF; // (0xF800 << 10) | 0x7FF
	// BD24: 24-bit branch displacement, halfword-aligned, in bits 24:1
	private static final int VLE_BD24_MASK = 0x01FFFFFE;
	// BD15: 15-bit branch displacement in low halfword bits 15:1 (mask applied to full word)
	private static final int VLE_BD15_MASK = 0x0000FFFE;

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
	public int getRelrRelocationType() {
		return PowerPC_ElfRelocationType.R_PPC_RELATIVE.typeId;
	}

	/**
	 * Encode a 16-bit value into VLE split16a format (I16A form).
	 * Per the Power ISA VLE Extension, the 16-bit immediate is split:
	 *   UI[0:4]  -> instruction bits 20:16  (high 5 bits)
	 *   UI[5:15] -> instruction bits 10:0   (low 11 bits)
	 * Reference: binutils bfd/elf32-ppc.c ppc_elf_vle_split16()
	 */
	private static int encodeSplit16A(int instruction, int value16) {
		instruction &= ~VLE_SPLIT16A_MASK;
		instruction |= (value16 & 0xF800) << 5;   // high 5 bits shifted to bits 20:16
		instruction |= (value16 & 0x7FF);          // low 11 bits at bits 10:0
		return instruction;
	}

	/**
	 * Encode a 16-bit value into VLE split16d format (D/I16D form).
	 * Per the Power ISA VLE Extension, the 16-bit immediate is split:
	 *   UI[0:4]  -> instruction bits 25:21  (high 5 bits)
	 *   UI[5:15] -> instruction bits 10:0   (low 11 bits)
	 * Reference: binutils bfd/elf32-ppc.c ppc_elf_vle_split16()
	 */
	private static int encodeSplit16D(int instruction, int value16) {
		instruction &= ~VLE_SPLIT16D_MASK;
		instruction |= (value16 & 0xF800) << 10;  // high 5 bits shifted to bits 25:21
		instruction |= (value16 & 0x7FF);          // low 11 bits at bits 10:0
		return instruction;
	}

	/**
	 * Determine the SDA base value for a VLE SDAREL relocation based on the memory block
	 * containing the target symbol.
	 * @return SDA base offset, or null on failure (error already marked)
	 */
	private Integer getSdaBaseForBlock(PowerPC_ElfRelocationContext elfRelocationContext,
			MemoryBlock block, Program program, Address relocationAddress,
			PowerPC_ElfRelocationType type, String symbolName, int symbolIndex) {
		if (block != null) {
			String blockName = block.getName();
			if (".sdata".equals(blockName) || ".sbss".equals(blockName)) {
				return elfRelocationContext.getSDABase();
			}
			if (".sdata2".equals(blockName) || ".sbss2".equals(blockName)) {
				return elfRelocationContext.getSDA2Base();
			}
		}
		markAsError(program, relocationAddress, type, symbolName, symbolIndex,
			"Failed to identify SDA base for VLE SDAREL relocation",
			elfRelocationContext.getLog());
		return null;
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
		
		long relocbase = elfRelocationContext.getImageBaseWordAdjustmentOffset();
		
		int newValue = 0;
		int byteLength = 4; // most relocations affect 4-bytes (change if different)
		
		// Handle relative relocations that do not require symbolAddr or symbolValue 
		switch (type) {

			case R_PPC_RELATIVE:
				newValue = (int) relocbase + addend;
				memory.setInt(relocationAddress, newValue);
				return new RelocationResult(Status.APPLIED, byteLength);
				
			case R_PPC_COPY:
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

		switch (type) {
			
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
				newValue = (int) symbolValue + addend;
				memory.setShort(relocationAddress, (short) newValue);
				byteLength = 2;
				break;
			case R_PPC_ADDR16_LO:
				if (sym.isSection() && sym.getValue() != 0 &&
					Long.compareUnsigned(symbolValue, relocbase) > 0 &&
					Long.compareUnsigned(symbolValue, relocbase + addend) <= 0) {
					/**
					 * (freebsd) Addend values are sometimes relative to sections in rela,
					 * where in reality they are relative to relocbase.  Detect this condition.
					 */
					symbolValue = (int) relocbase;
				}
				newValue = (int) (symbolValue + addend);
				memory.setShort(relocationAddress, (short) newValue);
				byteLength = 2;
				break;
			case R_PPC_ADDR16_HI:
				newValue = ((int) symbolValue + addend) >> 16;
				memory.setShort(relocationAddress, (short) newValue);
				byteLength = 2;
				break;
			case R_PPC_ADDR16_HA:
				if (sym.isSection() && sym.getValue() != 0 &&
					Long.compareUnsigned(symbolValue, relocbase) > 0 &&
					Long.compareUnsigned(symbolValue, relocbase + addend) <= 0) {
					/**
					 * (freebsd) Addend values are sometimes relative to sections in rela,
					 * where in reality they are relative to relocbase.  Detect this condition.
					 */
					symbolValue = (int) relocbase;
				}
				newValue = (int) (symbolValue + addend);
				newValue = (newValue >> 16) + ((newValue & 0x8000) != 0 ? 1 : 0);
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
			// =================================================================
			// VLE (Variable-Length Encoding) Relocations (types 216-232)
			// Per Power ISA VLE Extension and binutils bfd/elf32-ppc.c
			// =================================================================

			// --- VLE PC-relative branches ---

			case R_PPC_VLE_REL8: {
				// 8-bit PC-relative branch displacement (se_b, se_bc forms).
				// 16-bit instruction; 8-bit signed displacement in bits 7:0,
				// halfword-aligned (value includes implicit <<1).
				// HOW: size=2, bitsize=8, mask=0xFF, rightshift=1
				int displacement8 = (int) symbolValue + addend - offset;
				short oldInsn16 = memory.getShort(relocationAddress);
				short newInsn16 = (short) ((oldInsn16 & 0xFF00) |
					((displacement8 >> 1) & 0xFF));
				memory.setShort(relocationAddress, newInsn16);
				byteLength = 2;
				break;
			}

			case R_PPC_VLE_REL15:
				// 15-bit PC-relative branch displacement (e_bc form).
				// 32-bit instruction; displacement in bits 16:30 (ISA) = bits 15:1.
				// Halfword-aligned; mask 0xFFFE on lower 16 bits.
				newValue = (int) symbolValue + addend - offset;
				newValue = (oldValue & ~VLE_BD15_MASK) | (newValue & VLE_BD15_MASK);
				memory.setInt(relocationAddress, newValue);
				break;

			case R_PPC_VLE_REL24:
				// 24-bit PC-relative branch displacement (e_b, e_bl forms).
				// 32-bit instruction; 24-bit displacement in bits 1:24 (halfword-aligned).
				// HOW: bitsize=25, mask=0x1FFFFFE
				newValue = (int) symbolValue + addend - offset;
				newValue = (oldValue & ~VLE_BD24_MASK) | (newValue & VLE_BD24_MASK);
				memory.setInt(relocationAddress, newValue);
				break;

			// --- VLE absolute 16-bit (LO/HI/HA) ---

			case R_PPC_VLE_LO16A:
				// Low 16 bits of (S + A) in split16a (I16A) format.
				newValue = (int) (symbolValue + addend);
				memory.setInt(relocationAddress,
					encodeSplit16A(oldValue, newValue & 0xFFFF));
				break;

			case R_PPC_VLE_LO16D:
				// Low 16 bits of (S + A) in split16d (D) format.
				newValue = (int) (symbolValue + addend);
				memory.setInt(relocationAddress,
					encodeSplit16D(oldValue, newValue & 0xFFFF));
				break;

			case R_PPC_VLE_HI16A:
				// High 16 bits of (S + A) in split16a format.
				newValue = (int) ((symbolValue + addend) >> 16);
				memory.setInt(relocationAddress,
					encodeSplit16A(oldValue, newValue & 0xFFFF));
				break;

			case R_PPC_VLE_HI16D:
				// High 16 bits of (S + A) in split16d format.
				newValue = (int) ((symbolValue + addend) >> 16);
				memory.setInt(relocationAddress,
					encodeSplit16D(oldValue, newValue & 0xFFFF));
				break;

			case R_PPC_VLE_HA16A:
				// High adjusted 16 bits of (S + A) in split16a format.
				// "Adjusted" means +0x8000 before shift to account for sign
				// extension when the low 16 bits are later added via e_add16i.
				newValue = (int) (symbolValue + addend);
				newValue = (newValue >> 16) + ((newValue & 0x8000) != 0 ? 1 : 0);
				memory.setInt(relocationAddress,
					encodeSplit16A(oldValue, newValue & 0xFFFF));
				break;

			case R_PPC_VLE_HA16D:
				// High adjusted 16 bits of (S + A) in split16d format.
				newValue = (int) (symbolValue + addend);
				newValue = (newValue >> 16) + ((newValue & 0x8000) != 0 ? 1 : 0);
				memory.setInt(relocationAddress,
					encodeSplit16D(oldValue, newValue & 0xFFFF));
				break;

			// --- VLE SDA21 ---

			case R_PPC_VLE_SDA21:
			case R_PPC_VLE_SDA21_LO: {
				// VLE SDA21 relocation for e_add16i instruction.
				// 16-bit displacement relative to SDA base in bits 16:31.
				// Register base determined by section (.sdata→r13, .sdata2→r2).
				MemoryBlock sdaBlock = memory.getBlock(symbolAddr);
				Integer vleSdaBase = null;

				if (sdaBlock != null) {
					String sdaBlockName = sdaBlock.getName();
					if (".sdata".equals(sdaBlockName) || ".sbss".equals(sdaBlockName)) {
						vleSdaBase = elfRelocationContext.getSDABase();
					}
					else if (".sdata2".equals(sdaBlockName) ||
						".sbss2".equals(sdaBlockName)) {
						vleSdaBase = elfRelocationContext.getSDA2Base();
					}
				}
				if (vleSdaBase == null) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"Failed to identify SDA base for VLE SDA21 relocation",
						elfRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}
				newValue = (int) symbolValue + addend - vleSdaBase;
				// Encode in low 16 bits of the instruction word
				newValue = (oldValue & 0xFFFF0000) | (newValue & 0xFFFF);
				memory.setInt(relocationAddress, newValue);
				break;
			}

			// --- VLE SDA-relative 16-bit (split-immediate) ---

			case R_PPC_VLE_SDAREL_LO16A: {
				// Low 16 bits of (S + A - SDA_BASE) in split16a format.
				MemoryBlock sdarelBlock = memory.getBlock(symbolAddr);
				Integer sdarelBase = getSdaBaseForBlock(elfRelocationContext, sdarelBlock,
					program, relocationAddress, type, symbolName, symbolIndex);
				if (sdarelBase == null) {
					return RelocationResult.FAILURE;
				}
				newValue = (int) (symbolValue + addend - sdarelBase);
				memory.setInt(relocationAddress,
					encodeSplit16A(oldValue, newValue & 0xFFFF));
				break;
			}

			case R_PPC_VLE_SDAREL_LO16D: {
				// Low 16 bits of (S + A - SDA_BASE) in split16d format.
				MemoryBlock sdarelBlock = memory.getBlock(symbolAddr);
				Integer sdarelBase = getSdaBaseForBlock(elfRelocationContext, sdarelBlock,
					program, relocationAddress, type, symbolName, symbolIndex);
				if (sdarelBase == null) {
					return RelocationResult.FAILURE;
				}
				newValue = (int) (symbolValue + addend - sdarelBase);
				memory.setInt(relocationAddress,
					encodeSplit16D(oldValue, newValue & 0xFFFF));
				break;
			}

			case R_PPC_VLE_SDAREL_HI16A: {
				// High 16 bits of (S + A - SDA_BASE) in split16a format.
				MemoryBlock sdarelBlock = memory.getBlock(symbolAddr);
				Integer sdarelBase = getSdaBaseForBlock(elfRelocationContext, sdarelBlock,
					program, relocationAddress, type, symbolName, symbolIndex);
				if (sdarelBase == null) {
					return RelocationResult.FAILURE;
				}
				newValue = (int) ((symbolValue + addend - sdarelBase) >> 16);
				memory.setInt(relocationAddress,
					encodeSplit16A(oldValue, newValue & 0xFFFF));
				break;
			}

			case R_PPC_VLE_SDAREL_HI16D: {
				// High 16 bits of (S + A - SDA_BASE) in split16d format.
				MemoryBlock sdarelBlock = memory.getBlock(symbolAddr);
				Integer sdarelBase = getSdaBaseForBlock(elfRelocationContext, sdarelBlock,
					program, relocationAddress, type, symbolName, symbolIndex);
				if (sdarelBase == null) {
					return RelocationResult.FAILURE;
				}
				newValue = (int) ((symbolValue + addend - sdarelBase) >> 16);
				memory.setInt(relocationAddress,
					encodeSplit16D(oldValue, newValue & 0xFFFF));
				break;
			}

			case R_PPC_VLE_SDAREL_HA16A: {
				// High adjusted 16 bits of (S + A - SDA_BASE) in split16a format.
				MemoryBlock sdarelBlock = memory.getBlock(symbolAddr);
				Integer sdarelBase = getSdaBaseForBlock(elfRelocationContext, sdarelBlock,
					program, relocationAddress, type, symbolName, symbolIndex);
				if (sdarelBase == null) {
					return RelocationResult.FAILURE;
				}
				newValue = (int) (symbolValue + addend - sdarelBase);
				newValue = (newValue >> 16) + ((newValue & 0x8000) != 0 ? 1 : 0);
				memory.setInt(relocationAddress,
					encodeSplit16A(oldValue, newValue & 0xFFFF));
				break;
			}

			case R_PPC_VLE_SDAREL_HA16D: {
				// High adjusted 16 bits of (S + A - SDA_BASE) in split16d format.
				MemoryBlock sdarelBlock = memory.getBlock(symbolAddr);
				Integer sdarelBase = getSdaBaseForBlock(elfRelocationContext, sdarelBlock,
					program, relocationAddress, type, symbolName, symbolIndex);
				if (sdarelBase == null) {
					return RelocationResult.FAILURE;
				}
				newValue = (int) (symbolValue + addend - sdarelBase);
				newValue = (newValue >> 16) + ((newValue & 0x8000) != 0 ? 1 : 0);
				memory.setInt(relocationAddress,
					encodeSplit16D(oldValue, newValue & 0xFFFF));
				break;
			}

			case R_PPC_EMB_SDA21:
				// NOTE: PPC EABI V1.0 specifies this relocation on a 24-bit field address while 
				// GNU assumes a 32-bit field address.  We cope with this difference by 
				// forcing a 32-bit alignment of the relocation address. 
				long alignedRelocOffset = relocationAddress.getOffset() & ~3;
				relocationAddress = relocationAddress.getNewAddress(alignedRelocOffset);

				oldValue = memory.getInt(relocationAddress);

				MemoryBlock block = memory.getBlock(symbolAddr);
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
