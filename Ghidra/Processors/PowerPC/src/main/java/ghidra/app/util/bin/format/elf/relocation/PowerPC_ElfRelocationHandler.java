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

import java.math.BigInteger;
import java.util.Map;

import com.google.common.base.Predicate;

import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.extend.PowerPC_ElfExtension;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;

public class PowerPC_ElfRelocationHandler extends ElfRelocationHandler {

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
	public RelocationResult relocate(ElfRelocationContext elfRelocationContext,
			ElfRelocation relocation,
			Address relocationAddress) throws MemoryAccessException, NotFoundException {

		PowerPC_ElfRelocationContext ppcRelocationContext =
			(PowerPC_ElfRelocationContext) elfRelocationContext;

		ElfHeader elf = ppcRelocationContext.getElfHeader();
		if (elf.e_machine() != ElfConstants.EM_PPC || !elf.is32Bit()) {
			return RelocationResult.FAILURE;
		}

		Program program = ppcRelocationContext.getProgram();
		Memory memory = program.getMemory();

		int type = relocation.getType();
		if (type == PowerPC_ElfRelocationConstants.R_PPC_NONE) {
			return RelocationResult.SKIPPED;
		}
		int symbolIndex = relocation.getSymbolIndex();

		Language language = ppcRelocationContext.getProgram().getLanguage();
		if (!"PowerPC".equals(language.getProcessor().toString()) ||
			language.getLanguageDescription().getSize() != 32) {
			markAsError(program, relocationAddress, Long.toString(type), null,
				"Unsupported language for 32-bit PowerPC relocation",
				ppcRelocationContext.getLog());
			// TODO: should we return failure status?
		}

		// NOTE: Based upon glibc source it appears that PowerPC only uses RELA relocations
		int addend = (int) relocation.getAddend();

		int offset = (int) relocationAddress.getOffset();

		ElfSymbol sym = elfRelocationContext.getSymbol(symbolIndex); // may be null

//		if (sym.isLocal() && sym.getSectionHeaderIndex() != ElfSectionHeaderConstants.SHN_UNDEF) {
//
//			// see glibc - sysdeps/powerpc/powerpc32/dl-machine.h elf_machine_rela
//			
//			// TODO: Unclear if this logic is complete.  Need to find example where this is necessary.
//
//			// Relocation addend already includes original symbol value but needs to account 
//			// for any image base adjustment
//			symbolValue = (int) ppcRelocationContext.getImageBaseWordAdjustmentOffset();
//		}
//		else {
		Address symbolAddr = (elfRelocationContext.getSymbolAddress(sym));
		int symbolValue = (int) elfRelocationContext.getSymbolValue(sym);
//		}
		String symbolName = elfRelocationContext.getSymbolName(symbolIndex);

		int oldValue = memory.getInt(relocationAddress);
		int newValue = 0;

		int byteLength = 4; // most relocations affect 4-bytes (change if different)

		switch (type) {
			case PowerPC_ElfRelocationConstants.R_PPC_COPY:
				markAsWarning(program, relocationAddress, "R_PPC_COPY", symbolName,
					symbolIndex, "Runtime copy not supported", elfRelocationContext.getLog());
				return RelocationResult.SKIPPED;
			case PowerPC_ElfRelocationConstants.R_PPC_ADDR32:
			case PowerPC_ElfRelocationConstants.R_PPC_UADDR32:
			case PowerPC_ElfRelocationConstants.R_PPC_GLOB_DAT:
				newValue = symbolValue + addend;
				memory.setInt(relocationAddress, newValue);
				if (symbolIndex != 0 && addend != 0 && !sym.isSection()) {
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
				byteLength = 2;
				break;
			case PowerPC_ElfRelocationConstants.R_PPC_ADDR16_HI:
				newValue = (symbolValue + addend) >> 16;
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
			case PowerPC_ElfRelocationConstants.R_PPC_ADDR16_HA:
				newValue = (symbolValue + addend + 0x8000) >> 16;
				memory.setShort(relocationAddress, (short) newValue);
				byteLength = 2;
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
				newValue = (int) ppcRelocationContext.getImageBaseWordAdjustmentOffset() + addend;
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
						ppcRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}
				break;
			case PowerPC_ElfRelocationConstants.R_PPC_EMB_SDA21:
				// NOTE: PPC EABI V1.0 specifies this relocation on a 24-bit field address while 
				// GNU assumes a 32-bit field address.  We cope with this difference by 
				// forcing a 32-bit alignment of the relocation address. 
				long alignedRelocOffset = relocationAddress.getOffset() & ~3;
				relocationAddress = relocationAddress.getNewAddress(alignedRelocOffset);

				oldValue = memory.getInt(relocationAddress);

				Address symAddr = ppcRelocationContext.getSymbolAddress(sym);
				MemoryBlock block = memory.getBlock(symAddr);
				Integer sdaBase = null;
				Integer gprID = null;

				if (block != null) {
					String blockName = block.getName();
					if (".sdata".equals(blockName) || ".sbss".equals(blockName)) {
						sdaBase = ppcRelocationContext.getSDABase();
						gprID = 13;
					}
					else if (".sdata2".equals(blockName) || ".sbss2".equals(blockName)) {
						sdaBase = ppcRelocationContext.getSDA2Base();
						gprID = 2;
					}
					else if (".PPC.EMB.sdata0".equals(blockName) ||
						".PPC.EMB.sbss0".equals(blockName)) {
						sdaBase = 0;
						gprID = 0;
					}
					else if (MemoryBlock.EXTERNAL_BLOCK_NAME.equals(blockName)) {
						markAsError(program, relocationAddress, type, symbolName,
							"Unsupported relocation for external symbol",
							ppcRelocationContext.getLog());
						return RelocationResult.FAILURE;
					}
				}
				if (gprID == null || sdaBase == null) {
					markAsError(program, relocationAddress, type, symbolName,
						"Failed to identfy appropriate data block", ppcRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}

				newValue = (symbolValue - sdaBase + addend) & 0xffff;
				newValue |= gprID << 16;
				newValue |= oldValue & 0xffe00000;
				memory.setInt(relocationAddress, newValue);
				break;

			default:
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					ppcRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}

	/**
	 * <code>PowerPC_ElfRelocationContext</code> provides extended relocation context..
	 */
	private static class PowerPC_ElfRelocationContext extends ElfRelocationContext {

		private Integer sdaBase;
		private Integer sda2Base;

		protected PowerPC_ElfRelocationContext(ElfRelocationHandler handler,
				ElfLoadHelper loadHelper, Map<ElfSymbol, Address> symbolMap) {
			super(handler, loadHelper, symbolMap);
		}

		/**
		 * Get or establish _SDA_BASE_ value and apply as r13 context value to all memory blocks
		 * with execute permission.
		 * @return _SDA_BASE_ offset or null if unable to determine or establish
		 */
		Integer getSDABase() {
			if (sdaBase != null) {
				if (sdaBase == -1) {
					return null;
				}
				return sdaBase;
			}
			sdaBase = getBaseOffset("_SDA_BASE_", ".sdata", ".sbss");
			if (sdaBase == -1) {
				getLog().appendMsg("ERROR: failed to establish _SDA_BASE_");
				return null;
			}
			setRegisterContext("r13", BigInteger.valueOf(sdaBase), b -> b.isExecute());
			return sdaBase;
		}

		/**
		 * Get or establish _SDA2_BASE_ value and apply as r2 context value to all memory blocks
		 * with execute permission.
		 * @return _SDA2_BASE_ offset or null if unable to determine or establish
		 */
		Integer getSDA2Base() {
			if (sda2Base != null) {
				if (sda2Base == -1) {
					return null;
				}
				return sda2Base;
			}
			sda2Base = getBaseOffset("_SDA2_BASE_", ".sdata2", ".sbss2");
			if (sda2Base == -1) {
				getLog().appendMsg("ERROR: failed to establish _SDA2_BASE_");
				return null;
			}
			setRegisterContext("r2", BigInteger.valueOf(sda2Base), b -> b.isExecute());
			return sda2Base;
		}

		/**
		 * Apply register context to all memory blocks which satisfy blockPredicate check.
		 * @param regName register name
		 * @param value context value
		 * @param blockPredicate determine which memory blocks get context applied
		 */
		private void setRegisterContext(String regName, BigInteger value,
				Predicate<MemoryBlock> blockPredicate) {
			Register reg = program.getRegister(regName);
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				if (block.isExecute()) {
					try {
						program.getProgramContext().setValue(reg, block.getStart(), block.getEnd(),
							value);
					}
					catch (ContextChangeException e) {
						throw new AssertException(e); // no instructions should exist yet
					}
				}
			}
		}

		/**
		 * Establish base offset from symbol or range of specified memory blocks.
		 * @param symbolName base symbol name
		 * @param blockNames block names which may be used to establish base range
		 * @return base offset or -1 on failure
		 */
		private Integer getBaseOffset(String symbolName, String... blockNames) {

			MessageLog log = getLog();

			Symbol baseSymbol = SymbolUtilities.getLabelOrFunctionSymbol(program, symbolName,
				msg -> log.appendMsg(msg));
			if (baseSymbol != null) {
				int baseOffset = (int) baseSymbol.getAddress().getOffset();
				String absString = "";
				if (baseSymbol.isPinned()) {
					absString = "absolute ";
				}
				log.appendMsg(
					"Using " + absString + symbolName + " of 0x" + Integer.toHexString(baseOffset));
				return baseOffset;
			}

			Memory mem = program.getMemory();
			AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
			AddressSet blockSet = new AddressSet();
			for (String blockName : blockNames) {
				MemoryBlock block = mem.getBlock(blockName);
				if (block != null) {
					if (!block.getStart().getAddressSpace().equals(defaultSpace)) {
						log.appendMsg("ERROR: " + blockName + " not in default space");
						return -1;
					}
					blockSet.add(block.getStart(), block.getEnd());
				}
			}
			if (blockSet.isEmpty()) {
				return -1;
			}

			Address baseAddr = blockSet.getMinAddress();
			long range = blockSet.getMaxAddress().subtract(baseAddr) + 1;
			if (range > Short.MAX_VALUE) {
				// use aligned midpoint of range
				baseAddr = baseAddr.add((range / 2) & ~0x0f);
			}

			try {
				program.getSymbolTable().createLabel(baseAddr, symbolName, SourceType.ANALYSIS);
			}
			catch (InvalidInputException e) {
				throw new AssertException(e);
			}

			int baseOffset = (int) baseAddr.getOffset();
			log.appendMsg("Defined " + symbolName + " of 0x" + Integer.toHexString(baseOffset));
			return baseOffset;
		}

	}
}
