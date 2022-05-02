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
import ghidra.app.util.bin.format.elf.extend.PowerPC64_ElfExtension;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.*;
import ghidra.util.exception.NotFoundException;

public class PowerPC64_ElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_PPC64 && elf.is64Bit();
	}

	@Override
	public void relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation,
			Address relocationAddress) throws MemoryAccessException, NotFoundException {

		ElfHeader elf = elfRelocationContext.getElfHeader();
		if (elf.e_machine() != ElfConstants.EM_PPC64 || !elf.is64Bit()) {
			return;
		}

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		int type = relocation.getType();
		if (type == PowerPC64_ElfRelocationConstants.R_PPC64_NONE) {
			return;
		}
		int symbolIndex = relocation.getSymbolIndex();

		Language language = elfRelocationContext.getProgram().getLanguage();
		if (!"PowerPC".equals(language.getProcessor().toString()) ||
			language.getLanguageDescription().getSize() != 64) {
			markAsError(program, relocationAddress, Long.toString(type), null,
				"Unsupported language for 64-bit PowerPC relocation",
				elfRelocationContext.getLog());
		}

		// NOTE: Based upon glibc source it appears that PowerPC only uses RELA relocations
		long addend = relocation.getAddend();

		long offset = relocationAddress.getOffset();

		ElfSymbol sym = elfRelocationContext.getSymbol(symbolIndex);
		String symbolName = sym.getNameAsString();
		Address symbolAddr = elfRelocationContext.getSymbolAddress(sym);
		long symbolValue = elfRelocationContext.getSymbolValue(sym);

		int oldValue = memory.getInt(relocationAddress);
		int newValue = 0;

		// IMPORTANT NOTE:
		//   Handling of Object modules (*.o) is currently problematic since relocations
		//   which are fixing-up function references can refer to the TOC or OPD tables
		//   since function call stubs are not added until a full-link is performed.
		//   This can result in the code improperly flowing into these function
		//   linkage tables. Relocation R_PPC64_REL24 has been changed to attempt
		//   a work-around for local function call made via .opd entries.  Care must
		//   be taken not to do this for relocation types used within call stub code.

		// Obtain TOC base used by certain relocations
		long toc = 0;
		switch (type) {
			case PowerPC64_ElfRelocationConstants.R_PPC64_TOC16_LO:
			case PowerPC64_ElfRelocationConstants.R_PPC64_TOC16_HI:
			case PowerPC64_ElfRelocationConstants.R_PPC64_TOC16_HA:
			case PowerPC64_ElfRelocationConstants.R_PPC64_TOC16_LO_DS:
			case PowerPC64_ElfRelocationConstants.R_PPC64_TOC:

				MessageLog log = elfRelocationContext.getLog();
				Symbol tocBaseSym = SymbolUtilities.getLabelOrFunctionSymbol(program,
					PowerPC64_ElfExtension.TOC_BASE, err -> log.error("PPC_ELF", err));
				if (tocBaseSym == null) {
					markAsError(program, relocationAddress, type, symbolName,
						"TOC_BASE unknown", log);
					return;
				}
				toc = tocBaseSym.getAddress().getOffset();
				break;
			default:
		}

		switch (type) {
			case PowerPC64_ElfRelocationConstants.R_PPC64_COPY:
				markAsWarning(program, relocationAddress, "R_PPC64_COPY", symbolName,
					symbolIndex, "Runtime copy not supported", elfRelocationContext.getLog());
				break;
			case PowerPC64_ElfRelocationConstants.R_PPC64_ADDR32:
				newValue = (int) (symbolValue + addend);
				memory.setInt(relocationAddress, newValue);
				break;
			case PowerPC64_ElfRelocationConstants.R_PPC64_ADDR24:
				newValue = (int) ((symbolValue + addend) >> 2);
				newValue =
					(oldValue & ~PowerPC64_ElfRelocationConstants.PPC64_LOW24) | (newValue << 2);
				memory.setInt(relocationAddress, newValue);
				break;
			case PowerPC64_ElfRelocationConstants.R_PPC64_ADDR16:
				newValue = (int) (symbolValue + addend);
				memory.setShort(relocationAddress, (short) newValue);
				break;
			case PowerPC64_ElfRelocationConstants.R_PPC64_ADDR16_LO:
				newValue = (int) (symbolValue + addend);
				memory.setShort(relocationAddress, (short) newValue);
				break;
			case PowerPC64_ElfRelocationConstants.R_PPC64_TOC16_LO:
				newValue = (int) (symbolValue + addend - toc);
				memory.setShort(relocationAddress, (short) newValue);
				break;
			case PowerPC64_ElfRelocationConstants.R_PPC64_TOC16_LO_DS:
				newValue = (int) ((symbolValue + addend - toc) >> 2);
				newValue = ((oldValue >>> 16) & 0x3) | (newValue << 2);
				memory.setShort(relocationAddress, (short) newValue);
				break;
			case PowerPC64_ElfRelocationConstants.R_PPC64_ADDR16_HI:
				newValue = (int) (symbolValue + addend);
				newValue = ((newValue >> 16) & 0xFFFF);
				memory.setShort(relocationAddress, (short) newValue);
				break;
			case PowerPC64_ElfRelocationConstants.R_PPC64_TOC16_HI:
				newValue = (int) (symbolValue + addend - toc);
				newValue = ((newValue >> 16) & 0xFFFF);
				memory.setShort(relocationAddress, (short) newValue);
				break;
			case PowerPC64_ElfRelocationConstants.R_PPC64_ADDR16_HA:
				newValue = (int) (symbolValue + addend);
				newValue = ((newValue >> 16) + (((newValue & 0x8000) != 0) ? 1 : 0));
				memory.setShort(relocationAddress, (short) newValue);
				break;
			case PowerPC64_ElfRelocationConstants.R_PPC64_TOC16_HA:
				newValue = (int) (symbolValue + addend - toc);
				newValue = ((newValue >> 16) + (((newValue & 0x8000) != 0) ? 1 : 0));
				memory.setShort(relocationAddress, (short) newValue);
				break;
			case PowerPC64_ElfRelocationConstants.R_PPC64_ADDR14:
			case PowerPC64_ElfRelocationConstants.R_PPC64_ADDR14_BRTAKEN:
			case PowerPC64_ElfRelocationConstants.R_PPC64_ADDR14_BRNTAKEN:
				newValue = (int) ((symbolValue + addend) >> 2);
				newValue = (oldValue & ~PowerPC64_ElfRelocationConstants.PPC64_LOW14) |
					((newValue << 2) & PowerPC64_ElfRelocationConstants.PPC64_LOW24);
				memory.setInt(relocationAddress, newValue);
				break;
			case PowerPC64_ElfRelocationConstants.R_PPC64_REL24:

				// attempt to handle Object module case where referenced symbol resides within .opd
				symbolValue = fixupOPDSymbolValue(elfRelocationContext, sym);

				newValue = (int) ((symbolValue + addend - offset) >> 2);
				newValue = ((newValue << 2) & PowerPC64_ElfRelocationConstants.PPC64_LOW24);
				newValue = (oldValue & ~PowerPC64_ElfRelocationConstants.PPC64_LOW24) | newValue;
				memory.setInt(relocationAddress, newValue);
				break;
			case PowerPC64_ElfRelocationConstants.R_PPC64_RELATIVE:
				long value64 = elfRelocationContext.getImageBaseWordAdjustmentOffset() + addend;
				memory.setLong(relocationAddress, value64);
				break;
			case PowerPC64_ElfRelocationConstants.R_PPC64_REL32:
				newValue = (int) (symbolValue + addend - offset);
				memory.setInt(relocationAddress, newValue);
				break;
			case PowerPC64_ElfRelocationConstants.R_PPC64_REL14:
			case PowerPC64_ElfRelocationConstants.R_PPC64_REL14_BRTAKEN:
			case PowerPC64_ElfRelocationConstants.R_PPC64_REL14_BRNTAKEN:
				newValue = (int) (symbolValue + addend - offset) >> 2;
				newValue = (oldValue & ~PowerPC64_ElfRelocationConstants.PPC64_LOW14) |
					((newValue << 2) & PowerPC64_ElfRelocationConstants.PPC64_LOW14);
				memory.setInt(relocationAddress, newValue);
				break;
			case PowerPC64_ElfRelocationConstants.R_PPC64_JMP_SLOT:
				// TODO: do we need option to allow function descriptor
				// use - or not?  The EF_PPC64_ABI in e_flags is not reliable.
				Address functionDescriptorAddr = relocationAddress.getNewAddress(symbolValue);
				MemoryBlock block = memory.getBlock(functionDescriptorAddr);
				if (block == null) {
					throw new MemoryAccessException(
						"Function descriptor not found at: " + functionDescriptorAddr);
				}
				if (MemoryBlock.EXTERNAL_BLOCK_NAME.equals(block.getName())) {
					// If symbol is in EXTERNAL block, we don't have descriptor entry;
					// just fill-in first slot with EXTERNAL address
					memory.setLong(relocationAddress, symbolValue);
				}
				else {
					// Copy function descriptor data
					byte[] bytes = new byte[24]; // TODO: can descriptor size vary ?
					memory.getBytes(functionDescriptorAddr, bytes);
					memory.setBytes(relocationAddress, bytes);
				}
				break;
			case PowerPC64_ElfRelocationConstants.R_PPC64_UADDR32:
				newValue = (int) (symbolValue + addend);
				memory.setInt(relocationAddress, newValue);
				break;
			case PowerPC64_ElfRelocationConstants.R_PPC64_UADDR16:
				newValue = (int) (symbolValue + addend);
				memory.setShort(relocationAddress, (short) newValue);
				break;
			case PowerPC64_ElfRelocationConstants.R_PPC64_UADDR64:
			case PowerPC64_ElfRelocationConstants.R_PPC64_ADDR64:
			case PowerPC64_ElfRelocationConstants.R_PPC64_GLOB_DAT:
				value64 = symbolValue + addend;
				memory.setLong(relocationAddress, value64);
				if (addend != 0) {
					warnExternalOffsetRelocation(program, relocationAddress,
						symbolAddr, symbolName, addend, elfRelocationContext.getLog());
					applyComponentOffsetPointer(program, relocationAddress, addend);
				}
				break;
			case PowerPC64_ElfRelocationConstants.R_PPC64_TOC:
				memory.setLong(relocationAddress, toc);
				break;
			default:
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				break;
		}

	}

	/**
	 * This method generates a symbol value with possible substitution for those
	 * symbols residing within the .opd to refer to the real function instead.
	 * Care must be taken not to invoke this method for relocations which may be
	 * applied to call stubs. It is also important that relocations have already
	 * been applied to the .opd section since we will be using its data for
	 * locating the real function.
	 * @param elfRelocationContext
	 * @param sym
	 * @return symbol value
	 * @throws MemoryAccessException
	 */
	private long fixupOPDSymbolValue(ElfRelocationContext elfRelocationContext, ElfSymbol sym)
			throws MemoryAccessException {
		Address addr = elfRelocationContext.getSymbolAddress(sym);
		if (addr == null) {
			return 0;
		}
		Program program = elfRelocationContext.getProgram();
		MemoryBlock block = program.getMemory().getBlock(addr);
		if (block == null || !".opd".equals(block.getName())) {
			return addr.getOffset();
		}
		// .opd symbols will get moved to the real function by the extension (see processFunctionDescriptors)
		// Call stubs should always use the .opd symbol value and not the function address so we can - this
		// distinction can only be made using the relocation type.
		byte[] bytes = new byte[8];
		block.getBytes(addr, bytes);
		boolean bigEndian = elfRelocationContext.getElfHeader().isBigEndian();
		DataConverter dataConverter =
			bigEndian ? BigEndianDataConverter.INSTANCE : LittleEndianDataConverter.INSTANCE;
		return dataConverter.getLong(bytes);
	}

}
