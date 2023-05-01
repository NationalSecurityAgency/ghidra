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
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;
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
	public X86_64_ElfRelocationContext createRelocationContext(ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		return new X86_64_ElfRelocationContext(this, loadHelper, symbolMap);
	}

	public RelocationResult relocate(ElfRelocationContext elfRelocationContext,
			ElfRelocation relocation, Address relocationAddress) throws MemoryAccessException, NotFoundException {

		ElfHeader elf = elfRelocationContext.getElfHeader();
		if (elf.e_machine() != ElfConstants.EM_X86_64) {
			return RelocationResult.FAILURE;
		}

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		X86_64_ElfRelocationContext x86RelocationContext =
			(X86_64_ElfRelocationContext) elfRelocationContext;

		int type = relocation.getType();
		if (type == X86_64_ElfRelocationConstants.R_X86_64_NONE) {
			return RelocationResult.SKIPPED;
		}

		int symbolIndex = relocation.getSymbolIndex();

		// addend is either pulled from the relocation or the bytes in memory
		long addend =
			relocation.hasAddend() ? relocation.getAddend() : memory.getLong(relocationAddress);

		ElfSymbol sym = elfRelocationContext.getSymbol(symbolIndex);
		Address symbolAddr = elfRelocationContext.getSymbolAddress(sym);
		long symbolValue = elfRelocationContext.getSymbolValue(sym);
		String symbolName = elfRelocationContext.getSymbolName(symbolIndex);
		long symbolSize = sym.getSize();

		long offset = relocationAddress.getOffset();

		int byteLength = 8; // most relocations affect 8-bytes (change if different)
		long value;

		switch (type) {
			case X86_64_ElfRelocationConstants.R_X86_64_COPY:
				markAsWarning(program, relocationAddress, "R_X86_64_COPY", symbolName, symbolIndex,
					"Runtime copy not supported", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
			case X86_64_ElfRelocationConstants.R_X86_64_64:
				value = symbolValue + addend;
				memory.setLong(relocationAddress, value);
				if (symbolIndex != 0 && addend != 0 && !sym.isSection()) {
					warnExternalOffsetRelocation(program, relocationAddress,
						symbolAddr, symbolName, addend, elfRelocationContext.getLog());
					applyComponentOffsetPointer(program, relocationAddress, addend);
				}
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_16:
				value = symbolValue + addend;
				value = value & 0xffff;
				memory.setShort(relocationAddress, (short) value);
				byteLength = 2;
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_8:
				value = symbolValue + addend;
				value = value & 0xff;
				memory.setByte(relocationAddress, (byte) value);
				byteLength = 1;
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_PC32:
				value = symbolValue + addend - offset;
				value = value & 0xffffffff;
				memory.setInt(relocationAddress, (int) value);
				byteLength = 4;
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_PC16:
				value = symbolValue + addend - offset;
				value = value & 0xffff;
				memory.setShort(relocationAddress, (short) value);
				byteLength = 2;
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_PC8:
				value = symbolValue + addend - offset;
				value = value & 0xff;
				memory.setByte(relocationAddress, (byte) value);
				byteLength = 1;
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_GOT32:
				value = symbolValue + addend;
				memory.setInt(relocationAddress, (int) value);
				byteLength = 4;
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_PLT32:
				value = symbolValue + addend - offset;
				memory.setInt(relocationAddress, (int) value);
				byteLength = 4;
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_GLOB_DAT:
			case X86_64_ElfRelocationConstants.R_X86_64_JUMP_SLOT:
				value = symbolValue + addend;
				memory.setLong(relocationAddress, value);
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_GOTOFF64:
				try {
					long dotgot = elfRelocationContext.getGOTValue();
					value = symbolValue + addend - dotgot;
					memory.setLong(relocationAddress, value);
				}
				catch (NotFoundException e) {
					markAsError(program, relocationAddress, "R_X86_64_GOTOFF64", symbolName,
						e.getMessage(), elfRelocationContext.getLog());
				}
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_32:  // this one complains for unsigned overflow
			case X86_64_ElfRelocationConstants.R_X86_64_32S: // this one complains for signed overflow
				symbolValue += addend;
				value = (symbolValue & 0xffffffff);
				memory.setInt(relocationAddress, (int) value);
				byteLength = 4;
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_SIZE32:
				value = symbolSize + addend;
				value = (value & 0xffffffff);
				memory.setInt(relocationAddress, (int) value);
				byteLength = 4;
				break;
			case X86_64_ElfRelocationConstants.R_X86_64_SIZE64:
				value = symbolSize + addend;
				memory.setLong(relocationAddress, value);
				break;

			// Thread Local Symbol relocations (unimplemented concept)
			case X86_64_ElfRelocationConstants.R_X86_64_DTPMOD64:
				markAsWarning(program, relocationAddress, "R_X86_64_DTPMOD64", symbolName,
					symbolIndex, "Thread Local Symbol relocation not supported",
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
			case X86_64_ElfRelocationConstants.R_X86_64_DTPOFF64:
				markAsWarning(program, relocationAddress, "R_X86_64_DTPOFF64", symbolName,
					symbolIndex, "Thread Local Symbol relocation not supported",
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
			case X86_64_ElfRelocationConstants.R_X86_64_TPOFF64:
				markAsWarning(program, relocationAddress, "R_X86_64_TPOFF64", symbolName,
					symbolIndex, "Thread Local Symbol relocation not supported",
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
			case X86_64_ElfRelocationConstants.R_X86_64_TLSDESC:
				markAsWarning(program, relocationAddress, "R_X86_64_TLSDESC", symbolName,
					symbolIndex, "Thread Local Symbol relocation not supported",
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			// cases which do not use symbol value

			case X86_64_ElfRelocationConstants.R_X86_64_GOTPC32:
				try {
					long dotgot = elfRelocationContext.getGOTValue();
					value = dotgot + addend - offset;
					memory.setInt(relocationAddress, (int) value);
					byteLength = 4;
				}
				catch (NotFoundException e) {
					markAsError(program, relocationAddress, "R_X86_64_GOTPC32", symbolName,
						e.getMessage(), elfRelocationContext.getLog());
				}
				break;


			case X86_64_ElfRelocationConstants.R_X86_64_GOTPCRELX:
			case X86_64_ElfRelocationConstants.R_X86_64_REX_GOTPCRELX:

				// Check for supported Relax cases (assumes non-PIC)
				// Assumes non-PIC treatment is OK and attempts 
				// indirect-to-direct instruction transformation

				Address opAddr = relocationAddress.subtract(2);
				Address modRMAddr = relocationAddress.subtract(1);
				Address directValueAddr = null;

				byte op = memory.getByte(opAddr);
				byte modRM = memory.getByte(modRMAddr);

				byte symbolType = sym.getType();
				if (symbolType < ElfSymbol.STT_NOTYPE || symbolType > ElfSymbol.STT_COMMON) {
					// do not transform instruction for OS-specific symbol types
				}
				else if (op == (byte) 0x8b) { // check for MOV op
					// convert to LEA op
					elfRelocationContext.getLoadHelper().addArtificialRelocTableEntry(opAddr, 2);
					memory.setByte(opAddr, (byte) 0x8d); // direct LEA op
					directValueAddr = relocationAddress;
				}
				else if (op == (byte) 0xff) { // check for possible JMP/CALL op
					if (modRM == (byte) 0x25) { // check for indirect JMP op
						// convert to direct JMP op
						// must compensate for shorter instruction by appending NOP
						elfRelocationContext.getLoadHelper().addArtificialRelocTableEntry(opAddr, 2);
						memory.setByte(opAddr, (byte) 0xe9); // direct JMP op
						memory.setByte(relocationAddress.add(3), (byte) 0x90); // append NOP
						directValueAddr = modRMAddr;
						addend += 1;
					}
					else if (modRM == (byte) 0x15) { // check for indirect CALL instruction
						// convert to direct CALL instruction
						// use of addr32 prefix allows use of single instruction
						elfRelocationContext.getLoadHelper().addArtificialRelocTableEntry(opAddr, 2);
						memory.setByte(opAddr, (byte) 0x67); // addr32 prefix
						memory.setByte(modRMAddr, (byte) 0xe8); // direct CALL op
						directValueAddr = relocationAddress;
					}
				}
				if (directValueAddr != null) {
					value = symbolValue + addend - offset;
					memory.setInt(directValueAddr, (int) value);
					byteLength = 4;
					break;
				}

				// If instruction not handled as relaxed instruction
				// Let R_X86_64_GOTPCREL case handle as simple GOTPCREL relocation.

			case X86_64_ElfRelocationConstants.R_X86_64_GOTPCREL:
				Address symbolGotAddress = x86RelocationContext.getGotEntryAddress(symbolValue);
				if (symbolGotAddress == null) {
					markAsError(program, relocationAddress, type, symbolName,
						"GOT allocation failure", elfRelocationContext.getLog());
					break;
				}
				value = symbolGotAddress.getOffset() + addend - offset;
				memory.setInt(relocationAddress, (int) value);
				byteLength = 4;
				break;

			case X86_64_ElfRelocationConstants.R_X86_64_GOTPCREL64:
				symbolGotAddress = x86RelocationContext.getGotEntryAddress(symbolValue);
				if (symbolGotAddress == null) {
					markAsError(program, relocationAddress, "R_X86_64_GOTPCREL64", symbolName,
						"GOT allocation failure", elfRelocationContext.getLog());
					break;
				}
				value = symbolGotAddress.getOffset() + addend - offset;
				memory.setLong(relocationAddress, value);

			case X86_64_ElfRelocationConstants.R_X86_64_RELATIVE:
				// word64 for LP64 and specifies word32 for ILP32,
				// we assume LP64 only.  We probably need a hybrid
				// variant to handle the ILP32 case.
			case X86_64_ElfRelocationConstants.R_X86_64_RELATIVE64:
				// dl_machine.h
				// value = (Elf64_64Addr) map->l_addr + reloc->r_addend
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
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}
}
