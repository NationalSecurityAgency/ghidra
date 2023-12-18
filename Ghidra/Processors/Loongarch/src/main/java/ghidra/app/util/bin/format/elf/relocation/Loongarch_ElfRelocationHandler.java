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
import ghidra.util.exception.NotFoundException;


public class Loongarch_ElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_LOONGARCH;
	}

	@Override
	public RelocationResult relocate(ElfRelocationContext elfRelocationContext,
			ElfRelocation relocation,
			Address relocationAddress) throws MemoryAccessException, NotFoundException {
		ElfHeader elf = elfRelocationContext.getElfHeader();
		if (!canRelocate(elf)) {
			return RelocationResult.FAILURE;
		}

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();
		boolean is32 = elf.is32Bit();
		int type = relocation.getType();
		if (Loongarch_ElfRelocationConstants.R_LARCH_NONE == type) {
			return RelocationResult.SKIPPED;
		}

		long addend = relocation.hasAddend() ? relocation.getAddend() : is32 ? memory.getInt(relocationAddress) : memory.getLong(relocationAddress);
		long offset = relocationAddress.getOffset();
		long base = elfRelocationContext.getImageBaseWordAdjustmentOffset();

		int symbolIndex = relocation.getSymbolIndex();
		ElfSymbol sym = elfRelocationContext.getSymbol(symbolIndex);
		Address symbolAddr = elfRelocationContext.getSymbolAddress(sym);
		long symbolValue = elfRelocationContext.getSymbolValue(sym);
		String symbolName = elfRelocationContext.getSymbolName(symbolIndex);


		long value64 = 0;
		int value32 = 0;
		short value16 = 0;
		byte value8 = 0;
		byte[] bytes24 = new byte[3];
		
		int byteLength = 4; // most relocations affect 4-bytes (change if different)

		switch (type) {
			case Loongarch_ElfRelocationConstants.R_LARCH_32:
				// Runtime address resolving *(int32_t *) PC = RtAddr + A
				value32 = (int) (symbolValue + addend);
				memory.setInt(relocationAddress, value32);
				if (symbolIndex != 0 && addend != 0 && !sym.isSection()) {
					warnExternalOffsetRelocation(program, relocationAddress,
						symbolAddr, symbolName, addend, elfRelocationContext.getLog());
					if (elf.is32Bit()) {
						applyComponentOffsetPointer(program, relocationAddress, addend);
					}
				}
				break;

			case Loongarch_ElfRelocationConstants.R_LARCH_64:
				// Runtime address resolving *(int64_t *) PC = RtAddr + A
				value64 = symbolValue + addend;
				memory.setLong(relocationAddress, value64);
				byteLength = 8;
				if (symbolIndex != 0 && addend != 0 && !sym.isSection()) {
					warnExternalOffsetRelocation(program, relocationAddress,
						symbolAddr, symbolName, addend, elfRelocationContext.getLog());
					if (elf.is64Bit()) {
						applyComponentOffsetPointer(program, relocationAddress, addend);
					}
				}
				break;

			case Loongarch_ElfRelocationConstants.R_LARCH_RELATIVE:
				// Runtime fixup for load-address *(void **) PC = B + A
				if (is32) {
					value32 = (int) (base + addend);
					memory.setInt(relocationAddress, value32);
				}
				else {
					value64 = base + addend;
					memory.setLong(relocationAddress, value64);
					byteLength = 8;
				}
				break;

			case Loongarch_ElfRelocationConstants.R_LARCH_COPY:
				// Runtime memory copy in executable memcpy (PC, RtAddr, sizeof (sym))
				markAsWarning(program, relocationAddress, "R_LARCH_COPY", symbolName, symbolIndex,
					"Runtime copy not supported", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case Loongarch_ElfRelocationConstants.R_LARCH_JUMP_SLOT:
				// Runtime PLT supporting (implementation-defined)
				if (is32) {
					value32 = (int) (symbolValue);
					memory.setInt(relocationAddress, value32);
				}
				else {
					value64 = symbolValue;
					memory.setLong(relocationAddress, value64);
					byteLength = 8;
				}
				break;

			case Loongarch_ElfRelocationConstants.R_LARCH_TLS_DTPMOD32:
				// TLS relocation word32 = S->TLSINDEX
				markAsWarning(program, relocationAddress, "R_LARCH_TLS_DTPMOD32", symbolName,
					symbolIndex, "Thread Local Symbol relocation not supported",
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case Loongarch_ElfRelocationConstants.R_LARCH_TLS_DTPMOD64:
				// TLS relocation word64 = S->TLSINDEX
				markAsWarning(program, relocationAddress, "R_LARCH_TLS_DTPMOD64", symbolName,
					symbolIndex, "Thread Local Symbol relocation not supported",
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case Loongarch_ElfRelocationConstants.R_LARCH_TLS_DTPREL32:
				markAsWarning(program, relocationAddress, "R_LARCH_TLS_DTPREL32", symbolName,
					symbolIndex, "Thread Local Symbol relocation not supported",
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case Loongarch_ElfRelocationConstants.R_LARCH_TLS_DTPREL64:
				markAsWarning(program, relocationAddress, "R_LARCH_TLS_DTPREL64", symbolName,
					symbolIndex, "Thread Local Symbol relocation not supported",
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case Loongarch_ElfRelocationConstants.R_LARCH_TLS_TPREL32:
				markAsWarning(program, relocationAddress, "R_LARCH_TLS_DTREL32", symbolName,
					symbolIndex, "Thread Local Symbol relocation not supported",
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case Loongarch_ElfRelocationConstants.R_LARCH_TLS_TPREL64:
				markAsWarning(program, relocationAddress, "R_LARCH_TLS_TPREL64", symbolName,
					symbolIndex, "Thread Local Symbol relocation not supported",
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case Loongarch_ElfRelocationConstants.R_LARCH_IRELATIVE:
				if (is32) {
					value32 = (int) ( addend + elfRelocationContext.getImageBaseWordAdjustmentOffset());
					memory.setInt(relocationAddress, value32);
				}
				else {
					byteLength = 8;
					value64 = addend + elfRelocationContext.getImageBaseWordAdjustmentOffset();
					memory.setLong(relocationAddress, value64);
				}
				break;

//			case Loongarch_ElfRelocationConstants.R_LARCH_MARK_LA:

//			case Loongarch_ElfRelocationConstants.R_LARCH_MARK_PCREL:

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_PUSH_PCREL:

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_PUSH_ABSOLUTE:
				// PC-relative GOT reference MACRO la

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_PUSH_DUP:
				// PC-relative TLS IE GOT offset MACRO la.tls.ie

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_PUSH_GPREL:
				// PC-relative TLS GD reference MACRO la.tls.gd


//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_PUSH_TLS_TPREL:

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_PUSH_TLS_GOT:

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_PUSH_TLS_GD:

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_PUSH_PLT_PCREL:

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_ASSERT:

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_NOT:
				// Absolute address %lo(symbol) (S-Type)

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_SUB:

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_SL:

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_SR:

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_ADD:
				// TLS LE thread usage %tprel_add(symbol)

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_AND:
				// TLS LE thread usage %tprel_add(symbol)

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_IF_ELSE:
				// TLS LE thread usage %tprel_add(symbol)

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_POP_32_S_10_5:

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_POP_32_U_10_12:

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_POP_32_S_10_12:
				// TLS LE thread usage %tprel_add(symbol)

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_POP_32_S_10_16:
				// TLS LE thread usage %tprel_add(symbol)

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_POP_32_S_10_16_S2:
				// TLS LE thread usage %tprel_add(symbol)

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_POP_32_S_5_20:

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_POP_32_S_0_5_10_16_S2:
				// TLS LE thread usage %tprel_add(symbol)

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_POP_32_S_0_10_10_16_S2:
				// TLS LE thread usage %tprel_add(symbol)

//			case Loongarch_ElfRelocationConstants.R_LARCH_SOP_POP_32_U:
				// TLS LE thread usage %tprel_add(symbol)

			case Loongarch_ElfRelocationConstants.R_LARCH_ADD8:
				// 8-bit in-place addition *(int8_t *) PC += S + A
				value8 = memory.getByte(relocationAddress);
				value8 += (byte) symbolValue;
				value8 += (byte) addend;
				memory.setByte(relocationAddress, value8);
				byteLength = 1;
				break;

			case Loongarch_ElfRelocationConstants.R_LARCH_ADD16:
				// 16-bit in-place addition *(int16_t *) PC += S + A
				value16 = memory.getShort(relocationAddress);
				value16 += (short) symbolValue;
				value16 += (short) addend;
				memory.setShort(relocationAddress, value16);
				byteLength = 2;
				break;

			case Loongarch_ElfRelocationConstants.R_LARCH_ADD24:
				// 24-bit in-place addition (int24_t *) PC += S + A
				memory.getBytes(relocationAddress, bytes24);
				value32 = ((bytes24[2] << 8) + bytes24[1] ) << 8 + bytes24[0];
				value32 += (int) symbolValue;
				value32 += (int) addend;
				bytes24[0] = (byte) value32;
				bytes24[1] = (byte) (value32 >> 8);
				bytes24[2] = (byte) (value32 >> 16);
				memory.setBytes(relocationAddress, bytes24);
				byteLength = 3;
				break;
				
			case Loongarch_ElfRelocationConstants.R_LARCH_ADD32:
				// 32-bit in-place addition *(int32_t *) PC += S + A

				value32 = memory.getInt(relocationAddress);
				value32 += (int) symbolValue;
				value32 += (int) addend;
				memory.setInt(relocationAddress, value32);
				break;

			case Loongarch_ElfRelocationConstants.R_LARCH_ADD64:
				// 64-bit in-place addition *(int64_t *) PC += S + A

				value64 = memory.getLong(relocationAddress);
				value64 += symbolValue;
				value64 += addend;
				memory.setLong(relocationAddress, value64);
				byteLength = 8;
				break;

			case Loongarch_ElfRelocationConstants.R_LARCH_SUB8:
				// 8-bit in-place subtraction *(int8_t *) PC -= S + A
				value8 = memory.getByte(relocationAddress);
				value8 -= (byte) symbolValue;
				value8 -= (byte) addend;
				memory.setByte(relocationAddress, value8);
				byteLength = 1;
				break;

			case Loongarch_ElfRelocationConstants.R_LARCH_SUB16:
				// 16-bit in-place subtraction *(int16_t *) PC -= S + A
				value16 = memory.getShort(relocationAddress);
				value16 -= (short) symbolValue;
				value16 -= (short) addend;
				memory.setShort(relocationAddress, value16);
				byteLength = 2;
				break;

			case Loongarch_ElfRelocationConstants.R_LARCH_SUB24:
				// 24-bit in-place subtraction *(int324_t *) PC -= S + A
				memory.getBytes(relocationAddress, bytes24);
				value32 = ((bytes24[2] << 8) + bytes24[1] ) << 8 + bytes24[0];
				value32 -= (int) symbolValue;
				value32 -= (int) addend;
				bytes24[0] = (byte) value32;
				bytes24[1] = (byte) (value32 >> 8);
				bytes24[2] = (byte) (value32 >> 16);
				memory.setBytes(relocationAddress, bytes24);
				byteLength = 3;
				break;

			case Loongarch_ElfRelocationConstants.R_LARCH_SUB32:
				// 32-bit in-place subtraction *(int32_t *) PC -= S + A
				value32 = memory.getInt(relocationAddress);
				value32 -= (int) symbolValue;
				value32 -= (int) addend;
				memory.setInt(relocationAddress, value32);
				break;

			case Loongarch_ElfRelocationConstants.R_LARCH_SUB64:
				// 64-bit in-place subtraction *(int64_t *) PC -= S + A
				value64 = memory.getLong(relocationAddress);
				value64 -= symbolValue;
				value64 -= addend;
				memory.setLong(relocationAddress, value64);
				byteLength = 8;
				break;

//			case Loongarch_ElfRelocationConstants.R_LARCH_GNU_VTINHERIT:
				// GNU C++ vtable hierarchy 

//			case Loongarch_ElfRelocationConstants.R_LARCH_GNU_VTENTRY:
				// GNU C++ vtable member usage 

//			case Loongarch_ElfRelocationConstants.R_LARCH_B16:

//			case Loongarch_ElfRelocationConstants.R_LARCH_B21:

//			case Loongarch_ElfRelocationConstants.R_LARCH_B26:

//			case Loongarch_ElfRelocationConstants.R_LARCH_ABS_HI20:

//			case Loongarch_ElfRelocationConstants.R_LARCH_ABS_LO12:

//			case Loongarch_ElfRelocationConstants.R_LARCH_ABS64_LO20:

//			case Loongarch_ElfRelocationConstants.R_LARCH_ABS64_HI12:

//			case Loongarch_ElfRelocationConstants.R_LARCH_PCALA_HI20:

//			case Loongarch_ElfRelocationConstants.R_LARCH_PCALA_LO12:

//			case Loongarch_ElfRelocationConstants.R_LARCH_PCALA64_LO20:

//			case Loongarch_ElfRelocationConstants.R_LARCH_PCALA64_HI12:

//			case Loongarch_ElfRelocationConstants.R_LARCH_GOT_PC_HI20:

//			case Loongarch_ElfRelocationConstants.R_LARCH_GOT_PC_LO12:

//			case Loongarch_ElfRelocationConstants.R_LARCH_GOT64_PC_LO20:

//			case Loongarch_ElfRelocationConstants.R_LARCH_GOT64_HI12:

//			case Loongarch_ElfRelocationConstants.R_LARCH_TLS_LE_HI20:

//			case Loongarch_ElfRelocationConstants.R_LARCH_TLS_LE_LO12:

//			case Loongarch_ElfRelocationConstants.R_LARCH_TLS_LE64_LO20:

//			case Loongarch_ElfRelocationConstants.R_LARCH_TLS_LE64_HI12:
				// Instruction pair can be relaxed 

//			case Loongarch_ElfRelocationConstants.R_LARCH_TLS_IE_PC_HI20:
				// Local label subtraction 

//			case Loongarch_ElfRelocationConstants.R_LARCH_TLS_IE_PC_LO12:

//			case Loongarch_ElfRelocationConstants.R_LARCH_TLS_IE64_PC_LO20:
				// Local label subtraction 

//			case Loongarch_ElfRelocationConstants.R_LARCH_TLS_IE64_PC_HI12:
				// Local label subtraction 

//			case Loongarch_ElfRelocationConstants.R_LARCH_TLS_IE_HI20:
				// Local label subtraction 

//			case Loongarch_ElfRelocationConstants.R_LARCH_TLS_IE_LO12:

//			case Loongarch_ElfRelocationConstants.R_LARCH_TLS_IE64_LO20:
				// Instruction pair can be relaxed 

//			case Loongarch_ElfRelocationConstants.R_LARCH_TLS_IE64_HI12:
				// Local label subtraction 

//			case Loongarch_ElfRelocationConstants.R_LARCH_TLS_LD_PC_HI20:

//			case Loongarch_ElfRelocationConstants.R_LARCH_TLS_LD_HI20:
				// Local label subtraction 

//			case Loongarch_ElfRelocationConstants.R_LARCH_TLS_GD_PC_HI20:
				// Local label subtraction 

//			case Loongarch_ElfRelocationConstants.R_LARCH_TLS_GD_HI20:
				// Local label subtraction 

//			case Loongarch_ElfRelocationConstants.R_LARCH_32_PCREL:
				// 32-bit PC relative

//			case Loongarch_ElfRelocationConstants.R_LARCH_RELAX:

//			case Loongarch_ElfRelocationConstants.R_LARCH_DELETE:

//			case Loongarch_ElfRelocationConstants.R_LARCH_ALIGN:

//			case Loongarch_ElfRelocationConstants.R_LARCH_PCREL20_S2:

//			case Loongarch_ElfRelocationConstants.R_LARCH_CFA:

//			case Loongarch_ElfRelocationConstants.R_LARCH_ADD6:

//			case Loongarch_ElfRelocationConstants.R_LARCH_SUB6:

//			case Loongarch_ElfRelocationConstants.R_LARCH_ADD_ULEB128:

//			case Loongarch_ElfRelocationConstants.R_LARCH_SUB_ULEB128:

//			case Loongarch_ElfRelocationConstants.R_LARCH_64_PCREL:

			default:
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
		}
		
		return new RelocationResult(Status.APPLIED, byteLength);
	}
}
