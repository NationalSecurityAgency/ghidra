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

public class RISCV_ElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_RISCV;
	}

	@Override
	public void relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation,
			Address relocationAddress) throws MemoryAccessException, NotFoundException {
		ElfHeader elf = elfRelocationContext.getElfHeader();
		if (!canRelocate(elf)) {
			return;
		}

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();
		boolean is32 = elf.is32Bit();
		int type = relocation.getType();
		if (RISCV_ElfRelocationConstants.R_RISCV_NONE == type) {
			return;
		}

		long addend = relocation.hasAddend() ? relocation.getAddend() : is32 ? memory.getInt(relocationAddress) : memory.getLong(relocationAddress);
		long offset = relocationAddress.getOffset();
		long base = elfRelocationContext.getImageBaseWordAdjustmentOffset();
		ElfSymbol sym = null;
		long symbolValue = 0;
		Address symbolAddr = null;
		String symbolName = null;

		int symbolIndex = relocation.getSymbolIndex();
		if (symbolIndex != 0) {
			sym = elfRelocationContext.getSymbol(symbolIndex);
		}

		if (null != sym) {
			symbolAddr = elfRelocationContext.getSymbolAddress(sym);
			symbolValue = elfRelocationContext.getSymbolValue(sym);
			symbolName = sym.getNameAsString();
		}

		//TODO  remove debug
		switch(type) {
		case 2:
		case 3:
		case 5:
			break;
		default:
			System.out.println("DEBUG RISCV: " +
					type + " " + relocationAddress + " " +
					String.format("%x", symbolValue) + " " +
					String.format("%x", addend) + " " +
					String.format("%x", offset) + " " +
					String.format("%x", base));// + " " +
					//String.format("%x", memory.getInt(relocationAddress)));
			break;
		}

		long value64 = 0;
		int value32 = 0;
		short value16 = 0;
		byte value8 = 0;

		switch (type) {
		case RISCV_ElfRelocationConstants.R_RISCV_32:
			// Runtime relocation word32 = S + A
			value32 = (int)(symbolValue + addend);
			memory.setInt(relocationAddress, value32);
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_64:
			// Runtime relocation word64 = S + A
			if (addend != 0 && isUnsupportedExternalRelocation(program, relocationAddress,
				symbolAddr, symbolName, addend, elfRelocationContext.getLog())) {
				addend = 0; // prefer bad fixup for EXTERNAL over really-bad fixup
			}
			value64 = symbolValue + addend;
			memory.setLong(relocationAddress, value64);
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_RELATIVE:
			// Runtime relocation word32,64 = B + A
			if (is32) {
				value32 = (int)(base + addend);
				memory.setInt(relocationAddress, value32);
			}
			else {
				value64 = base + addend;
				memory.setLong(relocationAddress, value64);
			}
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_COPY:
			// Runtime relocation must be in executable. not allowed in shared library
			markAsWarning(program, relocationAddress, "R_RISCV_COPY", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());         
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_JUMP_SLOT:
			// Runtime relocation word32,64 = S ;handled by PLT unless LD_BIND_NOW
			if (is32) {
				value32 = (int)(symbolValue);
				memory.setInt(relocationAddress, value32);
			}
			else {
				value64 = symbolValue;
				memory.setLong(relocationAddress, value64);
			}
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_TLS_DTPMOD32:
			// TLS relocation word32 = S->TLSINDEX
			markAsWarning(program, relocationAddress, "R_RISCV_TLS_DTPMOD32", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());     
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_TLS_DTPMOD64:
			// TLS relocation word64 = S->TLSINDEX
			markAsWarning(program, relocationAddress, "R_RISCV_TLS_DTPMOD32", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());       
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_TLS_DTPREL32:
			// TLS relocation word32 = TLS + S + A - TLS_TP_OFFSET
			markAsWarning(program, relocationAddress, "R_RISCV_TLS_DTPREL32", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());       
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_TLS_DTPREL64:
			// TLS relocation word64 = TLS + S + A - TLS_TP_OFFSET
			markAsWarning(program, relocationAddress, "R_RISCV_TLS_DTPREL64", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());     
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_TLS_TPREL32:
			// TLS relocation word32 = TLS + S + A + S_TLS_OFFSET - TLS_DTV_OFFSET
			markAsWarning(program, relocationAddress, "R_RISCV_TLS_DTREL32", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());          
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_TLS_TPREL64:
			// TLS relocation word64 = TLS + S + A + S_TLS_OFFSET - TLS_DTV_OFFSET
			markAsWarning(program, relocationAddress, "R_RISCV_TLS_TPREL64", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());                  
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_BRANCH:
			// PC-relative branch (SB-Type)
			markAsWarning(program, relocationAddress, "R_RISCV_BRANCH", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_JAL:
			// PC-relative jump (UJ-Type)
			markAsWarning(program, relocationAddress, "R_RISCV_JAL", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_CALL:
			// PC-relative call MACRO call,tail (auipc+jalr pair)
			markAsWarning(program, relocationAddress, "R_RISCV_CALL", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_CALL_PLT:
			// PC-relative call (PLT) MACRO call,tail (auipc+jalr pair) PIC
			markAsWarning(program, relocationAddress, "R_RISCV_CALL_PLT", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_GOT_HI20:
			// PC-relative GOT reference MACRO la
			markAsWarning(program, relocationAddress, "R_RISCV_GOT_HI20", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_TLS_GOT_HI20:
			// PC-relative TLS IE GOT offset MACRO la.tls.ie
			markAsWarning(program, relocationAddress, "R_RISCV_TLS_GOT_HI20", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_TLS_GD_HI20:
			// PC-relative TLS GD reference MACRO la.tls.gd
			markAsWarning(program, relocationAddress, "R_RISCV_TLS_GD_HI20", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_PCREL_HI20:
			// PC-relative reference %pcrel_hi(symbol) (U-Type)
			markAsWarning(program, relocationAddress, "R_RISCV_PCREL_HI20", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_PCREL_LO12_I:
			// PC-relative reference %pcrel_lo(symbol) (I-Type)
			markAsWarning(program, relocationAddress, "R_RISCV_PCREL_LO12_I", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_PCREL_LO12_S:
			// PC-relative reference %pcrel_lo(symbol) (S-Type)
			markAsWarning(program, relocationAddress, "R_RISCV_PCREL_LO12_S", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_HI20:
			// Absolute address %hi(symbol) (U-Type)
			markAsWarning(program, relocationAddress, "R_RISCV_HI20", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_LO12_I:
			// Absolute address %lo(symbol) (I-Type)
			markAsWarning(program, relocationAddress, "R_RISCV_LO12_I", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_LO12_S:
			// Absolute address %lo(symbol) (S-Type)
			markAsWarning(program, relocationAddress, "R_RISCV_LO12_S", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_TPREL_HI20:
			// TLS LE thread offset %tprel_hi(symbol) (U-Type)
			markAsWarning(program, relocationAddress, "R_RISCV_TPREL_HI20", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_TPREL_LO12_I:
			// TLS LE thread offset %tprel_lo(symbol) (I-Type)
			markAsWarning(program, relocationAddress, "R_RISCV_TPREL_LO12_I", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_TPREL_LO12_S:
			// TLS LE thread offset %tprel_lo(symbol) (S-Type)
			markAsWarning(program, relocationAddress, "R_RISCV_TPREL_LO12_S", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_TPREL_ADD:
			// TLS LE thread usage %tprel_add(symbol)
			markAsWarning(program, relocationAddress, "R_RISCV_TPREL_ADD", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_ADD8:
			// 8-bit label addition word8 = old + S + A
			markAsWarning(program, relocationAddress, "R_RISCV_ADD8", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			value8 = memory.getByte(relocationAddress);
			value8 += (byte)symbolValue;
			value8 += (byte)addend;
			memory.setByte(relocationAddress, value8);
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_ADD16:
			// 16-bit label addition word16 = old + S + A
			markAsWarning(program, relocationAddress, "R_RISCV_ADD16", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			value16 = memory.getShort(relocationAddress);
			value16 += (short)symbolValue;
			value16 += (short)addend;
			memory.setShort(relocationAddress, value16);
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_ADD32:
			// 32-bit label addition word32 = old + S + A
			markAsWarning(program, relocationAddress, "R_RISCV_ADD32", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			value32 = memory.getInt(relocationAddress);
			value32 += (int)symbolValue;
			value32 += (int)addend;
			memory.setInt(relocationAddress, value32);
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_ADD64:
			// 64-bit label addition word64 = old + S + A
			markAsWarning(program, relocationAddress, "R_RISCV_ADD64", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			value64 = memory.getLong(relocationAddress);
			value64 += symbolValue;
			value64 += addend;
			memory.setLong(relocationAddress, value64);
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_SUB8:
			// 8-bit label subtraction word8 = old - S - A
			markAsWarning(program, relocationAddress, "R_RISCV_SUB8", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			value8 = memory.getByte(relocationAddress);
			value8 -= (byte)symbolValue;
			value8 -= (byte)addend;
			memory.setByte(relocationAddress, value8);
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_SUB16:
			// 16-bit label subtraction word16 = old - S - A
			markAsWarning(program, relocationAddress, "R_RISCV_SUB16", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			value16 = memory.getShort(relocationAddress);
			value16 -= (short)symbolValue;
			value16 -= (short)addend;
			memory.setShort(relocationAddress, value16);
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_SUB32:
			// 32-bit label subtraction word32 = old - S - A
			markAsWarning(program, relocationAddress, "R_RISCV_SUB32", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			value32 = memory.getInt(relocationAddress);
			value32 -= (int)symbolValue;
			value32 -= (int)addend;
			memory.setInt(relocationAddress, value32);
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_SUB64:
			// 64-bit label subtraction word64 = old - S - A
			markAsWarning(program, relocationAddress, "R_RISCV_SUB64", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			value64 = memory.getLong(relocationAddress);
			value64 -= symbolValue;
			value64 -= addend;
			memory.setLong(relocationAddress, value64);
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_GNU_VTINHERIT:
			// GNU C++ vtable hierarchy 
			markAsWarning(program, relocationAddress, "R_RISCV_GNU_VTINHERIT", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_GNU_VTENTRY:
			// GNU C++ vtable member usage 
			markAsWarning(program, relocationAddress, "R_RISCV_GNU_VTENTRY", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_ALIGN:
			// Alignment statement 
			markAsWarning(program, relocationAddress, "R_RISCV_ALIGN", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_RVC_BRANCH:
			// PC-relative branch offset (CB-Type)
			markAsWarning(program, relocationAddress, "R_RISCV_RVC_BRANCH", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_RVC_JUMP:
			// PC-relative jump offset (CJ-Type)
			markAsWarning(program, relocationAddress, "R_RISCV_RVC_BRANCH", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_RVC_LUI:
			// Absolute address (CI-Type)
			markAsWarning(program, relocationAddress, "R_RISCV_RVC_LUI", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_GPREL_I:
			// GP-relative reference (I-Type)
			markAsWarning(program, relocationAddress, "R_RISCV_GPREL_I", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_GPREL_S:
			// GP-relative reference (S-Type)
			markAsWarning(program, relocationAddress, "R_RISCV_GPREL_S", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_TPREL_I:
			// TP-relative TLS LE load (I-Type)
			markAsWarning(program, relocationAddress, "R_RISCV_TPREL_I", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_TPREL_S:
			// TP-relative TLS LE store (S-Type)
			markAsWarning(program, relocationAddress, "R_RISCV_TPREL_S", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_RELAX:
			// Instruction pair can be relaxed 
			markAsWarning(program, relocationAddress, "R_RISCV_RELAX", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_SUB6:
			// Local label subtraction 
			markAsWarning(program, relocationAddress, "R_RISCV_SUB6", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_SET6:
			// Local label subtraction 
			markAsWarning(program, relocationAddress, "R_RISCV_SET6", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_SET8:
			// Local label subtraction 
			markAsWarning(program, relocationAddress, "R_RISCV_SET8", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_SET16:
			// Local label subtraction 
			markAsWarning(program, relocationAddress, "R_RISCV_SET16", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_SET32:
			// Local label subtraction 
			markAsWarning(program, relocationAddress, "R_RISCV_SET32", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		case RISCV_ElfRelocationConstants.R_RISCV_32_PCREL:
			// 32-bit PC relative
			markAsWarning(program, relocationAddress, "R_RISCV_32_PCREL", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;

		default:
			// 58-191 Reserved Reserved for future standard use
			// 192-255 Reserved Reserved for nonstandard ABI extensions
			markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName, elfRelocationContext.getLog());
			break;

		}	
	}
}
