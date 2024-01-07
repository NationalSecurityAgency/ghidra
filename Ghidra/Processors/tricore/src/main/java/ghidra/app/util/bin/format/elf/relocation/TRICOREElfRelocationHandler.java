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

import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfRelocation;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;

public class TRICOREElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_TRICORE;
	}

	@Override
	public RelocationResult relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation,
			Address relocationAddress) throws MemoryAccessException, NotFoundException {

		ElfHeader elf = elfRelocationContext.getElfHeader();
		if (!canRelocate(elf)) {
			return RelocationResult.FAILURE;
		}

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		int type = relocation.getType();

		if (TRICOREElfRelocationConstants.R_TRICORE_NONE == type) {
			return RelocationResult.SKIPPED;
		}

		long addend = relocation.hasAddend() ? relocation.getAddend() : memory.getInt(relocationAddress);
		long offset = relocationAddress.getOffset();
		int symbolIndex = relocation.getSymbolIndex();

		long symbolValue = 0;
		String symbolName = null;
		ElfSymbol symbol = elfRelocationContext.getSymbol(symbolIndex);
		if (symbol != null) {
			symbolValue = elfRelocationContext.getSymbolValue(symbol);
			symbolName = symbol.getNameAsString();
		}

		long rv = 0;
		int byteLength = -1;

		/**
		 * Key S indicates the final value assigned to the symbol referenced in the
		 * relocation record. Key A is the addend value specified in the relocation
		 * record. Key P indicates the address of the relocation (for example, the
		 * address being modified). Key A[0] is the content of the small data base
		 * register A[0].
		 */
		switch (type) {
		case TRICOREElfRelocationConstants.R_TRICORE_32REL: // word32 S + A - P
			rv = symbolValue + addend - offset;
			byteLength = relocate_word32(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_32ABS: // word32 S + A
			rv = symbolValue + addend;
			byteLength = relocate_word32(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_24REL: // relB S + A - P
			rv = symbolValue + addend - offset;
			byteLength = relocate_relB(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_24ABS: // absB S + A
			rv = symbolValue + addend;
			byteLength = relocate_absB(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_16SM: // BOL S + A - A[0]
			//TODO  how to get "content of the small data base register A[0]"
			markAsWarning(program, relocationAddress, "R_TRICORE_16SM", symbolName, symbolIndex, 
					"TODO, needs support ", elfRelocationContext.getLog());
			// relocate_BOL(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_HI: // RLC S + A + 8000H >> 16
			rv = (symbolValue + addend + 0x8000) >> 16;
			byteLength = relocate_RLC(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_LO: // RLC S + A & FFFFH
			rv = (symbolValue + addend) & 0xffff;
			byteLength = relocate_RLC(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_LO2: // BOL S + A & FFFFH
			rv = (symbolValue + addend) & 0xffff;
			byteLength = relocate_BOL(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_18ABS: // ABS S + A
			rv = symbolValue + addend;
			byteLength = relocate_ABS(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_10SM: // BO S + A - A[0]
			markAsWarning(program, relocationAddress, "R_TRICORE_10SM", symbolName, symbolIndex, 
					"TODO, needs support ",	elfRelocationContext.getLog());
			// relocate_BO(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_15REL: // BR S + A - P
			rv = symbolValue + addend - offset;
			byteLength = relocate_BR(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_10LI: // BO S + A - A[1]
			markAsWarning(program, relocationAddress, "R_TRICORE_10LI", symbolName, symbolIndex, 
					"TODO, needs support ",	elfRelocationContext.getLog());
			// relocate_BO(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_16LI: // BOL S + A - A[1]
			markAsWarning(program, relocationAddress, "R_TRICORE_16LI", symbolName, symbolIndex, 
					"TODO, needs support ",	elfRelocationContext.getLog());
			// relocate_BOL(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_10A8: // BO S + A - A[8]
			markAsWarning(program, relocationAddress, "R_TRICORE_10A8", symbolName, symbolIndex,
					"TODO, needs support ",	elfRelocationContext.getLog());
			// relocate_BO(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_16A8: // BOL S + A - A[8]
			markAsWarning(program, relocationAddress, "R_TRICORE_16A8", symbolName, symbolIndex,
					"TODO, needs support ",	elfRelocationContext.getLog());
			// relocate_BOL(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_10A9: // BO S + A - A[9]
			markAsWarning(program, relocationAddress, "R_TRICORE_16A9", symbolName, symbolIndex, 
					"TODO, needs support ",	elfRelocationContext.getLog());
			// relocate_BO(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_16A9: // BOL S + A - A[9]
			markAsWarning(program, relocationAddress, "R_TRICORE_16A9", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			// relocate_BOL(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_10OFF:
			markAsWarning(program, relocationAddress, "R_TRICORE_10OFF", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_16OFF:
			rv = symbolValue + addend;
			byteLength = relocate_BOL(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_8ABS:
			markAsWarning(program, relocationAddress, "R_TRICORE_8ABS", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_16ABS:
			markAsWarning(program, relocationAddress, "R_TRICORE_16ABS", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_16BIT:
			markAsWarning(program, relocationAddress, "R_TRICORE_16BIT", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_3POS:
			rv = symbolValue + addend;
			byteLength = relocate_3POS(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_5POS:
			rv = symbolValue + addend;
			byteLength = relocate_5POS(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_PCPHI: // word16 S + A >> 16
			rv = (symbolValue + addend) >> 16;
			byteLength = relocate_word16(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_PCPLO: // word16 S + A & FFFFH
			rv = (symbolValue + addend) & 0xffff;
			byteLength = relocate_word16(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_PCPPAGE: // pcpPage S + A & FF00H
			rv = (symbolValue + addend) & 0xff00;
			byteLength = relocate_pcpPage(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_PCPOFF: // PI (S + A >> 2) & 3FH
			rv = ((symbolValue + addend) >> 2) & 0x3f;
			byteLength = relocate_PI(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_PCPTEXT: // word16 (S + A >> 1) & FFFFH
			rv = ((symbolValue + addend) >> 1) & 0xffff;
			byteLength = relocate_word16(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_5POS2:
			rv = (symbolValue + addend);
			byteLength = relocate_5POS2(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_BRCC:
			markAsWarning(program, relocationAddress, "R_TRICORE_BRCC", symbolName, symbolIndex,
					"TODO, needs support ",	elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_BRCZ:
			markAsWarning(program, relocationAddress, "R_TRICORE_BRCZ", symbolName, symbolIndex,
					"TODO, needs support ",	elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_BRNN:
			markAsWarning(program, relocationAddress, "R_TRICORE_BRNN", symbolName, symbolIndex,
					"TODO, needs support ",	elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_RRN:
			markAsWarning(program, relocationAddress, "R_TRICORE_RRN", symbolName, symbolIndex,
					"TODO, needs support ",	elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_4CONST:
			markAsWarning(program, relocationAddress, "R_TRICORE_4CONST", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_4REL:
			markAsWarning(program, relocationAddress, "R_TRICORE_4REL", symbolName, symbolIndex,
					"TODO, needs support ",	elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_4REL2:
			markAsWarning(program, relocationAddress, "R_TRICORE_4REL2", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_5POS3:
			markAsWarning(program, relocationAddress, "R_TRICORE_5POS3", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_4OFF:
			markAsWarning(program, relocationAddress, "R_TRICORE_4OFF", symbolName, symbolIndex,
					"TODO, needs support ",	elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_4OFF2:
			markAsWarning(program, relocationAddress, "R_TRICORE_4OFF2", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_4OFF4:
			markAsWarning(program, relocationAddress, "R_TRICORE_4OFF4", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_42OFF:
			markAsWarning(program, relocationAddress, "R_TRICORE_42OFF", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_42OFF2:
			markAsWarning(program, relocationAddress, "R_TRICORE_42OFF2", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_42OFF4:
			markAsWarning(program, relocationAddress, "R_TRICORE_42OFF4", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_2OFF:
			markAsWarning(program, relocationAddress, "R_TRICORE_2OFF", symbolName, symbolIndex,
					"TODO, needs support ",	elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_8CONST2:
			markAsWarning(program, relocationAddress, "R_TRICORE_8CONST2", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_4POS:
			markAsWarning(program, relocationAddress, "R_TRICORE_4POS", symbolName, symbolIndex,
					"TODO, needs support ",	elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_16SM2:
			markAsWarning(program, relocationAddress, "R_TRICORE_16SM2", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			// byteLength = relocate_BOL(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_5REL:
			markAsWarning(program, relocationAddress, "R_TRICORE_5REL", symbolName, symbolIndex,
					"TODO, needs support ",	elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_VTENTRY:
			markAsWarning(program, relocationAddress, "R_TRICORE_VTENTRY", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_VTINHERIT:
			markAsWarning(program, relocationAddress, "R_TRICORE_VTINHERIT", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_PCREL16:
			markAsWarning(program, relocationAddress, "R_TRICORE_PCREL16", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_PCREL8:
			markAsWarning(program, relocationAddress, "R_TRICORE_PCREL8", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_GOT:
			markAsWarning(program, relocationAddress, "R_TRICORE_GOT", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_GOT2:
			markAsWarning(program, relocationAddress, "R_TRICORE_GOT2", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_GOTHI:
			markAsWarning(program, relocationAddress, "R_TRICORE_GOTHI", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_GOTLO:
			markAsWarning(program, relocationAddress, "R_TRICORE_GOTLO", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_GOTLO2:
			markAsWarning(program, relocationAddress, "R_TRICORE_GOTLO2", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_GOTUP:
			markAsWarning(program, relocationAddress, "R_TRICORE_GOTUP", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_GOTOFF:
			markAsWarning(program, relocationAddress, "R_TRICORE_GOTOFF", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_GOTOFF2:
			markAsWarning(program, relocationAddress, "R_TRICORE_GOTOFF2", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_GOTOFFHI:
			markAsWarning(program, relocationAddress, "R_TRICORE_GOTOFFHI", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_GOTOFFLO:
			markAsWarning(program, relocationAddress, "R_TRICORE_GOTOFFLO", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_GOTOFFLO2:
			markAsWarning(program, relocationAddress, "R_TRICORE_GOTOFFLO2", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_GOTOFFUP:
			markAsWarning(program, relocationAddress, "R_TRICORE_GOTOFFUP", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_GOTPC:
			markAsWarning(program, relocationAddress, "R_TRICORE_GOTPC", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_GOTPC2:
			markAsWarning(program, relocationAddress, "R_TRICORE_GOTPC2", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_GOTPCHI:
			markAsWarning(program, relocationAddress, "R_TRICORE_GOTPCHI", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_GOTPCLO:
			markAsWarning(program, relocationAddress, "R_TRICORE_GOTPCLO", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_GOTPCLO2:
			markAsWarning(program, relocationAddress, "R_TRICORE_GOTPCLO2", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_GOTCPUP:
			markAsWarning(program, relocationAddress, "R_TRICORE_GOTCPUP", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_PLT:
			markAsWarning(program, relocationAddress, "R_TRICORE_PLT", symbolName, symbolIndex,
					"TODO, needs support ",	elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_COPY:
			markAsWarning(program, relocationAddress, "R_TRICORE_COPY", symbolName, symbolIndex,
					"TODO, needs support ",	elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_GLOB_DAT:
			markAsWarning(program, relocationAddress, "R_TRICORE_GLOB_DAT", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_JMP_SLOT:
			markAsWarning(program, relocationAddress, "R_TRICORE_JMP_SLOT", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_RELATIVE:
			markAsWarning(program, relocationAddress, "R_TRICORE_RELATIVE", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_BITPOS:
			// This reads as a pseudo relocation, possibly do RelocationResult.PARTIAL instead?
			return RelocationResult.SKIPPED;
		case TRICOREElfRelocationConstants.R_TRICORE_SBREG_S2:
			markAsWarning(program, relocationAddress, "R_TRICORE_SBREG_S2", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_SBREG_S1:
			markAsWarning(program, relocationAddress, "R_TRICORE_SBREG_S1", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_SBREG_D:
			markAsWarning(program, relocationAddress, "R_TRICORE_SBREG_D", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
			break;
		default:
			markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName, elfRelocationContext.getLog());
			break;
		}
		if (byteLength < 0) {
			return RelocationResult.UNSUPPORTED;
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}

	// TODO how bad is this approach, not sure how java handles bit manipulation
	// at this level, or just in a general a class exists that excels at these
	// operations?

	// RV = Relocation Value. IW = Instruction Word.

	/**
	 * A 32-bit field occupying four bytes. This address is NOT required to be
	 * 4-byte aligned.
	 */
	private int relocate_word32(Memory memory, Address relocationAddress, long rv) throws MemoryAccessException {
		memory.setInt(relocationAddress, (int) rv);
		return 4;
	}

	/**
	 * A 16-bit field occupying two bytes.
	 */
	private int relocate_word16(Memory memory, Address relocationAddress, long rv) throws MemoryAccessException {
		memory.setShort(relocationAddress, (short) rv);
		return 2;
	}

	/**
	 * A 32-bit instruction word, where: - bits 1-16 of the RV go into bits 16-31 of
	 * the IW. - bits 17-24 of the RV go into bits 8-15 of the IW. - the RV must be
	 * in the range [-16777216,16777214]. bit 0 of the RV must be zero.
	 */
	private int relocate_relB(Memory memory, Address relocationAddress, long rv) throws MemoryAccessException {
		// TODO ff000000..00fffffe?
		long mask = 0xfffffffeL;
		long val = ~mask & rv;
		int iw = memory.getInt(relocationAddress) & 0xff;
		iw |= ((val & 0x1fffe) << 15);
		iw |= ((val & 0x1fe0000) >> 9);
		memory.setInt(relocationAddress, iw);
		return 4;
	}

	/**
	 * A 32-bit instruction word, where: - bits 1-16 of the RV go into bits 16-31 of
	 * the IW. - bits 17-20 of the RV go into bits 8-11 of the IW. - bits 0 and 21
	 * to 27 of the RV must be zero. - bits 28-31 of the RV go into bits 12-15 of
	 * the IW.
	 */
	private int relocate_absB(Memory memory, Address relocationAddress, long rv) throws MemoryAccessException {
		long mask = 0x0fe00001L;
		long val = ~mask & rv;
		int iw = memory.getInt(relocationAddress) & 0xff;
		iw |= ((val & 0x1fffe) << 15);
		iw |= ((val & 0x1e0000) >> 9);
		iw |= ((val & 0xf0000000) >> 16);
		memory.setInt(relocationAddress, iw);
		return 4;
	}

	/**
	 * A 32-bit instruction word where: - bits 0-5 of the RV go into bits 16-21 of
	 * the IW. - bits 6-9 of the RV go into bits 28-31 of the IW. - bits 10-31 of
	 * the RV must be zero.
	 */
	@SuppressWarnings("unused")
	private int relocate_BO(Memory memory, Address relocationAddress, long rv) throws MemoryAccessException {
		long mask = 0xfffffc00L;
		long val = ~mask & rv;
		int iw = memory.getInt(relocationAddress) & 0xfc0ffff;
		iw |= ((val & 0x3f) << 16);
		iw |= ((val & 0x3c0) << 22);
		memory.setInt(relocationAddress, iw);
		return 4;
	}

	/**
	 * A 32-bit instruction word, where: - bits 0-5 of the RV go into bits 16-21 of
	 * the IW. - bits 6-9 of the RV go into bits 28-31 of the IW. - bits 10-15 of
	 * the RV go into bits 22-27 of the IW. - bits 16-31 of the RV must be zero.
	 */
	private int relocate_BOL(Memory memory, Address relocationAddress, long rv) throws MemoryAccessException {
		long mask = 0xffff0000L;
		long val = ~mask & rv;
		int iw = memory.getInt(relocationAddress) & 0xffff;
		iw |= ((val & 0x3f) << 16);
		iw |= ((val & 0x3c0) << 22);
		iw |= ((val & 0xfc00) << 12);
		memory.setInt(relocationAddress, iw);
		return 4;
	}

	/**
	 * A 32-bit instruction word, where: - bits 1-15 of the RV go into bits 16-30 of
	 * the IW. - bits 16-31 of the RV must be zero.
	 */
	private int relocate_BR(Memory memory, Address relocationAddress, long rv) throws MemoryAccessException {
		long mask = 0xffff0000L;
		long val = ~mask & rv;
		int iw = memory.getInt(relocationAddress) & 0x8000ffff;
		iw |= ((val & 0xfffe) << 15);
		memory.setInt(relocationAddress, iw);
		return 4;
	}

	/**
	 * A 32-bit instruction word, where: - bits 0-15 of the RV go into bits 12-27 of
	 * the IW. - bits 16-31 of the RV must be zero.
	 */
	private int relocate_RLC(Memory memory, Address relocationAddress, long rv) throws MemoryAccessException {
		long mask = 0xffff0000L;
		long val = ~mask & rv;
		int iw = memory.getInt(relocationAddress) & 0xf0000fff;
		iw |= ((val & 0xffff) << 12);
		memory.setInt(relocationAddress, iw);
		return 4;
	}

	/**
	 * A 32-bit instruction word, where: - bits 0-5 of the RV go into bits 16-21 of
	 * the IW. - bits 6-9 of the RV go into bits 28-31 of the IW. - bits 10-13 of
	 * the RV go into bits 22-25 of the IW. - bits 14-27 of the RV must be zero. -
	 * bits 28-31 of the RV go into bits 12-15 of the IW.
	 */
	private int relocate_ABS(Memory memory, Address relocationAddress, long rv) throws MemoryAccessException {
		long mask = 0x0fffc000L;
		long val = ~mask & rv;
		int iw = memory.getInt(relocationAddress) & 0xc000fff;
		iw |= ((val & 0x3f) << 16);
		iw |= ((val & 0x3c0) << 22);
		iw |= ((val & 0x3c00) << 12);
		iw |= ((val & 0xf0000000) >> 16);
		memory.setInt(relocationAddress, iw);
		return 4;
	}

	/**
	 * A 32-bit instruction word, where: - bits 0-3 of the RV go into bits 8-11 of
	 * the IW. - bits 4-32 of the RV must be zero.
	 */
	@SuppressWarnings("unused")
	private int relocate_SBR(Memory memory, Address relocationAddress, long rv)
			throws MemoryAccessException, NotFoundException {
		long mask = 0xfffffff0L;
		long val = ~mask & rv;

		// oddly this is defined but not in any relocations
		throw new NotFoundException();
	}

	/**
	 * A 16-bit instruction word, where: - bits 8-15 of the RV go into bits 8-15 of
	 * the IW. - bits 0-7 and 16-31 of the RV must be zero.
	 */
	private int relocate_pcpPage(Memory memory, Address relocationAddress, long rv) throws MemoryAccessException {
		long mask = 0xffff00ffL;
		long val = ~mask & rv;
		int iw = memory.getShort(relocationAddress) & 0xff;
		iw |= (val & 0xff00);
		memory.setShort(relocationAddress, (short) iw);
		return 2;
	}

	/**
	 * A 16-bit instruction word, where: - bits 0-5 of the RV go into bits 0-5 of
	 * the IW. - bits 6-15 of the RV must be zero.
	 */
	private int relocate_PI(Memory memory, Address relocationAddress, long rv) throws MemoryAccessException {
		long mask = 0xffffffc0L;
		long val = ~mask & rv;
		int iw = memory.getShort(relocationAddress) & 0xffc0;
		iw |= (val & 0x3f);
		memory.setShort(relocationAddress, (short) iw);
		return 2;
	}
	
	/**
	 * 
	 */
	private int relocate_3POS(Memory memory, Address relocationAddress, long rv) throws MemoryAccessException {
		long mask = 0xfffffff8L;
		long val = ~mask & rv;
		int iw = memory.getInt(relocationAddress);
		iw |= val << 8;
		memory.setInt(relocationAddress, iw);
		return 4;
	}
	
	/**
	 * 
	 */
	private int relocate_5POS(Memory memory, Address relocationAddress, long rv) throws MemoryAccessException {
		long mask = 0xffffffe0L;
		long val = ~mask & rv;
		int iw = memory.getInt(relocationAddress);
		iw |= val << 16;
		memory.setInt(relocationAddress, iw);
		return 4;
	}
	
	/**
	 * 
	 */
	private int relocate_5POS2(Memory memory, Address relocationAddress, long rv) throws MemoryAccessException {
		long mask = 0xffffffe0L;
		long val = ~mask & rv;
		int iw = memory.getInt(relocationAddress);
		iw |= val << 23;
		memory.setInt(relocationAddress, iw);
		return 4;
	}
}
