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
import ghidra.util.exception.NotFoundException;

public class TRICOREElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_TRICORE;
	}

	@Override
	public void relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation, Address relocationAddress)
			throws MemoryAccessException, NotFoundException {

		ElfHeader elf = elfRelocationContext.getElfHeader();
		if (!canRelocate(elf)) {
			return;
		}

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		int type = relocation.getType();

		if (TRICOREElfRelocationConstants.R_TRICORE_NONE == type) {
			return;
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

		int rv = 0;

		 /**
		  * Key S indicates the final value assigned to the symbol referenced in the relocation record.
		  * Key A is the addend value specified in the relocation record.
		  * Key P indicates the address of the relocation (for example, the address being modified).
		  * Key A[0] is the content of the small data base register A[0].
		  */
		switch (type) {
		case TRICOREElfRelocationConstants.R_TRICORE_32REL:   //word32 S + A - P
			rv = (int)(symbolValue + addend - offset);
			relocate_word32(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_32ABS:   //word32 S + A
			rv = (int)(symbolValue + addend);
			relocate_word32(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_24REL:   //relB S + A - P
			rv = (int)(symbolValue + addend - offset);
			relocate_relB(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_24ABS:   //absB S + A
			rv = (int)(symbolValue + addend);
			relocate_absB(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_16SM:    //BOL S + A - A[0]
			markAsWarning(program, relocationAddress, "R_TRICORE_16SM", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog()); 
			//relocate_BOL(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_HI:      //RLC S + A + 8000H >> 16
			rv = ((int)(symbolValue + addend) + 0x8000) >> 16;
			relocate_RLC(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_LO:      //RLC S + A & FFFFH
			rv = (int)(symbolValue + addend) & 0xffff;
			relocate_RLC(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_LO2:     //BOL S + A & FFFFH
			rv = (int)(symbolValue + addend) & 0xffff;
			relocate_BOL(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_18ABS:   //ABS S + A
			rv = (int)(symbolValue + addend);
			relocate_ABS(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_10SM:    //BO S + A - A[0]
			markAsWarning(program, relocationAddress, "R_TRICORE_10SM", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog()); 
			//relocate_BO(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_15REL:   //BR S + A - P
			rv = (int)(symbolValue + addend - offset);
			relocate_BR(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_10LI:    //BO S + A - A[1]
			markAsWarning(program, relocationAddress, "R_TRICORE_10LI", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog()); 
			//relocate_BO(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_16LI:    //BOL S + A - A[1]
			markAsWarning(program, relocationAddress, "R_TRICORE_16LI", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog()); 
			//relocate_BOL(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_10A8:    //BO S + A - A[8]
			markAsWarning(program, relocationAddress, "R_TRICORE_10A8", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog()); 
			//relocate_BO(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_16A8:    //BOL S + A - A[8]
			markAsWarning(program, relocationAddress, "R_TRICORE_16A8", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog()); 
			//relocate_BOL(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_10A9:    //BO S + A - A[9]
			markAsWarning(program, relocationAddress, "R_TRICORE_16A9", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog()); 
			//relocate_BO(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_16A9:    //BOL S + A - A[9]
			markAsWarning(program, relocationAddress, "R_TRICORE_16A9", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog()); 
			//relocate_BOL(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_PCPHI:   //word16 S + A >> 16
			rv = (int)(symbolValue + addend) >> 16;
			relocate_word16(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_PCPLO:   //word16 S + A & FFFFH
			rv = (int)(symbolValue + addend) & 0xffff;
			relocate_word16(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_PCPPAGE: //pcpPage S + A & FF00H
			rv = (int)(symbolValue + addend) & 0xff00;
			relocate_pcpPage(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_PCPOFF:  //PI (S + A >> 2) & 3FH
			rv = ((int)(symbolValue + addend) >> 2) & 0x3f;
			relocate_PI(memory, relocationAddress, rv);
			break;
		case TRICOREElfRelocationConstants.R_TRICORE_PCPTEXT: //word16 (S + A >> 1) & FFFFH
			rv = ((int)(symbolValue + addend) >> 1) & 0xffff;
			relocate_word16(memory, relocationAddress, rv);
			break;
		default:
			markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName, elfRelocationContext.getLog());
			break;
		}
	}

	//TODO  how bad is this approach, not sure how java handles bit manipulation
	//      at this level, or just in a general a class exists that excels at these
	//      operations?

	//  RV = Relocation Value. IW = Instruction Word.

	/**
	 * A 32-bit field occupying four bytes. This address is NOT required to be 4-byte aligned.
	 */
	private void relocate_word32(Memory memory, Address relocationAddress, int rv) throws MemoryAccessException {
		memory.setInt(relocationAddress, rv);
	}

	/**
	 * A 16-bit field occupying two bytes.
	 */
	private void relocate_word16(Memory memory, Address relocationAddress, int rv) throws MemoryAccessException {
		memory.setShort(relocationAddress, (short)rv);
	}

	/**
	 * A 32-bit instruction word, where:
	 * - bits 1-16 of the RV go into bits 16-31 of the IW.
	 * - bits 17-24 of the RV go into bits 8-15 of the IW.
	 * - the RV must be in the range [-16777216,16777214].
	 *   bit 0 of the RV must be zero.
	 */
	private void relocate_relB(Memory memory, Address relocationAddress, int rv) throws MemoryAccessException {
		if (rv < -16777216 || rv > 16777214 || (rv & 1) != 0) {
			throw new MemoryAccessException();
		}

		int iw = memory.getInt(relocationAddress) & 0xff;
		iw |= ((rv & 0x1fffe) << 15);
		iw |= ((rv & 0x1fe0000) >> 9);
		memory.setInt(relocationAddress, iw);
	}

	/**
	 * A 32-bit instruction word, where:
	 * - bits 1-16 of the RV go into bits 16-31 of the IW.
	 * - bits 17-20 of the RV go into bits 8-11 of the IW.
	 * - bits 0 and 21 to 27 of the RV must be zero.
	 * - bits 28-31 of the RV go into bits 12-15 of the IW.
	 */
	private void relocate_absB(Memory memory, Address relocationAddress, int rv) throws MemoryAccessException {
		if ((0xfe00001 & rv) != 0) {
			throw new MemoryAccessException();
		}
		int iw = memory.getInt(relocationAddress) & 0xff;
		iw |= ((rv & 0x1fffe) << 15);
		iw |= ((rv & 0x1e0000) >> 9);
		iw |= ((rv & 0xf0000000) >> 16);
		memory.setInt(relocationAddress, iw);
	}

	/**
	 * A 32-bit instruction word where:
	 * - bits 0-5 of the RV go into bits 16-21 of the IW.
	 * - bits 6-9 of the RV go into bits 28-31 of the IW.
	 * - bits 10-31 of the RV must be zero.
	 */
	private void relocate_BO(Memory memory, Address relocationAddress, int rv) throws MemoryAccessException {
		if ((0xfffffc00 & rv) != 0) {
			throw new MemoryAccessException();
		}
		int iw = memory.getInt(relocationAddress) & 0xfc0ffff;
		iw |= ((rv & 0x3f) << 16);
		iw |= ((rv & 0x3c0) << 22);
		memory.setInt(relocationAddress, iw);
	}

	/**
	 * A 32-bit instruction word, where:
	 * - bits 0-5 of the RV go into bits 16-21 of the IW.
	 * - bits 6-9 of the RV go into bits 28-31 of the IW.
	 * - bits 10-15 of the RV go into bits 22-27 of the IW.
	 * - bits 16-31 of the RV must be zero.
	 */
	private void relocate_BOL(Memory memory, Address relocationAddress, int rv) throws MemoryAccessException {
		if ((0xffff0000 & rv) != 0) {
			throw new MemoryAccessException();
		}
		int iw = memory.getInt(relocationAddress) & 0xffff;
		iw |= ((rv & 0x3f) << 16);
		iw |= ((rv & 0x3c0) << 22);
		iw |= ((rv & 0xfc00) << 12);
		memory.setInt(relocationAddress, iw);
	}

	/**
	 * A 32-bit instruction word, where:
	 * - bits 1-15 of the RV go into bits 16-30 of the IW.
	 * - bits 16-31 of the RV must be zero.
	 */
	private void relocate_BR(Memory memory, Address relocationAddress, int rv) throws MemoryAccessException {
		if ((0xffff0000 & rv) != 0) {
			throw new MemoryAccessException();
		}
		int iw = memory.getInt(relocationAddress) & 0x8000ffff;
		iw |= ((rv & 0xfffe) << 15);
		memory.setInt(relocationAddress, iw);
	}

	/**
	 * A 32-bit instruction word, where:
	 * - bits 0-15 of the RV go into bits 12-27 of the IW.
	 * - bits 16-31 of the RV must be zero.
	 */
	private void relocate_RLC(Memory memory, Address relocationAddress, int rv) throws MemoryAccessException {
		if ((0xffff0000 & rv) != 0) {
			throw new MemoryAccessException();
		}
		int iw = memory.getInt(relocationAddress) & 0xf0000fff;
		iw |= ((rv & 0xffff) << 12);
		memory.setInt(relocationAddress, iw);
	}

	/**
	 * A 32-bit instruction word, where:
	 * - bits 0-5 of the RV go into bits 16-21 of the IW.
	 * - bits 6-9 of the RV go into bits 28-31 of the IW.
	 * - bits 10-13 of the RV go into bits 22-25 of the IW.
	 * - bits 14-27 of the RV must be zero.
	 * - bits 28-31 of the RV go into bits 12-15 of the IW.
	 */
	private void relocate_ABS(Memory memory, Address relocationAddress, int rv) throws MemoryAccessException {
		if ((0xfffc000 & rv) != 0) {
			throw new MemoryAccessException();
		}
		int iw = memory.getInt(relocationAddress) & 0xc000fff;
		iw |= ((rv & 0x3f) << 16);
		iw |= ((rv & 0x3c0) << 22);
		iw |= ((rv & 0x3c00) << 12);
		iw |= ((rv & 0xf0000000) >> 16);
		memory.setInt(relocationAddress, iw);
	}

	/**
	 *  A 32-bit instruction word, where:
	 *  - bits 0-3 of the RV go into bits 8-11 of the IW.
	 *  - bits 4-32 of the RV must be zero.
	 */
	@SuppressWarnings("unused")
	private void relocate_SBR(Memory memory, Address relocationAddress, int rv) throws MemoryAccessException, NotFoundException {
		// oddly this is defined but not in any relocations
		throw new NotFoundException();
	}

	/**
	 * A 16-bit instruction word, where:
	 * - bits 8-15 of the RV go into bits 8-15 of the IW.
	 * - bits 0-7 and 16-31 of the RV must be zero.
	 */
	private void relocate_pcpPage(Memory memory, Address relocationAddress, int rv) throws MemoryAccessException {
		if ((0xffff00ff & rv) != 0) {
			throw new MemoryAccessException();
		}
		int iw = memory.getShort(relocationAddress) & 0xff;
		iw |= (rv & 0xff00);
		memory.setShort(relocationAddress, (short)iw);
	}

	/**
	 * A 16-bit instruction word, where:
	 * - bits 0-5 of the RV go into bits 0-5 of the IW.
	 * - bits 6-15 of the RV must be zero.
	 */
	private void relocate_PI(Memory memory, Address relocationAddress, int rv) throws MemoryAccessException {
		if ((0xffffffc0 & rv) != 0) {
			throw new MemoryAccessException();
		}
		int iw = memory.getShort(relocationAddress) & 0xffc0;
		iw |= (rv & 0x3f);
		memory.setShort(relocationAddress, (short)iw);
	}
 }
