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

public class Tricore_ElfRelocationHandler
		extends AbstractElfRelocationHandler<Tricore_ElfRelocationType, ElfRelocationContext<?>> {

	/**
	 * Constructor
	 */
	public Tricore_ElfRelocationHandler() {
		super(Tricore_ElfRelocationType.class);
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_TRICORE;
	}

	@Override
	public int getRelrRelocationType() {
		return Tricore_ElfRelocationType.R_TRICORE_RELATIVE.typeId;
	}

	@Override
	protected RelocationResult relocate(ElfRelocationContext<?> elfRelocationContext,
			ElfRelocation relocation, Tricore_ElfRelocationType type, Address relocationAddress,
			ElfSymbol sym, Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		long addend =
			relocation.hasAddend() ? relocation.getAddend() : memory.getInt(relocationAddress);
		long offset = relocationAddress.getOffset();
		int symbolIndex = relocation.getSymbolIndex();

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
			case R_TRICORE_32REL: // word32 S + A - P
				rv = symbolValue + addend - offset;
				byteLength = relocate_word32(memory, relocationAddress, rv);
				break;
			case R_TRICORE_32ABS: // word32 S + A
				rv = symbolValue + addend;
				byteLength = relocate_word32(memory, relocationAddress, rv);
				break;
			case R_TRICORE_24REL: // relB S + A - P
				rv = symbolValue + addend - offset;
				byteLength = relocate_relB(memory, relocationAddress, rv);
				break;
			case R_TRICORE_24ABS: // absB S + A
				rv = symbolValue + addend;
				byteLength = relocate_absB(memory, relocationAddress, rv);
				break;

			/**
			case R_TRICORE_16SM: // BOL S + A - A[0]
				break;
			**/

			case R_TRICORE_HI: // RLC S + A + 8000H >> 16
				rv = (symbolValue + addend + 0x8000) >> 16;
				byteLength = relocate_RLC(memory, relocationAddress, rv);
				break;
			case R_TRICORE_LO: // RLC S + A & FFFFH
				rv = (symbolValue + addend) & 0xffff;
				byteLength = relocate_RLC(memory, relocationAddress, rv);
				break;
			case R_TRICORE_LO2: // BOL S + A & FFFFH
				rv = (symbolValue + addend) & 0xffff;
				byteLength = relocate_BOL(memory, relocationAddress, rv);
				break;
			case R_TRICORE_18ABS: // ABS S + A
				rv = symbolValue + addend;
				byteLength = relocate_ABS(memory, relocationAddress, rv);
				break;

			/**
			case R_TRICORE_10SM: // BO S + A - A[0]
				break;
			**/

			case R_TRICORE_15REL: // BR S + A - P
				rv = symbolValue + addend - offset;
				byteLength = relocate_BR(memory, relocationAddress, rv);
				break;

			/**
			case R_TRICORE_10LI: // BO S + A - A[1]
				break;
			case R_TRICORE_16LI: // BOL S + A - A[1]
				break;
			case R_TRICORE_10A8: // BO S + A - A[8]
				break;
			case R_TRICORE_16A8: // BOL S + A - A[8]
				break;
			case R_TRICORE_10A9: // BO S + A - A[9]
				break;
			case R_TRICORE_16A9: // BOL S + A - A[9]
				break;
			case R_TRICORE_10OFF:
				break;
			**/

			case R_TRICORE_16OFF:
				rv = symbolValue + addend;
				byteLength = relocate_BOL(memory, relocationAddress, rv);
				break;

			/**
			case R_TRICORE_8ABS:
				break;
			case R_TRICORE_16ABS:
				break;
			case R_TRICORE_16BIT:
				break;
			**/

			case R_TRICORE_3POS:
				rv = symbolValue + addend;
				byteLength = relocate_3POS(memory, relocationAddress, rv);
				break;
			case R_TRICORE_5POS:
				rv = symbolValue + addend;
				byteLength = relocate_5POS(memory, relocationAddress, rv);
				break;
			case R_TRICORE_PCPHI: // word16 S + A >> 16
				rv = (symbolValue + addend) >> 16;
				byteLength = relocate_word16(memory, relocationAddress, rv);
				break;
			case R_TRICORE_PCPLO: // word16 S + A & FFFFH
				rv = (symbolValue + addend) & 0xffff;
				byteLength = relocate_word16(memory, relocationAddress, rv);
				break;
			case R_TRICORE_PCPPAGE: // pcpPage S + A & FF00H
				rv = (symbolValue + addend) & 0xff00;
				byteLength = relocate_pcpPage(memory, relocationAddress, rv);
				break;
			case R_TRICORE_PCPOFF: // PI (S + A >> 2) & 3FH
				rv = ((symbolValue + addend) >> 2) & 0x3f;
				byteLength = relocate_PI(memory, relocationAddress, rv);
				break;
			case R_TRICORE_PCPTEXT: // word16 (S + A >> 1) & FFFFH
				rv = ((symbolValue + addend) >> 1) & 0xffff;
				byteLength = relocate_word16(memory, relocationAddress, rv);
				break;
			case R_TRICORE_5POS2:
				rv = (symbolValue + addend);
				byteLength = relocate_5POS2(memory, relocationAddress, rv);
				break;

			/**
			case R_TRICORE_BRCC:
				break;
			case R_TRICORE_BRCZ:
				break;
			case R_TRICORE_BRNN:
				break;
			case R_TRICORE_RRN:
				break;
			case R_TRICORE_4CONST:
				break;
			case R_TRICORE_4REL:
				break;
			case R_TRICORE_4REL2:
				break;
			case R_TRICORE_5POS3:
				break;
			case R_TRICORE_4OFF:
				break;
			case R_TRICORE_4OFF2:
				break;
			case R_TRICORE_4OFF4:
				break;
			case R_TRICORE_42OFF:
				break;
			case R_TRICORE_42OFF2:
				break;
			case R_TRICORE_42OFF4:
				break;
			case R_TRICORE_2OFF:
				break;
			case R_TRICORE_8CONST2:
				break;
			case R_TRICORE_4POS:
				break;
			case R_TRICORE_16SM2:
				break;
			case R_TRICORE_5REL:
				break;
			case R_TRICORE_VTENTRY:
				break;
			case R_TRICORE_VTINHERIT:
				break;
			case R_TRICORE_PCREL16:
				break;
			case R_TRICORE_PCREL8:
				break;
			case R_TRICORE_GOT:
				break;
			case R_TRICORE_GOT2:
				break;
			case R_TRICORE_GOTHI:
				break;
			case R_TRICORE_GOTLO:
				break;
			case R_TRICORE_GOTLO2:
				break;
			case R_TRICORE_GOTUP:
				break;
			case R_TRICORE_GOTOFF:
				break;
			case R_TRICORE_GOTOFF2:
				break;
			case R_TRICORE_GOTOFFHI:
				break;
			case R_TRICORE_GOTOFFLO:
				break;
			case R_TRICORE_GOTOFFLO2:
				break;
			case R_TRICORE_GOTOFFUP:
				break;
			case R_TRICORE_GOTPC:
				break;
			case R_TRICORE_GOTPC2:
				break;
			case R_TRICORE_GOTPCHI:
				break;
			case R_TRICORE_GOTPCLO:
				break;
			case R_TRICORE_GOTPCLO2:
				break;
			case R_TRICORE_GOTCPUP:
				break;
			case R_TRICORE_PLT:
				break;
			**/

			case R_TRICORE_GLOB_DAT:
			case R_TRICORE_JMP_SLOT:
				memory.setInt(relocationAddress, (int) symbolValue);
				break;

			case R_TRICORE_RELATIVE:
				long base = program.getImageBase().getOffset();
				rv = (int) (base + addend);
				byteLength = relocate_word32(memory, relocationAddress, rv);
				break;

			case R_TRICORE_COPY:
				markAsUnsupportedCopy(program, relocationAddress, type, symbolName, symbolIndex,
					sym.getSize(), elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case R_TRICORE_BITPOS:
				// This reads as a pseudo relocation, possibly do RelocationResult.PARTIAL instead?
				return RelocationResult.SKIPPED;

			/**
			case R_TRICORE_SBREG_S2:
				break;
			case R_TRICORE_SBREG_S1:
				break;
			case R_TRICORE_SBREG_D:
				break;
			**/

			default:
				break;
		}

		if (byteLength <= 0) {
			markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
				elfRelocationContext.getLog());
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
	private int relocate_word32(Memory memory, Address relocationAddress, long rv)
			throws MemoryAccessException {
		memory.setInt(relocationAddress, (int) rv);
		return 4;
	}

	/**
	 * A 16-bit field occupying two bytes.
	 */
	private int relocate_word16(Memory memory, Address relocationAddress, long rv)
			throws MemoryAccessException {
		memory.setShort(relocationAddress, (short) rv);
		return 2;
	}

	/**
	 * A 32-bit instruction word, where: - bits 1-16 of the RV go into bits 16-31 of
	 * the IW. - bits 17-24 of the RV go into bits 8-15 of the IW. - the RV must be
	 * in the range [-16777216,16777214]. bit 0 of the RV must be zero.
	 */
	private int relocate_relB(Memory memory, Address relocationAddress, long rv)
			throws MemoryAccessException {
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
	private int relocate_absB(Memory memory, Address relocationAddress, long rv)
			throws MemoryAccessException {
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
	private int relocate_BO(Memory memory, Address relocationAddress, long rv)
			throws MemoryAccessException {
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
	private int relocate_BOL(Memory memory, Address relocationAddress, long rv)
			throws MemoryAccessException {
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
	private int relocate_BR(Memory memory, Address relocationAddress, long rv)
			throws MemoryAccessException {
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
	private int relocate_RLC(Memory memory, Address relocationAddress, long rv)
			throws MemoryAccessException {
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
	private int relocate_ABS(Memory memory, Address relocationAddress, long rv)
			throws MemoryAccessException {
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
	private int relocate_pcpPage(Memory memory, Address relocationAddress, long rv)
			throws MemoryAccessException {
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
	private int relocate_PI(Memory memory, Address relocationAddress, long rv)
			throws MemoryAccessException {
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
	private int relocate_3POS(Memory memory, Address relocationAddress, long rv)
			throws MemoryAccessException {
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
	private int relocate_5POS(Memory memory, Address relocationAddress, long rv)
			throws MemoryAccessException {
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
	private int relocate_5POS2(Memory memory, Address relocationAddress, long rv)
			throws MemoryAccessException {
		long mask = 0xffffffe0L;
		long val = ~mask & rv;
		int iw = memory.getInt(relocationAddress);
		iw |= val << 23;
		memory.setInt(relocationAddress, iw);
		return 4;
	}
}
