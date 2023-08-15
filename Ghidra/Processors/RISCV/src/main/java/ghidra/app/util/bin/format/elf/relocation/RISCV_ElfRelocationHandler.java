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

import java.util.Iterator;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.*;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.util.exception.NotFoundException;

/**
 * See https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-elf.adoc for information on the different riscv elf
 * relocation types.  Different relocation types are found in different contexts - not all of which are currently handled here.
 * The contexts we *attempt* to handle include:
 *
 * 1. fully linked Elf executables like the Linux `cp` utility which rely on dynamic linking to libraries like libc.so.6
 * 2. object files compiled with or without Position Independent code (`-fpic`) support
 * 3. Sharable object libraries like `libc.so.6`
 * 3. kernel load modules compiled with position independent code (`-fpic`) support
 *
 * Keep in mind:
 *
 * 1. You may find multiple relocations at any single address.
 * 2. Many relocations and relocation variants are there to support linker/loader optimizations unneeded by Ghidra.
 * 3. Some relocations can only name their target indirectly.  R_RISCV_PCREL_LO12_I references a R_RISCV_PCREL_HI20 relocation,
 *    but needs the symbol referenced by that R_RISCV_PCREL_HI20 in order to compute a PC relative offset.
 * 4. Many discrete symbols can share the same symbol name, e.g. `.L0`.  These symbol names can include non-printing characters like `".L0^B2"`
 *
 */
public class RISCV_ElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_RISCV;
	}

	/**
	 * Get the adjusted 20 high bits of a 32 bit target.  The lower 12 bits will
	 * be found in a later instruction, using a sign-extended signed addition.  If those
	 * 12 bits will be seen as negative, we need to increment the higher bits by one
	 * @param target a 32 bit offset
	 * @return the higher 20 bits possibly incremented by 0x1000
	 */
	static int getHi20(int target) {
		int target_h = target & 0xfffff000;
		// the low order 12 bits are sign-extended before adding, so we may need to adjust the high order 20 bits
		if ((target & 0x00000800) == 0x800) {
			target_h = target_h + 0x1000;
		}
		return target_h;
	}

	/**
	 * get the lower 12 bits of a 32 bit target.  These will typically be added - not or'ed - to
	 * a register holding the higher 20 bits.
	 * @param target a 32 bit offset
	 * @return the lower 12 bits of target
	 */
	static int getLo12(int target) {
		return (target & 0x00000fff);
	}

	/**
	 * PC relative relocations like R_RISCV_PCREL_LO12_I find their target indirectly,
	 * using their symbolValue to locate the address of the matching R_RISCV_PCREL_HI20
	 * or R_RISCV_GOT_HI20.
	 * That *HI20 relocation's symbol value points to the actual target.
	 * This function attempts to locate that actual target by querying Ghidra's Relocation
	 * and Symbol tables. There can be more than one relocation assigned to a given address,
	 * so we need to search.
	 * 
	 * Note that this function probably belongs within ElfRelocationContext, but we have no
	 * published strategy for integration testing that class.
	 *
	 * @return the relocation symbol value associated with the linked relocation type.
	 */
	static int getSymbolValueIndirect(ElfRelocationContext elfRelocationContext, int hi20Addr) {

		int target;
		// Get the relevant Ghidra tables
		Program program = elfRelocationContext.getProgram();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		RelocationTable relocationTable = program.getRelocationTable();

		// get the possible address of R_RISCV_PCREL_HI20 relocation holding the target address
		Address hi20Address = program.getAddressFactory().getAddress(space.getSpaceID(), hi20Addr);

		// we need an address set with one holding a single address to retrieve multiple relocations
		AddressSet relocationAddressSet = new AddressSet(hi20Address);
		// get any relocations at this address - hopefully R_RISCV_PCREL_HI20 and likely R_RISCV_RELAX
		Iterator<Relocation> relocs = relocationTable.getRelocations(relocationAddressSet);
		// search the relocations for a R_RISCV_PCREL_HI20 relocation
		while (relocs.hasNext()) {
			Relocation rel = relocs.next();
			// there may be other valid relocation types to process
			if ((rel.getType() == RISCV_ElfRelocationConstants.R_RISCV_PCREL_HI20) ||
				(rel.getType() == RISCV_ElfRelocationConstants.R_RISCV_GOT_HI20)) {
				int refSymbolIndex = (int) rel.getValues()[0];
//				System.out.println("Matching PCREL_HI20 value is 0x" + Long.toHexString(refSymbolIndex));
				// Note that an elf symbol index is not the same thing as a regular symbol index.
				ElfSymbol elfSym = elfRelocationContext.getSymbol(refSymbolIndex);
				int targetOffset = (int) elfRelocationContext.getSymbolValue(elfSym);
//				System.out.println(
//					"PCREL_HI20 Symbol \"" + elfRelocationContext.getSymbolName(refSymbolIndex) +
//						"\" found with offset 0x" + Long.toHexString(targetOffset));
				// compute the target offset from the referred auipc instruction
				target = targetOffset - hi20Addr;
//				System.out.println("PCREL_HI20 Symbol location is 0x" + Long.toHexString(target));
				return target;
			}
		}
		return 0;
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
		if (RISCV_ElfRelocationConstants.R_RISCV_NONE == type) {
			return RelocationResult.SKIPPED;
		}

		long addend = relocation.hasAddend() ? relocation.getAddend()
				: is32 ? memory.getInt(relocationAddress) : memory.getLong(relocationAddress);
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
		int target = 0;

		int byteLength = 4; // most relocations affect 4-bytes (change if different)

		switch (type) {
			case RISCV_ElfRelocationConstants.R_RISCV_32:
				// Runtime relocation word32 = S + A
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

			case RISCV_ElfRelocationConstants.R_RISCV_64:
				// Runtime relocation word64 = S + A
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

			case RISCV_ElfRelocationConstants.R_RISCV_RELATIVE:
				// Runtime relocation word32,64 = B + A
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

			case RISCV_ElfRelocationConstants.R_RISCV_COPY:
				// Runtime relocation must be in executable. not allowed in shared library
				markAsWarning(program, relocationAddress, "R_RISCV_COPY", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_JUMP_SLOT:
				// Runtime relocation word32,64 = S ;handled by PLT unless LD_BIND_NOW
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

			case RISCV_ElfRelocationConstants.R_RISCV_TLS_DTPMOD32:
				// TLS relocation word32 = S->TLSINDEX
				markAsWarning(program, relocationAddress, "R_RISCV_TLS_DTPMOD32", symbolName,
					symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_TLS_DTPMOD64:
				// TLS relocation word64 = S->TLSINDEX
				markAsWarning(program, relocationAddress, "R_RISCV_TLS_DTPMOD64", symbolName,
					symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_TLS_DTPREL32:
				// TLS relocation word32 = TLS + S + A - TLS_TP_OFFSET
				markAsWarning(program, relocationAddress, "R_RISCV_TLS_DTPREL32", symbolName,
					symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_TLS_DTPREL64:
				// TLS relocation word64 = TLS + S + A - TLS_TP_OFFSET
				markAsWarning(program, relocationAddress, "R_RISCV_TLS_DTPREL64", symbolName,
					symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_TLS_TPREL32:
				// TLS relocation word32 = TLS + S + A + S_TLS_OFFSET - TLS_DTV_OFFSET
				markAsWarning(program, relocationAddress, "R_RISCV_TLS_TPREL32", symbolName,
					symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_TLS_TPREL64:
				// TLS relocation word64 = TLS + S + A + S_TLS_OFFSET - TLS_DTV_OFFSET
				markAsWarning(program, relocationAddress, "R_RISCV_TLS_TPREL64", symbolName,
					symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_BRANCH:
				// PC-relative branch (B-Type)
				target = (int) (addend + symbolValue - offset);
				value32 =
					((target & 0x01e) << 7) | ((target & 0x0800) >> 4) | ((target & 0x03e0) << 20) |
						((target & 0x1000) << 19) | memory.getInt(relocationAddress);
				memory.setInt(relocationAddress, value32);
				break;

			case RISCV_ElfRelocationConstants.R_RISCV_JAL:
				// PC-relative jump (J-Type)
				target = (int) (addend + symbolValue - offset);
				value32 =
					(target & 0xff000) | ((target & 0x00800) << 9) | ((target & 0x007fe) << 20) |
						((target & 0x100000) << 11) | memory.getInt(relocationAddress);
				memory.setInt(relocationAddress, value32);
				break;

			case RISCV_ElfRelocationConstants.R_RISCV_CALL:
				// PC-relative call (PLT) MACRO call,tail (auipc+jalr pair) PIC
				// Identical processing in Ghidra as the following

			case RISCV_ElfRelocationConstants.R_RISCV_CALL_PLT:
				// PC-relative call MACRO call,tail (auipc+jalr pair)
				target = (int) (addend + symbolValue - offset);
				memory.setInt(relocationAddress,
					getHi20(target) | memory.getInt(relocationAddress));
				memory.setInt(relocationAddress.add(4),
					(getLo12(target) << 20) | memory.getInt(relocationAddress.add(4)));
				byteLength = 8;
				break;

			case RISCV_ElfRelocationConstants.R_RISCV_TLS_GOT_HI20:
				// PC-relative TLS IE GOT offset MACRO la.tls.ie
				markAsWarning(program, relocationAddress, "R_RISCV_TLS_GOT_HI20", symbolName,
					symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_TLS_GD_HI20:
				// PC-relative TLS GD reference MACRO la.tls.gd
				markAsWarning(program, relocationAddress, "R_RISCV_TLS_GD_HI20", symbolName,
					symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_GOT_HI20:
				// PC-relative GOT reference MACRO la
			case RISCV_ElfRelocationConstants.R_RISCV_PCREL_HI20:
				// PC-relative, not tested on 32 bit objects
				target = (int) (addend + symbolValue - offset);
				memory.setInt(relocationAddress,
					getHi20(target) | memory.getInt(relocationAddress));
				break;

			case RISCV_ElfRelocationConstants.R_RISCV_PCREL_LO12_I:
				// PC-relative reference %pcrel_lo(symbol) (I-Type), relative to the cited pc_rel_hi20
				target = getSymbolValueIndirect(elfRelocationContext, (int) symbolValue);
				if (target == 0) {
					markAsWarning(program, relocationAddress, "R_RISCV_PCREL_LO12_I", symbolName,
						symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
					return RelocationResult.UNSUPPORTED;
				}
				value32 = ((target & 0x00000fff) << 20) | memory.getInt(relocationAddress);
				memory.setInt(relocationAddress, value32);
				break;

			case RISCV_ElfRelocationConstants.R_RISCV_PCREL_LO12_S:
				// PC-relative reference %pcrel_lo(symbol) (S-Type)
				//    S-type immediates split the 12 bit value into separate 7 bit and 5 bit fields.
				// Warning: untested!
				target = getSymbolValueIndirect(elfRelocationContext, (int) symbolValue);
				if (target == 0) {
					markAsWarning(program, relocationAddress, "R_RISCV_PCREL_LO12_I", symbolName,
						symbolIndex,
						"TODO, needs support ", elfRelocationContext.getLog());
					return RelocationResult.UNSUPPORTED;
				}
				value32 = ((target & 0x000007f) << 25) | (target & 0x00000f80) |
					memory.getInt(relocationAddress);
				memory.setInt(relocationAddress, value32);
				break;

			case RISCV_ElfRelocationConstants.R_RISCV_HI20:
				// Absolute address %hi(symbol) (U-Type)
				value32 =
					(int) ((symbolValue + 0x800) & 0xfffff000) | memory.getInt(relocationAddress);
				memory.setInt(relocationAddress, value32);
				break;

			case RISCV_ElfRelocationConstants.R_RISCV_LO12_I:
				// Absolute address %lo(symbol) (I-Type)
				value32 =
					((int) (symbolValue & 0x00000fff) << 20) | memory.getInt(relocationAddress);
				memory.setInt(relocationAddress, value32);
				break;

			case RISCV_ElfRelocationConstants.R_RISCV_LO12_S:
				// Absolute address %lo(symbol) (S-Type)
				value32 = (int) (symbolValue & 0x00000fff);
				value32 = ((value32 & 0x1f) << 7) | ((value32 & 0xfe0) << 20) |
					memory.getInt(relocationAddress);
				memory.setInt(relocationAddress, value32);
				break;

			case RISCV_ElfRelocationConstants.R_RISCV_TPREL_HI20:
				// TLS LE thread offset %tprel_hi(symbol) (U-Type)
				markAsWarning(program, relocationAddress, "R_RISCV_TPREL_HI20", symbolName,
					symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_TPREL_LO12_I:
				// TLS LE thread offset %tprel_lo(symbol) (I-Type)
				markAsWarning(program, relocationAddress, "R_RISCV_TPREL_LO12_I", symbolName,
					symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_TPREL_LO12_S:
				// TLS LE thread offset %tprel_lo(symbol) (S-Type)
				markAsWarning(program, relocationAddress, "R_RISCV_TPREL_LO12_S", symbolName,
					symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_TPREL_ADD:
				// TLS LE thread usage %tprel_add(symbol)
				markAsWarning(program, relocationAddress, "R_RISCV_TPREL_ADD", symbolName,
					symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_ADD8:
				// 8-bit label addition word8 = old + S + A
				markAsWarning(program, relocationAddress, "R_RISCV_ADD8", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
				value8 = memory.getByte(relocationAddress);
				value8 += (byte) symbolValue;
				value8 += (byte) addend;
				memory.setByte(relocationAddress, value8);
				byteLength = 1;
				break;

			case RISCV_ElfRelocationConstants.R_RISCV_ADD16:
				// 16-bit label addition word16 = old + S + A
				value16 = memory.getShort(relocationAddress);
				value16 += (short) symbolValue;
				value16 += (short) addend;
				memory.setShort(relocationAddress, value16);
				byteLength = 2;
				break;

			case RISCV_ElfRelocationConstants.R_RISCV_ADD32:
				// 32-bit label addition word32 = old + S + A
				value32 = memory.getInt(relocationAddress);
				value32 += (int) symbolValue;
				value32 += (int) addend;
				memory.setInt(relocationAddress, value32);
				break;

			case RISCV_ElfRelocationConstants.R_RISCV_ADD64:
				// 64-bit label addition word64 = old + S + A
				value64 = memory.getLong(relocationAddress);
				value64 += symbolValue;
				value64 += addend;
				memory.setLong(relocationAddress, value64);
				byteLength = 8;
				break;

			case RISCV_ElfRelocationConstants.R_RISCV_SUB8:
				// 8-bit label subtraction word8 = old - S - A
				value8 = memory.getByte(relocationAddress);
				value8 -= (byte) symbolValue;
				value8 -= (byte) addend;
				memory.setByte(relocationAddress, value8);
				byteLength = 1;
				break;

			case RISCV_ElfRelocationConstants.R_RISCV_SUB16:
				// 16-bit label subtraction word16 = old - S - A
				value16 = memory.getShort(relocationAddress);
				value16 -= (short) symbolValue;
				value16 -= (short) addend;
				memory.setShort(relocationAddress, value16);
				byteLength = 2;
				break;

			case RISCV_ElfRelocationConstants.R_RISCV_SUB32:
				// 32-bit label subtraction word32 = old - S - A
				value32 = memory.getInt(relocationAddress);
				value32 -= (int) symbolValue;
				value32 -= (int) addend;
				memory.setInt(relocationAddress, value32);
				break;

			case RISCV_ElfRelocationConstants.R_RISCV_SUB64:
				// 64-bit label subtraction word64 = old - S - A
				value64 = memory.getLong(relocationAddress);
				value64 -= symbolValue;
				value64 -= addend;
				memory.setLong(relocationAddress, value64);
				byteLength = 8;
				break;

			case RISCV_ElfRelocationConstants.R_RISCV_GNU_VTINHERIT:
				// GNU C++ vtable hierarchy 
				markAsWarning(program, relocationAddress, "R_RISCV_GNU_VTINHERIT", symbolName,
					symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_GNU_VTENTRY:
				// GNU C++ vtable member usage 
				markAsWarning(program, relocationAddress, "R_RISCV_GNU_VTENTRY", symbolName,
					symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_ALIGN:
				// Alignment statement 
				markAsWarning(program, relocationAddress, "R_RISCV_ALIGN", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_RVC_BRANCH: {
				// PC-relative branch offset (CB-Type)
				short target_s = (short) (addend + symbolValue - offset);
				// 15   13  |  12 11 10|9 7|       6 5 4 3 2|1 0
				// C.BEQZ offset[8|4:3] src offset[7:6|2:1|5] C1
				value16 = (short) (((target_s & 0x100) << 4) | ((target_s & 0x18) << 7) |
					((target_s & 0xc0) >> 1) |
					((target_s & 0x06) << 2) | ((target_s & 0x20) >> 3) |
					(memory.getShort(relocationAddress) & 0xe383));
				memory.setShort(relocationAddress, value16);
				byteLength = 2;
				break;
			}

			case RISCV_ElfRelocationConstants.R_RISCV_RVC_JUMP: {
				short target_s = (short) (addend + symbolValue - offset);
				// Complicated swizzling going on here.
				// For details, see The RISC-V Instruction Set Manual Volume I: Unprivileged ISA
				// 15  13  |  12 11 10 9 8 7 6 5 3 2|1 0
				// C.J offset[11| 4|9:8|10|6|7|3:1|5] C1
				value16 = (short) (((target_s & 0x800) << 1) | ((target_s & 0x10) << 7) |
					((target_s & 0x300) << 1) |
					((target_s & 0x400) >> 2) | ((target_s & 0x40) << 1) |
					((target_s & 0x80) >> 1) |
					((target_s & 0x0e) << 2) | ((target_s & 0x20) >> 3) |
					(memory.getShort(relocationAddress) & 0xe003));
				memory.setShort(relocationAddress, value16);
				byteLength = 2;
				break;
			}

			case RISCV_ElfRelocationConstants.R_RISCV_RVC_LUI:
				// Absolute address (CI-Type)
				markAsWarning(program, relocationAddress, "R_RISCV_RVC_LUI", symbolName,
					symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_GPREL_I:
				// GP-relative reference (I-Type)
				markAsWarning(program, relocationAddress, "R_RISCV_GPREL_I", symbolName,
					symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_GPREL_S:
				// GP-relative reference (S-Type)
				markAsWarning(program, relocationAddress, "R_RISCV_GPREL_S", symbolName,
					symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_TPREL_I:
				// TP-relative TLS LE load (I-Type)
				markAsWarning(program, relocationAddress, "R_RISCV_TPREL_I", symbolName,
					symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_TPREL_S:
				// TP-relative TLS LE store (S-Type)
				markAsWarning(program, relocationAddress, "R_RISCV_TPREL_S", symbolName,
					symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_RELAX:
				// Instruction pair can be relaxed by the linker/loader- ignore
				return RelocationResult.SKIPPED;

			case RISCV_ElfRelocationConstants.R_RISCV_SUB6:
				// Local label subtraction 
				markAsWarning(program, relocationAddress, "R_RISCV_SUB6", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_SET6:
				// Local label subtraction 
				markAsWarning(program, relocationAddress, "R_RISCV_SET6", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_SET8:
				// Local label subtraction 
				markAsWarning(program, relocationAddress, "R_RISCV_SET8", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_SET16:
				// Local label subtraction 
				markAsWarning(program, relocationAddress, "R_RISCV_SET16", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_SET32:
				// Local label subtraction 
				markAsWarning(program, relocationAddress, "R_RISCV_SET32", symbolName, symbolIndex,
					"TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case RISCV_ElfRelocationConstants.R_RISCV_32_PCREL:
				// 32-bit PC relative
				markAsWarning(program, relocationAddress, "R_RISCV_32_PCREL", symbolName,
					symbolIndex, "TODO, needs support ", elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			default:
				// 58-191 Reserved Reserved for future standard use
				// 192-255 Reserved Reserved for nonstandard ABI extensions
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}
}
