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

/**
 * See https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-elf.adoc for 
 * information on the different RISCV ELF relocation types.  Different relocation types are found 
 * in different contexts - not all of which are currently handled here.
 * 
 * The contexts we *attempt* to handle include:
 *
 * 1. fully linked Elf executables like the Linux `cp` utility which rely on dynamic linking to 
 *    libraries like libc.so.6
 * 2. object files compiled with or without Position Independent code (`-fpic`) support
 * 3. Sharable object libraries like `libc.so.6`
 * 3. kernel load modules compiled with position independent code (`-fpic`) support
 *
 * Keep in mind:
 *
 * 1. You may find multiple relocations at any single address.
 * 2. Many relocations and relocation variants are there to support linker/loader optimizations 
 *    unneeded by Ghidra.
 * 3. Some relocations can only name their target indirectly.  R_RISCV_PCREL_LO12_I references 
 *    a R_RISCV_PCREL_HI20 relocation, but needs the symbol referenced by that R_RISCV_PCREL_HI20 
 *    in order to compute a PC relative offset.
 * 4. Many discrete symbols can share the same symbol name, e.g. `.L0`.  These symbol names can 
 *    include non-printing characters like `".L0^B2"`
 *
 */
public class RISCV_ElfRelocationHandler
		extends AbstractElfRelocationHandler<RISCV_ElfRelocationType, RISCV_ElfRelocationContext> {

	/**
	 * Constructor
	 */
	public RISCV_ElfRelocationHandler() {
		super(RISCV_ElfRelocationType.class);
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_RISCV;
	}

	@Override
	public RISCV_ElfRelocationContext createRelocationContext(ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		return new RISCV_ElfRelocationContext(this, loadHelper, symbolMap);
	}

	@Override
	public int getRelrRelocationType() {
		return RISCV_ElfRelocationType.R_RISCV_RELATIVE.typeId;
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
	 * or R_RISCV_GOT_HI20.  The HI20 relocation's symbol identifies the actual target.
	 * @param elfRelocationContext ELF relocation context for RISCV
	 * @param hi20Symbol symbol which identifies a HI20 relocation offset
	 * @param relocAddrOffsetAdj relocation offset adjustment to be used when computing
	 * actual address offet within the target program.
	 * @return the 32-bit HI20 relative offset value or 0 if HI20 relocation not found
	 */
	private static int getSymbolValueIndirect(RISCV_ElfRelocationContext elfRelocationContext,
			ElfSymbol hi20Symbol, long relocAddrOffsetAdj) {

		ElfRelocation hi20Reloc = elfRelocationContext.getHi20Relocation(hi20Symbol);
		if (hi20Reloc == null) {
			return 0;
		}

		int symIndex = hi20Reloc.getSymbolIndex();
		ElfSymbol sym = elfRelocationContext.getSymbol(symIndex);
		long symOffset = elfRelocationContext.getSymbolValue(sym);

		// must apply HI20 addend to symbol offset
		long targetOffset = symOffset + hi20Reloc.getAddend();

		// must adjust to account for image-base
		long hi20RelocOffset = hi20Reloc.getOffset() + relocAddrOffsetAdj;

		// TODO: should we perform range check for 64-bit case?
		return (int) (targetOffset - hi20RelocOffset);
	}

	@Override
	protected RelocationResult relocate(RISCV_ElfRelocationContext elfRelocationContext,
			ElfRelocation relocation, RISCV_ElfRelocationType type, Address relocationAddress,
			ElfSymbol sym, Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		if (!relocation.hasAddend()) {
			// Implementation only supports Elf_Rela relocations for RISCV
			return RelocationResult.UNSUPPORTED;
		}

		ElfHeader elf = elfRelocationContext.getElfHeader();
		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		long addend = relocation.getAddend();
		long offset = relocationAddress.getOffset();
		long base = elfRelocationContext.getImageBaseWordAdjustmentOffset();

		int symbolIndex = relocation.getSymbolIndex();

		long value64 = 0;
		int value32 = 0;
		short value16 = 0;
		byte value8 = 0;
		int target = 0;

		int byteLength = 4; // most relocations affect 4-bytes (change if different)

		switch (type) {
			case R_RISCV_32:
				// Runtime relocation word32 = S + A
				value32 = (int) (symbolValue + addend);
				memory.setInt(relocationAddress, value32);
				if (symbolIndex != 0 && addend != 0 && !sym.isSection()) {
					warnExternalOffsetRelocation(program, relocationAddress, symbolAddr, symbolName,
						addend, elfRelocationContext.getLog());
					if (elf.is32Bit()) {
						applyComponentOffsetPointer(program, relocationAddress, addend);
					}
				}
				break;

			case R_RISCV_64:
				// Runtime relocation word64 = S + A
				value64 = symbolValue + addend;
				memory.setLong(relocationAddress, value64);
				byteLength = 8;
				if (symbolIndex != 0 && addend != 0 && !sym.isSection()) {
					warnExternalOffsetRelocation(program, relocationAddress, symbolAddr, symbolName,
						addend, elfRelocationContext.getLog());
					if (elf.is64Bit()) {
						applyComponentOffsetPointer(program, relocationAddress, addend);
					}
				}
				break;

			case R_RISCV_RELATIVE:
				// Runtime relocation word32,64 = B + A
				if (elf.is32Bit()) {
					value32 = (int) (base + addend);
					memory.setInt(relocationAddress, value32);
				}
				else {
					value64 = base + addend;
					memory.setLong(relocationAddress, value64);
					byteLength = 8;
				}
				break;

			case R_RISCV_COPY:
				// Runtime relocation must be in executable. not allowed in shared library
				markAsUnsupportedCopy(program, relocationAddress, type, symbolName, symbolIndex,
					sym.getSize(), elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;

			case R_RISCV_JUMP_SLOT:
				// Runtime relocation word32,64 = S ;handled by PLT unless LD_BIND_NOW
				if (elf.is32Bit()) {
					value32 = (int) (symbolValue);
					memory.setInt(relocationAddress, value32);
				}
				else {
					value64 = symbolValue;
					memory.setLong(relocationAddress, value64);
					byteLength = 8;
				}
				break;

//			case R_RISCV_TLS_DTPMOD32: // TLS relocation word32 = S->TLSINDEX
//
//			case R_RISCV_TLS_DTPMOD64: // TLS relocation word64 = S->TLSINDEX
//
//			case R_RISCV_TLS_DTPREL32: // TLS relocation word32 = TLS + S + A - TLS_TP_OFFSET
//
//			case R_RISCV_TLS_DTPREL64: // TLS relocation word64 = TLS + S + A - TLS_TP_OFFSET
//
//			case R_RISCV_TLS_TPREL32:  // TLS relocation word32 = TLS + S + A + S_TLS_OFFSET - TLS_DTV_OFFSET
//
//			case R_RISCV_TLS_TPREL64:  // TLS relocation word64 = TLS + S + A + S_TLS_OFFSET - TLS_DTV_OFFSET

			case R_RISCV_BRANCH:
				// PC-relative branch (SB-Type)
				target = (int) (addend + symbolValue - offset);
				value32 = encodeSBTypeImm(target) |
					(memory.getInt(relocationAddress) & ~encodeSBTypeImm(-1));
				memory.setInt(relocationAddress, value32);
				break;

			case R_RISCV_JAL:
				// PC-relative jump (UJ-Type)
				target = (int) (addend + symbolValue - offset);
				value32 = encodeUJTypeImm(target) |
					(memory.getInt(relocationAddress) & ~encodeUJTypeImm(-1));
				memory.setInt(relocationAddress, value32);
				break;

			case R_RISCV_CALL:
				// PC-relative call (PLT) MACRO call,tail (auipc+jalr pair) PIC
				// Identical processing in Ghidra as the following

			case R_RISCV_CALL_PLT:
				// PC-relative call MACRO call,tail (auipc+jalr pair)
				target = (int) (addend + symbolValue - offset);
				memory.setInt(relocationAddress,
					getHi20(target) | (memory.getInt(relocationAddress) & 0xfff));
				memory.setInt(relocationAddress.add(4),
					(getLo12(target) << 20) | (memory.getInt(relocationAddress.add(4)) & 0xfffff));
				byteLength = 8;
				break;

//			case R_RISCV_TLS_GOT_HI20: // PC-relative TLS IE GOT offset MACRO la.tls.ie
//				
//			case R_RISCV_TLS_GD_HI20:  // PC-relative TLS GD reference MACRO la.tls.gd

			case R_RISCV_GOT_HI20:
				// PC-relative GOT reference MACRO la
			case R_RISCV_PCREL_HI20:
				// PC-relative, not tested on 32 bit objects
				target = (int) (addend + symbolValue - offset);
				memory.setInt(relocationAddress,
					getHi20(target) | (memory.getInt(relocationAddress) & 0xfff));
				break;

			case R_RISCV_PCREL_LO12_I:
				// PC-relative reference %pcrel_lo(symbol) (I-Type), relative to the cited pc_rel_hi20
				target = getSymbolValueIndirect(elfRelocationContext, sym,
					relocationAddress.getOffset() - relocation.getOffset());
				if (target == 0) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"Failed to locate HI20 relocation", elfRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}
				value32 =
					((target & 0x00000fff) << 20) | (memory.getInt(relocationAddress) & 0xfffff);
				memory.setInt(relocationAddress, value32);
				break;

			case R_RISCV_PCREL_LO12_S:
				// PC-relative reference %pcrel_lo(symbol) (S-Type)
				//    S-type immediates split the 12 bit value into separate 7 bit and 5 bit fields.
				// Warning: untested!
				target = getSymbolValueIndirect(elfRelocationContext, sym,
					relocationAddress.getOffset() - relocation.getOffset());
				if (target == 0) {
					markAsError(program, relocationAddress, type, symbolName, symbolIndex,
						"Failed to locate HI20 relocation", elfRelocationContext.getLog());
					return RelocationResult.FAILURE;
				}
				value32 = ((target & 0x000007f) << 25) | (target & 0x00000f80) |
					(memory.getInt(relocationAddress) & 0x1fff07f);
				memory.setInt(relocationAddress, value32);
				break;

			case R_RISCV_HI20:
				// Absolute address %hi(symbol) (U-Type)
				value32 = (int) ((symbolValue + 0x800) & 0xfffff000) |
					(memory.getInt(relocationAddress) & 0xfff);
				memory.setInt(relocationAddress, value32);
				break;

			case R_RISCV_LO12_I:
				// Absolute address %lo(symbol) (I-Type)
				value32 = ((int) (symbolValue & 0x00000fff) << 20) |
					(memory.getInt(relocationAddress) & 0xfffff);
				memory.setInt(relocationAddress, value32);
				break;

			case R_RISCV_LO12_S:
				// Absolute address %lo(symbol) (S-Type)
				value32 = (int) (symbolValue & 0x00000fff);
				value32 = ((value32 & 0x1f) << 7) | ((value32 & 0xfe0) << 20) |
					(memory.getInt(relocationAddress) & 0x1fff07f);
				memory.setInt(relocationAddress, value32);
				break;

//			case R_RISCV_TPREL_HI20: // TLS LE thread offset %tprel_hi(symbol) (U-Type)
//
//			case R_RISCV_TPREL_LO12_I: // TLS LE thread offset %tprel_lo(symbol) (I-Type)
//
//			case R_RISCV_TPREL_LO12_S: // TLS LE thread offset %tprel_lo(symbol) (S-Type)
//
//			case R_RISCV_TPREL_ADD: // TLS LE thread usage %tprel_add(symbol)

			case R_RISCV_ADD8:
				// 8-bit label addition word8 = old + S + A
				value8 = memory.getByte(relocationAddress);
				value8 += (byte) (symbolValue + addend);
				memory.setByte(relocationAddress, value8);
				byteLength = 1;
				break;

			case R_RISCV_ADD16:
				// 16-bit label addition word16 = old + S + A
				value16 = memory.getShort(relocationAddress);
				value16 += (short) (symbolValue + addend);
				memory.setShort(relocationAddress, value16);
				byteLength = 2;
				break;

			case R_RISCV_ADD32:
				// 32-bit label addition word32 = old + S + A
				value32 = memory.getInt(relocationAddress);
				value32 += (int) (symbolValue + addend);
				memory.setInt(relocationAddress, value32);
				break;

			case R_RISCV_ADD64:
				// 64-bit label addition word64 = old + S + A
				value64 = memory.getLong(relocationAddress);
				value64 += (symbolValue + addend);
				memory.setLong(relocationAddress, value64);
				byteLength = 8;
				break;

			case R_RISCV_SUB8:
				// 8-bit label subtraction word8 = old - S - A
				value8 = memory.getByte(relocationAddress);
				value8 -= (byte) (symbolValue + addend);
				memory.setByte(relocationAddress, value8);
				byteLength = 1;
				break;

			case R_RISCV_SUB16:
				// 16-bit label subtraction word16 = old - S - A
				value16 = memory.getShort(relocationAddress);
				value16 -= (short) (symbolValue + addend);
				memory.setShort(relocationAddress, value16);
				byteLength = 2;
				break;

			case R_RISCV_SUB32:
				// 32-bit label subtraction word32 = old - S - A
				value32 = memory.getInt(relocationAddress);
				value32 -= (int) (symbolValue + addend);
				memory.setInt(relocationAddress, value32);
				break;

			case R_RISCV_SUB64:
				// 64-bit label subtraction word64 = old - S - A
				value64 = memory.getLong(relocationAddress);
				value64 -= (symbolValue + addend);
				memory.setLong(relocationAddress, value64);
				byteLength = 8;
				break;

//			case R_RISCV_GNU_VTINHERIT: // GNU C++ vtable hierarchy 
//
//			case R_RISCV_GNU_VTENTRY: // GNU C++ vtable member usage 
//
//			case R_RISCV_ALIGN: // Alignment statement 

			case R_RISCV_RVC_BRANCH: {
				// PC-relative branch offset (CB-Type)
				short target_s = (short) (addend + symbolValue - offset);
				value16 = (short) (encodeCBTypeImm(target_s) |
					(memory.getShort(relocationAddress) & ~encodeCBTypeImm(-1)));
				memory.setShort(relocationAddress, value16);
				byteLength = 2;
				break;
			}

			case R_RISCV_RVC_JUMP: {
				// PC-relative jump offset (CJ-Type)
				short target_s = (short) (addend + symbolValue - offset);
				value16 = (short) (encodeCJTypeImm(target_s) |
					(memory.getShort(relocationAddress) & ~encodeCJTypeImm(-1)));
				memory.setShort(relocationAddress, value16);
				byteLength = 2;
				break;
			}

//			case R_RISCV_RVC_LUI: // Absolute address (CI-Type)
//
//			case R_RISCV_GPREL_I: // GP-relative reference (I-Type)
//
//			case R_RISCV_GPREL_S: // GP-relative reference (S-Type)
//
//			case R_RISCV_TPREL_I: // TP-relative TLS LE load (I-Type)
//
//			case R_RISCV_TPREL_S: // TP-relative TLS LE store (S-Type)

			case R_RISCV_RELAX:
				// Instruction pair can be relaxed by the linker/loader- ignore
				return RelocationResult.SKIPPED;

			case R_RISCV_SUB6:
				int loc8 = memory.getByte(relocationAddress);
				value8 = (byte) (symbolValue + addend);
				value8 = (byte) ((loc8 & 0xc0) | (((loc8 & 0x3f) - value8) & 0x3f));
				memory.setByte(relocationAddress, value8);
				byteLength = 1;
				break;

			case R_RISCV_SET6:
				loc8 = memory.getByte(relocationAddress);
				value8 = (byte) (symbolValue + addend);
				value8 = (byte) ((loc8 & 0xc0) | (value8 & 0x3f));
				memory.setByte(relocationAddress, value8);
				byteLength = 1;
				break;

			case R_RISCV_SET8:
				value8 = (byte) (symbolValue + addend);
				memory.setByte(relocationAddress, value8);
				byteLength = 1;
				break;

			case R_RISCV_SET16:
				value16 = (short) (symbolValue + addend);
				memory.setShort(relocationAddress, value8);
				byteLength = 2;
				break;

			case R_RISCV_32_PCREL:
			case R_RISCV_SET32:
				value32 = (int) (symbolValue + addend);
				memory.setInt(relocationAddress, value8);
				break;

			default:
				// 58-191 Reserved Reserved for future standard use
				// 192-255 Reserved Reserved for nonstandard ABI extensions
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}

	private static int getBitField(int val, int shiftRight, int bitSize) {
		return ((val >> shiftRight) & ((1 << bitSize) - 1));
	}

	private static int encodeSBTypeImm(int val) {
		return (getBitField(val, 1, 4) << 8) | (getBitField(val, 5, 6) << 25) |
			(getBitField(val, 11, 1) << 7) | (getBitField(val, 12, 1) << 31);
	}

	private static int encodeUJTypeImm(int val) {
		return (getBitField(val, 1, 10) << 21) | (getBitField(val, 11, 1) << 20) |
			(getBitField(val, 12, 8) << 12) | (getBitField(val, 20, 1) << 31);
	}

	private static int encodeCBTypeImm(int val) {
		return (getBitField(val, 1, 2) << 3) | (getBitField(val, 3, 2) << 10) |
			(getBitField(val, 5, 1) << 2) | (getBitField(val, 6, 2) << 5) |
			(getBitField(val, 8, 1) << 12);
	}

	private static int encodeCJTypeImm(int val) {
		return (getBitField(val, 1, 3) << 3) | (getBitField(val, 4, 1) << 11) |
			(getBitField(val, 5, 1) << 2) | (getBitField(val, 6, 1) << 7) |
			(getBitField(val, 7, 1) << 6) | (getBitField(val, 8, 2) << 9) |
			(getBitField(val, 10, 1) << 8) | (getBitField(val, 11, 1) << 12);
	}

}
