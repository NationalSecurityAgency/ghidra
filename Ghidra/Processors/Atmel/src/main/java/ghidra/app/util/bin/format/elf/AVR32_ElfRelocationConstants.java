/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.elf;

public class AVR32_ElfRelocationConstants {

	/* Atmel AVR32 relocations. */
	// NONE (possibly a placeholder for relocations that are moved) 
	// <align:0 bitpos:0 bitsize:0 complain:dont>
	public static final int R_AVR32_NONE = 0;
	/* Data Relocations */
	// DATA: ((S + A) & 0xffffffff) (Normal Data) 
	// <align:0 bitpos:0 bitsize:32 complain:dont>
	public static final int R_AVR32_32 = 1;
	// DATA: ((S + A) & 0x0000ffff) (Normal Data) 
	// <align:0 bitpos:0 bitsize:16 complain:bitfield>
	public static final int R_AVR32_16 = 2;
	// DATA: ((S + A) & 0x000000ff)(Normal Data) 
	// <align:0 bitpos:0 bitsize:8 complain:bitfield>
	public static final int R_AVR32_8 = 3;
	// DATA: ((S + A - P) & 0xffffffff) (PC-relative)
	// <align:0 bitpos:0 bitsize:32 complain:signed>
	public static final int R_AVR32_32_PCREL = 4;
	// DATA: ((S + A - P) & 0x0000ffff) (PC-relative)
	// <align:0 bitpos:0 bitsize:16 complain:signed>
	public static final int R_AVR32_16_PCREL = 5;
	// DATA: ((S + A - P) & 0x000000ff) (PC-relative)
	// <align:0 bitpos:0 bitsize:8 complain:signed>
	public static final int R_AVR32_8_PCREL = 6;
	// Difference between two labels: L2 - L1. The value of L1 is encoded as S +
	// A,
	// while the initial difference after assembly is
	// inserted into the object file by the assembler.
	// DATA: (S & 0xffffffff)
	// <align:0 bitpos:0 bitsize:32 complain:dont>
	public static final int R_AVR32_DIFF32 = 7;
	// DATA: (S & 0x0000ffff)
	// <align:0 bitpos:0 bitsize:16 complain:signed>
	public static final int R_AVR32_DIFF16 = 8;
	// DATA: (S & 0x000000ff)
	// <align:0 bitpos:0 bitsize:8 complain:signed>
	public static final int R_AVR32_DIFF8 = 9;
	// Reference to a symbol through the Global Offset Table (GOT). The linker
	// will allocate an entry for symbol in the GOT and insert the offset
	// of this entry as the relocation value. A = 0
	// DATA: (G & 0xffffffff)
	// <align:0 bitpos:0 bitsize:32 complain:signed>
	public static final int R_AVR32_GOT32 = 10;
	// DATA: (G & 0x0000ffff)
	// <align:0 bitpos:0 bitsize:16 complain:signed>
	public static final int R_AVR32_GOT16 = 11;
	// DATA: (G & 0x000000ff)
	// <align:0 bitpos:0 bitsize:8 complain:signed>
	public static final int R_AVR32_GOT8 = 12;
	/* Normal Code Relocations */
	// Normal (non-pc-relative) code relocations. Alignment and signedness
	// is indicated by the suffixes. S means signed, U means unsigned.
	// W means word-aligned, H means halfword-aligned, neither means
	// byte-aligned (no alignment.)
	// NORMAL CODE: ((S + A) & 0x1e10ffff) 
	// <align:0 bitpos:0 bitsize:21 complain:signed>
	public static final int R_AVR32_21S = 13;
	// NORMAL CODE: ((S + A) & 0x0000ffff)
	// <align:0 bitpos:0 bitsize:16 complain:unsigned>
	public static final int R_AVR32_16U = 14;
	// NORMAL CODE: ((S + A) & 0x0000ffff) 
	// <align:0 bitpos:0 bitsize:16 complain:signed>
	public static final int R_AVR32_16S = 15;
	// NORMAL CODE: (((S + A)) << 4) & 0x00000ff0)
	// <align:0 bitpos:4 bitsize:8 complain:signed>
	public static final int R_AVR32_8S = 16;
	// NORMAL CODE: ((S + A) & 0x000000ff)
	// <align:0 bitpos:0 bitsize:8 complain:signed>
	public static final int R_AVR32_8S_EXT = 17;
	/* PC-Relative Code Relocations */
	// PC-relative relocations are signed if neither 'U' nor 'S' is
	// specified. However, we explicitly tack on a 'B' to indicate no
	// alignment, to avoid confusion with data relocs. All of these
	// resolve to S + A - P, except the one with 'N' (negated) suffix.
	// This particular one resolves to P - S - A.
	// PC-REL CODE: (((S + A - P) >> 1) & 0x1e10ffff)
	// <align:1 bitpos:0 bitsize:21 complain:signed>
	public static final int R_AVR32_22H_PCREL = 18;
	// PC-REL CODE: (((S + A - P) >> 2) & 0x0000ffff)
	// <align:2 bitpos:0 bitsize:16 complain:signed>
	public static final int R_AVR32_18W_PCREL = 19;
	// PC-REL CODE: ((S + A - P) & 0x0000ffff)
	// <align:0 bitpos:0 bitsize:16 complain:signed>
	public static final int R_AVR32_16B_PCREL = 20;
	// PC-REL CODE: ((P - S - A) & 0x0000ffff)
	// <align:0 bitpos:0 bitsize:16 complain:signed>
	public static final int R_AVR32_16N_PCREL = 21;
	// PC-REL CODE: (((S + A - P) >>> 2) & 0x0000f0ff)
	// <align:2 bitpos:0 bitsize:12 complain:unsigned>
	public static final int R_AVR32_14UW_PCREL = 22;
	// PC-REL CODE: (((S + A - P) >> 1) << 4)
	// Must then: tmp1 = (newValue & 0x00000ff3);
	// Must then: tmp2 = ((newValue & 0x00003000) >> 12); (to match opcode disp)
	// Must then: tmp3 = ((tmp1 << 16) | (tmp2 << 16))
	// Must then: (oldValue | tmp3) & 0xffffffff)
	// <align:1 bitpos:4 bitsize:10 complain:signed>
	public static final int R_AVR32_11H_PCREL = 23;
	// PC-REL CODE: (((S + A - P) >>> 2) & 0x000000ff)
	// <align:2 bitpos:0 bitsize:8 complain:unsigned>
	public static final int R_AVR32_10UW_PCREL = 24;
	// PC-REL CODE: ((((S + A - P) >> 1) << 4) & 0x00000ff0)
	// Must then: (oldValue | newValue << 16) & 0xffffffff)
	// <align:1 bitpos:4 bitsize:8 complain:signed>
	public static final int R_AVR32_9H_PCREL = 25;
	// PC-REL CODE: ((((S + A)  << 4) - P) >>> 2) & 0x000007f0)
	// <align:2 bitpos:4 bitsize:7 complain:unsigned>
	public static final int R_AVR32_9UW_PCREL = 26;
	/* Special Code Relocations */
	// Special CODE: (((S + A) >> 16) & 0x0000ffff)
	// <align:16 bitpos:0 bitsize:16 complain:dont>
	public static final int R_AVR32_HI16 = 27;
	// Special CODE: ((S + A) & 0x0000ffff)
	// <align:0 bitpos:0 bitsize:16 complain:dont>
	public static final int R_AVR32_LO16 = 28;
	/* PIC Relocations */
	// Subtract the link-time address of the GOT from (S + A) and
	// insert the result.
	// PIC: (((S + A) - GOT) & 0xffffffff)
	// <align:0 bitpos:0 bitsize:32 complain:dont>
	public static final int R_AVR32_GOTPC = 29;
	// Reference to a symbol through the GOT. The linker will
	// allocate an entry for symbol in the GOT and insert
	// the offset of this entry as the relocation value.
	// Addend(A) must be zero. As usual, 'S' means signed, 'W' means
	// word-aligned, etc.
	// PIC: ((G >> 2) & 0x1e10ffff)
	// <align:2 bitpos:0 bitsize:21 complain:signed> (Call instructions)
	public static final int R_AVR32_GOTCALL = 30;
	// PIC: ((G >> 2) & 0x1e10ffff)
	// <align:2 bitpos:0 bitsize:21 complain:signed> (lda.w instructions)
	public static final int R_AVR32_LDA_GOT = 31;
	// PIC: (G & 0x1e10ffff)
	// <align:0 bitpos:0 bitsize:21 complain:signed>
	public static final int R_AVR32_GOT21S = 32;
	// PIC: ((G >> 2) & 0x0000ffff)
	// <align:2 bitpos:0 bitsize:16 complain:signed>
	public static final int R_AVR32_GOT18SW = 33;
	// PIC: (G & 0x0000ffff)
	// <align:0 bitpos:0 bitsize:16 complain:signed>
	public static final int R_AVR32_GOT16S = 34;
	// PIC: (((G) << 4) >> 2) & 0x000001f0)
	// <align:2 bitpos:4 bitsize:5 complain:unsigned>
	public static final int R_AVR32_GOT7UW = 35;
	/* Constant Pool Relocations */
	// 32-bit constant pool entry.
	// CONST POOL: ((S + A) & 0xffffffff)
	// <align:0 bitpos:0 bitsize:32 complain:dont>
	public static final int R_AVR32_32_CPENT = 36;
	// Constant pool references. Some of these relocations are signed,
	// others are unsigned. Constant pool always comes after
	// the code that references it.
	// CONST POOL: (((S + A - P) >> 2) & 0x0000ffff)
	// Must then: ((oldValue | newValue) & 0xffffffff)
	// <align:2 bitpos:0 bitsize:16 complain:signed>
	public static final int R_AVR32_CPCALL = 37;
	// CONST POOL: ((S + A - P) & 0x0000ffff)
	// <align:0 bitpos:0 bitsize:16 complain:signed>
	public static final int R_AVR32_16_CP = 38;
	// CONST POOL: ((((S + A - P) >>> 2) << 4) & 0x000007f0)
	// Must then: ((oldValue | newValue << 16) & 0xffffffff)
	// <align:2 bitpos:4 bitsize:7 complain:unsigned>
	public static final int R_AVR32_9W_CP = 39;
	/* Dynamic Relocations */
	// Dynamic: ((B + A) & 0xffffffff)
	// <align:0 bitpos:0 bitsize:32 complain:signed>
	public static final int R_AVR32_RELATIVE = 40;
	// Dynamic: ((S + A) & 0xffffffff)
	// <align:0 bitpos:0 bitsize:32 complain:dont>
	public static final int R_AVR32_GLOB_DAT = 41;
	// Dynamic: ((S + A) & 0xffffffff)
	// <align:0 bitpos:0 bitsize:32 complain:dont>
	public static final int R_AVR32_JMP_SLOT = 42;
	/* Linkrelax Information */
	// Symbol(S) must be the absolute symbol. The Addend(A) specifies
	// the alignment order, e.g. if A is 2, the linker must add
	// padding so that the next address is aligned to a 4-byte
	// boundary.
	// Linkrelax: (P << A)
	// <align:0 bitpos:0 bitsize:0 complain:unsigned>
	public static final int R_AVR32_ALIGN = 43;
	public static final int R_AVR32_NUM = 44;
	/* Total Size in Bytes of the Global Offset Table */
	public static final int DT_AVR32_GOTSZ = 0x70000001;
	/* CPU-Specific flags for the ELF header e_flags field */
	public static final int EF_AVR32_LINKRELAX = 0x01;
	public static final int EF_AVR32_PIC = 0x02;
}
