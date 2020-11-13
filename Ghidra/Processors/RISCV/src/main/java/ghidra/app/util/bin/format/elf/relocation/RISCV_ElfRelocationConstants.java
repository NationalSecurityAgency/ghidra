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

public class RISCV_ElfRelocationConstants {

	/*
	 * A	Addend field in the relocation entry associated with the symbol
	 * B	Base address of a shared object loaded into memory
	 * G	Offset of the symbol into the GOT (Global Offset Table)
	 * S	Value of the symbol in the symbol table
	 * GP	Global Pointer register (x3)
	 */
    public static final int R_RISCV_NONE = 0; // None 
    public static final int R_RISCV_32 = 1; // Runtime relocation word32 = S + A
    public static final int R_RISCV_64 = 2; // Runtime relocation word64 = S + A
    public static final int R_RISCV_RELATIVE = 3; // Runtime relocation word32,64 = B + A
    public static final int R_RISCV_COPY = 4; // Runtime relocation must be in executable. not allowed in shared library
    public static final int R_RISCV_JUMP_SLOT = 5; // Runtime relocation word32,64 = S ;handled by PLT unless LD_BIND_NOW
    public static final int R_RISCV_TLS_DTPMOD32 = 6; // TLS relocation word32 = S->TLSINDEX
    public static final int R_RISCV_TLS_DTPMOD64 = 7; // TLS relocation word64 = S->TLSINDEX
    public static final int R_RISCV_TLS_DTPREL32 = 8; // TLS relocation word32 = TLS + S + A - TLS_TP_OFFSET
    public static final int R_RISCV_TLS_DTPREL64 = 9; // TLS relocation word64 = TLS + S + A - TLS_TP_OFFSET
    public static final int R_RISCV_TLS_TPREL32 = 10; // TLS relocation word32 = TLS + S + A + S_TLS_OFFSET - TLS_DTV_OFFSET
    public static final int R_RISCV_TLS_TPREL64 = 11; // TLS relocation word64 = TLS + S + A + S_TLS_OFFSET - TLS_DTV_OFFSET
    public static final int R_RISCV_BRANCH = 16; // PC-relative branch (SB-Type)
    public static final int R_RISCV_JAL = 17; // PC-relative jump (UJ-Type)
    public static final int R_RISCV_CALL = 18; // PC-relative call MACRO call,tail (auipc+jalr pair)
    public static final int R_RISCV_CALL_PLT = 19; // PC-relative call (PLT) MACRO call,tail (auipc+jalr pair) PIC
    public static final int R_RISCV_GOT_HI20 = 20; // PC-relative GOT reference MACRO la
    public static final int R_RISCV_TLS_GOT_HI20 = 21; // PC-relative TLS IE GOT offset MACRO la.tls.ie
    public static final int R_RISCV_TLS_GD_HI20 = 22; // PC-relative TLS GD reference MACRO la.tls.gd
    public static final int R_RISCV_PCREL_HI20 = 23; // PC-relative reference %pcrel_hi(symbol) (U-Type)
    public static final int R_RISCV_PCREL_LO12_I = 24; // PC-relative reference %pcrel_lo(symbol) (I-Type)
    public static final int R_RISCV_PCREL_LO12_S = 25; // PC-relative reference %pcrel_lo(symbol) (S-Type)
    public static final int R_RISCV_HI20 = 26; // Absolute address %hi(symbol) (U-Type)
    public static final int R_RISCV_LO12_I = 27; // Absolute address %lo(symbol) (I-Type)
    public static final int R_RISCV_LO12_S = 28; // Absolute address %lo(symbol) (S-Type)
    public static final int R_RISCV_TPREL_HI20 = 29; // TLS LE thread offset %tprel_hi(symbol) (U-Type)
    public static final int R_RISCV_TPREL_LO12_I = 30; // TLS LE thread offset %tprel_lo(symbol) (I-Type)
    public static final int R_RISCV_TPREL_LO12_S = 31; // TLS LE thread offset %tprel_lo(symbol) (S-Type)
    public static final int R_RISCV_TPREL_ADD = 32; // TLS LE thread usage %tprel_add(symbol)
    public static final int R_RISCV_ADD8 = 33; // 8-bit label addition word8 = old + S + A
    public static final int R_RISCV_ADD16 = 34; // 16-bit label addition word16 = old + S + A
    public static final int R_RISCV_ADD32 = 35; // 32-bit label addition word32 = old + S + A
    public static final int R_RISCV_ADD64 = 36; // 64-bit label addition word64 = old + S + A
    public static final int R_RISCV_SUB8 = 37; // 8-bit label subtraction word8 = old - S - A
    public static final int R_RISCV_SUB16 = 38; // 16-bit label subtraction word16 = old - S - A
    public static final int R_RISCV_SUB32 = 39; // 32-bit label subtraction word32 = old - S - A
    public static final int R_RISCV_SUB64 = 40; // 64-bit label subtraction word64 = old - S - A
    public static final int R_RISCV_GNU_VTINHERIT = 41; // GNU C++ vtable hierarchy 
    public static final int R_RISCV_GNU_VTENTRY = 42; // GNU C++ vtable member usage 
    public static final int R_RISCV_ALIGN = 43; // Alignment statement 
    public static final int R_RISCV_RVC_BRANCH = 44; // PC-relative branch offset (CB-Type)
    public static final int R_RISCV_RVC_JUMP = 45; // PC-relative jump offset (CJ-Type)
    public static final int R_RISCV_RVC_LUI = 46; // Absolute address (CI-Type)
    public static final int R_RISCV_GPREL_I = 47; // GP-relative reference (I-Type)
    public static final int R_RISCV_GPREL_S = 48; // GP-relative reference (S-Type)
    public static final int R_RISCV_TPREL_I = 49; // TP-relative TLS LE load (I-Type)
    public static final int R_RISCV_TPREL_S = 50; // TP-relative TLS LE store (S-Type)
    public static final int R_RISCV_RELAX = 51; // Instruction pair can be relaxed 
    public static final int R_RISCV_SUB6 = 52; // Local label subtraction 
    public static final int R_RISCV_SET6 = 53; // Local label subtraction 
    public static final int R_RISCV_SET8 = 54; // Local label subtraction 
    public static final int R_RISCV_SET16 = 55; // Local label subtraction 
    public static final int R_RISCV_SET32 = 56; // Local label subtraction
    public static final int R_RISCV_32_PCREL = 57; // 32-bit PC relative
    // 58-191 Reserved Reserved for future standard use 
    // 192-255 Reserved Reserved for nonstandard ABI extensions 
}
