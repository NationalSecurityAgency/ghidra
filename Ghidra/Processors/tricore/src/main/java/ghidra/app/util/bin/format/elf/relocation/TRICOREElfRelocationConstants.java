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

public class TRICOREElfRelocationConstants {

	// e_flags Identifying TriCore/PCP Derivatives
	public static final int EF_TRICORE_V1_1 = 0x80000000;
	public static final int EF_TRICORE_V1_2 = 0x40000000;
	public static final int EF_TRICORE_V1_3 = 0x20000000;
	public static final int EF_TRICORE_PCP2 = 0x02000000;

	// TriCore Section Attribute Flags
	public static final int SHF_TRICORE_ABS = 0x400;
	public static final int SHF_TRICORE_NOREAD = 0x800;

	public static final int R_TRICORE_NONE = 0; // none none
	public static final int R_TRICORE_32REL = 1; // word32 S + A - P
	public static final int R_TRICORE_32ABS = 2; // word32 S + A
	public static final int R_TRICORE_24REL = 3; // relB S + A - P
	public static final int R_TRICORE_24ABS = 4; // absB S + A
	public static final int R_TRICORE_16SM = 5; // BOL S + A - A[0]
	public static final int R_TRICORE_HI = 6; // RLC S + A + 8000H >> 16
	public static final int R_TRICORE_LO = 7; // RLC S + A & FFFFH
	public static final int R_TRICORE_LO2 = 8; // BOL S + A & FFFFH
	public static final int R_TRICORE_18ABS = 9; // ABS S + A
	public static final int R_TRICORE_10SM = 10; // BO S + A - A[0]
	public static final int R_TRICORE_15REL = 11; // BR S + A - P

	/*
	 * GNU extensions
	 */
	public static final int R_TRICORE_10LI = 12; // BO S + A - A[1]
	public static final int R_TRICORE_16LI = 13; // BOL S + A - A[1]
	public static final int R_TRICORE_10A8 = 14; // BO S + A - A[8]
	public static final int R_TRICORE_16A8 = 15; // BOL S + A - A[8]
	public static final int R_TRICORE_10A9 = 16; // BO S + A - A[9]
	public static final int R_TRICORE_16A9 = 17; // BOL S + A - A[9]
	public static final int R_TRICORE_10OFF = 18; // BO 10 bit data offset
	public static final int R_TRICORE_16OFF = 19; // bolC 16 bit data offset
	public static final int R_TRICORE_8ABS = 20; // 8 bit absolute data relocation
	public static final int R_TRICORE_16ABS = 21; // 16 bit absolute data relocation
	public static final int R_TRICORE_16BIT = 22; // absBb 1 bit relocation
	public static final int R_TRICORE_3POS = 23; // absBp 3 bit bit position
	public static final int R_TRICORE_5POS = 24; // bitP1 5 bit bit position

	/*
	 * PCP relocations
	 */
	public static final int R_TRICORE_PCPHI = 25; // word16 S + A >> 16
	public static final int R_TRICORE_PCPLO = 26; // word16 S + A & FFFFH
	public static final int R_TRICORE_PCPPAGE = 27; // pcpPage S + A & FF00H
	public static final int R_TRICORE_PCPOFF = 28; // PI (S + A >> 2) & 3FH
	public static final int R_TRICORE_PCPTEXT = 29; // word16 (S + A >> 1) & FFFFH

	/*
	 * More GNU extensions
	 */
	public static final int R_TRICORE_5POS2 = 30; // bitP2 5 bit bit position
	public static final int R_TRICORE_BRCC = 31; // brcC 4 bit signed offset
	public static final int R_TRICORE_BRCZ = 32; // brcC2 4 bit unsigned offset
	public static final int R_TRICORE_BRNN = 33; // brnN 5 bit bit position
	public static final int R_TRICORE_RRN = 34; // rrN 2 bit unsigned constant
	public static final int R_TRICORE_4CONST = 35; // sbcC 4 bit signed constant
	public static final int R_TRICORE_4REL = 36; // sbcD/sbrD 5 bit PC-relative, zero-extended displacement
	public static final int R_TRICORE_4REL2 = 37; // sbrD 5 bit PC-relative, one-extended displacement
	public static final int R_TRICORE_5POS3 = 38; // sbrN 5 bit bit position
	public static final int R_TRICORE_4OFF = 39; // slroO 4 bit zero-extended offset
	public static final int R_TRICORE_4OFF2 = 40; // slroO2 5 bit zero-extended offset
	public static final int R_TRICORE_4OFF4 = 41; // slroO4 6 bit zero-extended offset
	public static final int R_TRICORE_42OFF = 42; // sroO 4 bit zero-extended offset
	public static final int R_TRICORE_42OFF2 = 43; // sroO2 5 bit zero-extended offset
	public static final int R_TRICORE_42OFF4 = 44; // slroO4 6 bit zero-extended offset
	public static final int R_TRICORE_2OFF = 45; // srrsN 2 bit zero-extended constant
	public static final int R_TRICORE_8CONST2 = 46; // scC 8 bit zero-extended offset
	public static final int R_TRICORE_4POS = 47; // sbrnN 4 bit zero-extended constant
	public static final int R_TRICORE_16SM2 = 48; // rlcC 16 bit small data section relocation
	public static final int R_TRICORE_5REL = 49; // sbcD/sbrD 6 bit PC-relative, zero-extended displacement

	/*
	 * GNU extensions to help optimizing virtual tables (C++)
	 */
	public static final int R_TRICORE_VTENTRY = 50; //
	public static final int R_TRICORE_VTINHERIT = 51; //

	/*
	 * Support for shared objects
	 */
	public static final int R_TRICORE_PCREL16 = 52; // 16 bit PC-relative relocation
	public static final int R_TRICORE_PCREL8 = 53; // 8 bit PC-relative relocation
	public static final int R_TRICORE_GOT = 54; // rlcC 16 bit GOT symbol entry
	public static final int R_TRICORE_GOT2 = 55; // bolC 16 bit GOT symbol entry
	public static final int R_TRICORE_GOTHI = 56; // rlcC 16 bit GOTHI symbol entry
	public static final int R_TRICORE_GOTLO = 57; // rlcC 16 bit GOTLO symbol entry
	public static final int R_TRICORE_GOTLO2 = 58; // bolC 16 bit GOTLO symbol entry
	public static final int R_TRICORE_GOTUP = 59; // rlcC 16 bit GOTUP symbol entry
	public static final int R_TRICORE_GOTOFF = 60; // rlcC 16 bit GOTOFF symbol entry
	public static final int R_TRICORE_GOTOFF2 = 61; // bolC 16 bit GOTOFF symbol entry
	public static final int R_TRICORE_GOTOFFHI = 62; // rlcC 16 bit GOTOFFHI symbol entry
	public static final int R_TRICORE_GOTOFFLO = 63; // rlcC 16 bit GOTOFFLO symbol entry
	public static final int R_TRICORE_GOTOFFLO2 = 64; // bolC 16 bit GOTOFFLO symbol entry
	public static final int R_TRICORE_GOTOFFUP = 65; // rlcC 16 bit GOTOFFUP symbol entry
	public static final int R_TRICORE_GOTPC = 66; // rlcC 16 bit GOTPC symbol entry
	public static final int R_TRICORE_GOTPC2 = 67; // bolC 16 bit GOTPC symbol entry
	public static final int R_TRICORE_GOTPCHI = 68; // rlcC 16 bit GOTPCHI symbol entry
	public static final int R_TRICORE_GOTPCLO = 69; // rlcC 16 bit GOTPCLO symbol entry
	public static final int R_TRICORE_GOTPCLO2 = 70; // bolC 16 bit GOTPCLO symbol entry
	public static final int R_TRICORE_GOTCPUP = 71; // rlcC 16 bit GOTPCUP symbol entry
	public static final int R_TRICORE_PLT = 72; //relB PLT entry
	public static final int R_TRICORE_COPY = 73; // COPY
	public static final int R_TRICORE_GLOB_DAT = 74; // GLOB_DAT
	public static final int R_TRICORE_JMP_SLOT = 75; // JMP_SLOT
	public static final int R_TRICORE_RELATIVE = 76; // RELATIVE

	/*
	 * Support for single bit objects
	 */
	public static final int R_TRICORE_BITPOS = 77; // BITPOS

	/*
	 * Support for small data addressing areas get the base address of a small data
	 * symbol
	 */
	public static final int R_TRICORE_SBREG_S2 = 78; // SMALL DATA Baseregister operand 2
	public static final int R_TRICORE_SBREG_S1 = 79; // SMALL DATA Baseregister operand 1
	public static final int R_TRICORE_SBREG_D = 80; // SMALL DATA Baseregister destination
}
