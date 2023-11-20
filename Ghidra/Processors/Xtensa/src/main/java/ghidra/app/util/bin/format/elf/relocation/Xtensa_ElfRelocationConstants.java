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

public class Xtensa_ElfRelocationConstants {
	/* Xtensa processor ELF architecture-magic number */

	// EM_XTENSA is already definded
	public static final int EM_XTENSA_OLD =	0xABC7;

	/* Xtensa relocations defined by the ABIs */

	public static final int R_XTENSA_NONE = 0;
	public static final int R_XTENSA_32 = 1;
	public static final int R_XTENSA_RTLD = 2;
	public static final int R_XTENSA_GLOB_DAT = 3;
	public static final int R_XTENSA_JMP_SLOT = 4;
	public static final int R_XTENSA_RELATIVE = 5;
	public static final int R_XTENSA_PLT = 6;
	public static final int R_XTENSA_OP0 = 8;
	public static final int R_XTENSA_OP1 = 9;
	public static final int R_XTENSA_OP2 = 10;
	public static final int R_XTENSA_ASM_EXPAND = 11;
	public static final int R_XTENSA_ASM_SIMPLIFY = 12;
	public static final int R_XTENSA_GNU_VTINHERIT = 15;
	public static final int R_XTENSA_GNU_VTENTRY = 16;
	public static final int R_XTENSA_DIFF8 = 17;
	public static final int R_XTENSA_DIFF16 = 18;
	public static final int R_XTENSA_DIFF32 = 19;
	public static final int R_XTENSA_SLOT0_OP = 20;
	public static final int R_XTENSA_SLOT1_OP = 21;
	public static final int R_XTENSA_SLOT2_OP = 22;
	public static final int R_XTENSA_SLOT3_OP = 23;
	public static final int R_XTENSA_SLOT4_OP = 24;
	public static final int R_XTENSA_SLOT5_OP = 25;
	public static final int R_XTENSA_SLOT6_OP = 26;
	public static final int R_XTENSA_SLOT7_OP = 27;
	public static final int R_XTENSA_SLOT8_OP = 28;
	public static final int R_XTENSA_SLOT9_OP = 29;
	public static final int R_XTENSA_SLOT10_OP = 30;
	public static final int R_XTENSA_SLOT11_OP = 31;
	public static final int R_XTENSA_SLOT12_OP = 32;
	public static final int R_XTENSA_SLOT13_OP = 33;
	public static final int R_XTENSA_SLOT14_OP = 34;
	public static final int R_XTENSA_SLOT0_ALT = 35;
	public static final int R_XTENSA_SLOT1_ALT = 36;
	public static final int R_XTENSA_SLOT2_ALT = 37;
	public static final int R_XTENSA_SLOT3_ALT = 38;
	public static final int R_XTENSA_SLOT4_ALT = 39;
	public static final int R_XTENSA_SLOT5_ALT = 40;
	public static final int R_XTENSA_SLOT6_ALT = 41;
	public static final int R_XTENSA_SLOT7_ALT = 42;
	public static final int R_XTENSA_SLOT8_ALT = 43;
	public static final int R_XTENSA_SLOT9_ALT = 44;
	public static final int R_XTENSA_SLOT10_ALT = 45;
	public static final int R_XTENSA_SLOT11_ALT = 46;
	public static final int R_XTENSA_SLOT12_ALT = 47;
	public static final int R_XTENSA_SLOT13_ALT = 48;
	public static final int R_XTENSA_SLOT14_ALT = 49;
}
