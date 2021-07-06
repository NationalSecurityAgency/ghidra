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

public class SH_ElfRelocationConstants {

	public static final int R_SH_NONE = 0;    // No operation needed
	public static final int R_SH_DIR32 = 1;   // (S + A) */
	public static final int R_SH_REL32 = 2;   // (S + A) - P
	public static final int R_SH_DIR8WPN = 3; // 8-bit PC relative branch divided by 2 :  (((S + A) - P) >> 1) & 0xff
	public static final int R_SH_IND12W = 4;  // 12-bit PC relative branch divided by 2 :  (((S + A) - P) >> 1) & 0xfff
	public static final int R_SH_DIR8WPL = 5; // 8-bit PC unsigned-relative branch divided by 4 :  (((S + A) - P) >> 2) & 0xff
	public static final int R_SH_DIR8WPZ = 6; // 8-bit PC unsigned-relative branch divided by 2 :  (((S + A) - P) >> 1) & 0xff
	public static final int R_SH_DIR8BP = 7;
	public static final int R_SH_DIR8W = 8;
	public static final int R_SH_DIR8L = 9;

	// Relocation numbering in this file corresponds to GNU binutils and
	// values below this point may differ significantly from those specified
	// for other uses (e.g., see https://android.googlesource.com/platform/external/elfutils/+/android-4.1.2_r1/libelf/elf.h )

	public static final int R_SH_LOOP_START = 10;
	public static final int R_SH_LOOP_END = 11;

	public static final int R_SH_GNU_VTINHERIT = 22;
	public static final int R_SH_GNU_VTENTRY = 23;
	public static final int R_SH_SWITCH8 = 24;

	public static final int R_SH_SWITCH16 = 25;
	public static final int R_SH_SWITCH32 = 26;
	public static final int R_SH_USES = 27;
	public static final int R_SH_COUNT = 28;
	public static final int R_SH_ALIGN = 29;
	public static final int R_SH_CODE = 30;
	public static final int R_SH_DATA = 31;
	public static final int R_SH_LABEL = 32;

	public static final int R_SH_DIR16 = 33;
	public static final int R_SH_DIR8 = 34;
	public static final int R_SH_DIR8UL = 35;
	public static final int R_SH_DIR8UW = 36;
	public static final int R_SH_DIR8U = 37;
	public static final int R_SH_DIR8SW = 38;
	public static final int R_SH_DIR8S = 39;
	public static final int R_SH_DIR4UL = 40;
	public static final int R_SH_DIR4UW = 41;
	public static final int R_SH_DIR4U = 42;
	public static final int R_SH_PSHA = 43;
	public static final int R_SH_PSHL = 44;
	public static final int R_SH_DIR5U = 45;
	public static final int R_SH_DIR6U = 46;
	public static final int R_SH_DIR6S = 47;
	public static final int R_SH_DIR10S = 48;
	public static final int R_SH_DIR10SW = 49;
	public static final int R_SH_DIR10SL = 50;
	public static final int R_SH_DIR10SQ = 51;

	public static final int R_SH_DIR16S = 53;

	public static final int R_SH_TLS_GD_32 = 144;
	public static final int R_SH_TLS_LD_32 = 145;
	public static final int R_SH_TLS_LDO_32 = 146;
	public static final int R_SH_TLS_IE_32 = 147;
	public static final int R_SH_TLS_LE_32 = 148;
	public static final int R_SH_TLS_DTPMOD32 = 149;
	public static final int R_SH_TLS_DTPOFF32 = 150;
	public static final int R_SH_TLS_TPOFF32 = 151;

	public static final int R_SH_GOT32 = 160;
	public static final int R_SH_PLT32 = 161;
	public static final int R_SH_COPY = 162;
	public static final int R_SH_GLOB_DAT = 163;
	public static final int R_SH_JMP_SLOT = 164;
	public static final int R_SH_RELATIVE = 165;
	public static final int R_SH_GOTOFF = 166;
	public static final int R_SH_GOTPC = 167;
	public static final int R_SH_GOTPLT32 = 168;
	public static final int R_SH_GOT_LOW16 = 169;
	public static final int R_SH_GOT_MEDLOW16 = 170;
	public static final int R_SH_GOT_MEDHI16 = 171;
	public static final int R_SH_GOT_HI16 = 172;
	public static final int R_SH_GOTPLT_LOW16 = 173;
	public static final int R_SH_GOTPLT_MEDLOW16 = 174;
	public static final int R_SH_GOTPLT_MEDHI16 = 175;
	public static final int R_SH_GOTPLT_HI16 = 176;
	public static final int R_SH_PLT_LOW16 = 177;
	public static final int R_SH_PLT_MEDLOW16 = 178;
	public static final int R_SH_PLT_MEDHI16 = 179;
	public static final int R_SH_PLT_HI16 = 180;
	public static final int R_SH_GOTOFF_LOW16 = 181;
	public static final int R_SH_GOTOFF_MEDLOW16 = 182;
	public static final int R_SH_GOTOFF_MEDHI16 = 183;
	public static final int R_SH_GOTOFF_HI16 = 184;
	public static final int R_SH_GOTPC_LOW16 = 185;
	public static final int R_SH_GOTPC_MEDLOW16 = 186;
	public static final int R_SH_GOTPC_MEDHI16 = 187;
	public static final int R_SH_GOTPC_HI16 = 188;
	public static final int R_SH_GOT10BY4 = 189;
	public static final int R_SH_GOTPLT10BY4 = 190;
	public static final int R_SH_GOT10BY8 = 191;
	public static final int R_SH_GOTPLT10BY8 = 192;
	public static final int R_SH_COPY64 = 193;
	public static final int R_SH_GLOB_DAT64 = 194;
	public static final int R_SH_JMP_SLOT64 = 195;
	public static final int R_SH_RELATIVE64 = 196;

	public static final int R_SH_SHMEDIA_CODE = 242;
	public static final int R_SH_PT_16 = 243;
	public static final int R_SH_IMMS16 = 244;
	public static final int R_SH_IMMU16 = 245;
	public static final int R_SH_IMM_LOW16 = 246;
	public static final int R_SH_IMM_LOW16_PCREL = 247;
	public static final int R_SH_IMM_MEDLOW16 = 248;
	public static final int R_SH_IMM_MEDLOW16_PCREL = 249;
	public static final int R_SH_IMM_MEDHI16 = 250;
	public static final int R_SH_IMM_MEDHI16_PCREL = 251;
	public static final int R_SH_IMM_HI16 = 252;
	public static final int R_SH_IMM_HI16_PCREL = 253;
	public static final int R_SH_64 = 254;
	public static final int R_SH_64_PCREL = 255;
}
