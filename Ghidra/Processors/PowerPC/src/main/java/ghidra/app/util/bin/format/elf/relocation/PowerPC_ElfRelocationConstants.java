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

public class PowerPC_ElfRelocationConstants {

	public static final int R_PPC_NONE = 0;
	public static final int R_PPC_ADDR32 = 1; // word32 S + A
	public static final int R_PPC_ADDR24 = 2; // low24 (S + A) >> 2
	public static final int R_PPC_ADDR16 = 3; // half16 S + A
	public static final int R_PPC_ADDR16_LO = 4; // half16 #lo(S + A)
	public static final int R_PPC_ADDR16_HI = 5; // half16 #hi(S + A)
	public static final int R_PPC_ADDR16_HA = 6; // half16 #ha(S + A)
	public static final int R_PPC_ADDR14 = 7; // low14 (S + A) >> 2
	public static final int R_PPC_ADDR14_BRTAKEN = 8; // low14 (S + A) >> 2
	public static final int R_PPC_ADDR14_BRNTAKEN = 9; // low14 (S + A) >> 2
	public static final int R_PPC_REL24 = 10; // low24 (S + A - P) >> 2
	public static final int R_PPC_REL14 = 11; // low14 (S + A - P) >> 2
	public static final int R_PPC_REL14_BRTAKEN = 12; // low14 (S + A - P) >>
														// 2
	public static final int R_PPC_REL14_BRNTAKEN = 13; // low14 (S + A - P) >>
														// 2
	public static final int R_PPC_GOT16 = 14; // half16 G + A
	public static final int R_PPC_GOT16_LO = 15; // half16 #lo(G + A)
	public static final int R_PPC_GOT16_HI = 16; // half16 #hi(G + A)
	public static final int R_PPC_GOT16_HA = 17; // half16 #ha(G + A)
	public static final int R_PPC_PLTREL24 = 18; // low24 (L + A + P) >> 2
	public static final int R_PPC_COPY = 19; // none none
	public static final int R_PPC_GLOB_DAT = 20; // word32 S + A
	public static final int R_PPC_JMP_SLOT = 21; // Old ABI: word32 S + A, New ABI: generate branch instruction
	public static final int R_PPC_RELATIVE = 22; // word32 S + A
	public static final int R_PPC_LOCAL24PC = 23; // none
	public static final int R_PPC_UADDR32 = 24; // low24
	public static final int R_PPC_UADDR16 = 25; // half16 S + A
	public static final int R_PPC_REL32 = 26; // word32 S + A - P
	public static final int R_PPC_PLT32 = 27; // word32 L + A
	public static final int R_PPC_PLTREL32 = 28; // word32 L + A - P
	public static final int R_PPC_PLT16_LO = 29; // half16 #lo(L + A)
	public static final int R_PPC_PLT16_HI = 30; // half16 #hi(L + A)
	public static final int R_PPC_PLT16_HA = 31; // half16 #ha(L + A)
	public static final int R_PPC_SDAREL16 = 32; // half16 S + A - _SDA_BASE_
	public static final int R_PPC_SECTOFF = 33; // half16 R + A
	public static final int R_PPC_SECTOFF_LO = 34; // half16 #lo(R + A)
	public static final int R_PPC_SECTOFF_HI = 35; // half16 #hi(R + A)
	public static final int R_PPC_SECTOFF_HA = 36; // half16 #ha(R + A)
	public static final int R_PPC_ADDR30 = 37; // word30 (S + A - P) >> 2

	public static final int R_POWERPC_TLS = 67;
	public static final int R_POWERPC_DTPMOD = 68;
	public static final int R_POWERPC_TPREL16 = 69;
	public static final int R_POWERPC_TPREL16_LO = 70;
	public static final int R_POWERPC_TPREL16_HI = 71;
	public static final int R_POWERPC_TPREL16_HA = 72;
	public static final int R_POWERPC_TPREL = 73;
	public static final int R_POWERPC_DTPREL16 = 74;
	public static final int R_POWERPC_DTPREL16_LO = 75;
	public static final int R_POWERPC_DTPREL16_HI = 76;
	public static final int R_POWERPC_DTPREL16_HA = 77;
	public static final int R_POWERPC_DTPREL = 78;
	public static final int R_POWERPC_GOT_TLSGD16 = 79;
	public static final int R_POWERPC_GOT_TLSGD16_LO = 80;
	public static final int R_POWERPC_GOT_TLSGD16_HI = 81;
	public static final int R_POWERPC_GOT_TLSGD16_HA = 82;
	public static final int R_POWERPC_GOT_TLSLD16 = 83;
	public static final int R_POWERPC_GOT_TLSLD16_LO = 84;
	public static final int R_POWERPC_GOT_TLSLD16_HI = 85;
	public static final int R_POWERPC_GOT_TLSLD16_HA = 86;
	public static final int R_POWERPC_GOT_TPREL16 = 87;
	public static final int R_POWERPC_GOT_TPREL16_LO = 88;
	public static final int R_POWERPC_GOT_TPREL16_HI = 89;
	public static final int R_POWERPC_GOT_TPREL16_HA = 90;
	public static final int R_POWERPC_GOT_DTPREL16 = 91;
	public static final int R_POWERPC_GOT_DTPREL16_LO = 92;
	public static final int R_POWERPC_GOT_DTPREL16_HI = 93;
	public static final int R_POWERPC_GOT_DTPREL16_HA = 94;
	public static final int R_PPC_TLSGD = 95;
	public static final int R_PPC_TLSLD = 96;

	public static final int R_PPC_EMB_NADDR32 = 101; // uword32 (A - S)
	public static final int R_PPC_EMB_NADDR16 = 102; // uhalf16 (A - S)
	public static final int R_PPC_EMB_NADDR16_LO = 103; // uhalf16 #lo(A - S)
	public static final int R_PPC_EMB_NADDR16_HI = 104; // uhalf16 #hi(A - S)
	public static final int R_PPC_EMB_NADDR16_HA = 105; // uhalf16 #ha(A - S)
	public static final int R_PPC_EMB_SDAI16 = 106; // uhalf16 T
	public static final int R_PPC_EMB_SDA2I16 = 107; // uhalf16 U
	public static final int R_PPC_EMB_SDA2REL = 108; // uhalf16 S + A - _SDA2_BASE_
	public static final int R_PPC_EMB_SDA21 = 109; // ulow21
	public static final int R_PPC_EMB_MRKREF = 110; // none
	public static final int R_PPC_EMB_RELSEC16 = 111; // uhalf16 V + A
	public static final int R_PPC_EMB_RELST_LO = 112; // uhalf16 #lo(W + A)
	public static final int R_PPC_EMB_RELST_HI = 113; // uhalf16 #hi(W + A)
	public static final int R_PPC_EMB_RELST_HA = 114; // uhalf16 #ha(W + A)
	public static final int R_PPC_EMB_BIT_FLD = 115; // uword32
	public static final int R_PPC_EMB_RELSDA = 116; // uhalf16

	public static final int R_POWERPC_PLTSEQ = 119;
	public static final int R_POWERPC_PLTCALL = 120;

	public static final int R_PPC_VLE_REL8 = 216;
	public static final int R_PPC_VLE_REL15 = 217;
	public static final int R_PPC_VLE_REL24 = 218;
	public static final int R_PPC_VLE_LO16A = 219;
	public static final int R_PPC_VLE_LO16D = 220;
	public static final int R_PPC_VLE_HI16A = 221;
	public static final int R_PPC_VLE_HI16D = 222;
	public static final int R_PPC_VLE_HA16A = 223;
	public static final int R_PPC_VLE_HA16D = 224;
	public static final int R_PPC_VLE_SDA21 = 225;
	public static final int R_PPC_VLE_SDA21_LO = 226;
	public static final int R_PPC_VLE_SDAREL_LO16A = 227;
	public static final int R_PPC_VLE_SDAREL_LO16D = 228;
	public static final int R_PPC_VLE_SDAREL_HI16A = 229;
	public static final int R_PPC_VLE_SDAREL_HI16D = 230;
	public static final int R_PPC_VLE_SDAREL_HA16A = 231;
	public static final int R_PPC_VLE_SDAREL_HA16D = 232;

	public static final int R_POWERPC_REL16DX_HA = 246;
	public static final int R_POWERPC_IRELATIVE = 248;
	public static final int R_POWERPC_REL16 = 249;
	public static final int R_POWERPC_REL16_LO = 250;
	public static final int R_POWERPC_REL16_HI = 251;
	public static final int R_POWERPC_REL16_HA = 252;
	public static final int R_POWERPC_GNU_VTINHERIT = 253;
	public static final int R_POWERPC_GNU_VTENTRY = 254;
	public static final int R_PPC_TOC16 = 255;

	// Masks for manipulating Power PC relocation targets
	public static final int PPC_WORD32 = 0xFFFFFFFF;
	public static final int PPC_WORD30 = 0xFFFFFFFC;
	public static final int PPC_LOW24 = 0x03FFFFFC;
	public static final int PPC_LOW14 = 0x0020FFFC;
	public static final int PPC_HALF16 = 0xFFFF;

	private PowerPC_ElfRelocationConstants() {
		// no construct
	}
}
