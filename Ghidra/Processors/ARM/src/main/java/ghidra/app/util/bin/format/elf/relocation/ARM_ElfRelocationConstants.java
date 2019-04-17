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

public class ARM_ElfRelocationConstants {

	/** No operation needed */
	public static final int R_ARM_NONE = 0;
	/** ((S + A) | T) - P [DEPRECATED] */
	public static final int R_ARM_PC24 = 1;
	/** (S + A) | T */
	public static final int R_ARM_ABS32 = 2;
	/** ((S + A) | T) - P */
	public static final int R_ARM_REL32 = 3;
	/** S + A - P */
	public static final int R_ARM_LDR_PC_G0 = 4;
	/** S + A */
	public static final int R_ARM_ABS16 = 5;
	/** S + A */
	public static final int R_ARM_ABS12 = 6;
	/** S + A */
	public static final int R_ARM_THM_ABS5 = 7;
	/** S + A */
	public static final int R_ARM_ABS_8 = 8;
	/** ((S + A) | T) - B(S) */
	public static final int R_ARM_SBREL32 = 9;
	/** ((S + A) | T) - P */
	public static final int R_ARM_THM_CALL = 10;
	/** S + A - Pa */
	public static final int R_ARM_THM_PC8 = 11;
	/** DELTA(B(S)) + A */
	public static final int R_ARM_BREL_ADJ = 12;
	public static final int R_ARM_TLS_DESC = 13;
	/** [OBSOLETE] */
	public static final int R_ARM_THM_SWI8 = 14;
	/** [OBSOLETE] */
	public static final int R_ARM_XPC25 = 15;
	/** [OBSOLETE] */
	public static final int R_ARM_THM_XPC22 = 16;
	/** Module[S] */
	public static final int R_ARM_TLS_DTPMOD32 = 17;
	/** S + A - TLS */
	public static final int R_ARM_TLS_DTPOFF32 = 18;
	/** S + A - TLS */
	public static final int R_ARM_TLS_TPOFF32 = 19;
	/** Miscellaneous */
	public static final int R_ARM_COPY = 20;
	/** (S + A) | T */
	public static final int R_ARM_GLOB_DAT = 21;
	/** (S + A) | T */
	public static final int R_ARM_JUMP_SLOT = 22;
	/** B(S) + A [Note: see Table 4-16] */
	public static final int R_ARM_RELATIVE = 23;
	/** ((S + A) | T) - GOT_ORG */
	public static final int R_ARM_GOTOFF32 = 24;
	/** B(S) + A - P */
	public static final int R_ARM_BASE_PREL = 25;
	/** GOT(S) + A - GOT_ORG */
	public static final int R_ARM_GOT_BREL = 26;
	/** ((S + A) | T) - P */
	public static final int R_ARM_GOT_PLT32 = 27;
	/** ((S + A) | T) - P */
	public static final int R_ARM_CALL = 28;
	/** ((S + A) | T) - P */
	public static final int R_ARM_JUMP24 = 29;
	/** ((S + A) | T) - P */
	public static final int R_ARM_THM_JUMP24 = 30;
	/** B(S) + A */
	public static final int R_ARM_BASE_ABS = 31;
	/** Obsolete */
	public static final int R_ARM_ALU_PCREL_7_0 = 32;
	/** Obsolete */
	public static final int R_ARM_ALU_PCREL_15_8 = 33;
	/** Obsolete */
	public static final int R_ARM_ALU_PCREL_23_15 = 34;
	/** S + A - B(S) */
	public static final int R_ARM_LDR_SBREL_11_0_NC = 35;
	/** S + A - B(S) */
	public static final int R_ARM_ALU_SBREL_19_12_NC = 36;
	/** S + A - B(S) */
	public static final int R_ARM_ALU_SBREL_27_20_CK = 37;
	/** (S + A) | T or ((S + A) | T) - P */
	public static final int R_ARM_TARGET1 = 38;
	/** ((S + A) | T) - B(S) */
	public static final int R_ARM_SBREL31 = 39;
	/** Miscellaneous */
	public static final int R_ARM_V4BX = 40;
	/** Miscellaneous */
	public static final int R_ARM_TARGET2 = 41;
	/** ((S + A) | T) - P */
	public static final int R_ARM_PREL31 = 42;
	/** (S + A) | T */
	public static final int R_ARM_MOVW_ABS_NC = 43;
	/** S + A */
	public static final int R_ARM_MOVT_ABS = 44;
	/** ((S + A) | T) - P */
	public static final int R_ARM_MOVW_PREL_NC = 45;
	/** S + A - P */
	public static final int R_ARM_MOVT_PREL = 46;
	/** (S + A) | T */
	public static final int R_ARM_THM_MOVW_ABS_NC = 47;
	/** S + A */
	public static final int R_ARM_THM_MOVT_ABS = 48;
	/** ((S + A) | T) - P */
	public static final int R_ARM_THM_MOVW_PREL_NC = 49;
	/** S + A - P */
	public static final int R_ARM_THM_MOVT_PREL = 50;
	/** ((S + A) | T) - P */
	public static final int R_ARM_THM_JUMP19 = 51;
	/** S + A - P */
	public static final int R_ARM_THM_JUMP6 = 52;
	/** ((S + A) | T) - Pa */
	public static final int R_ARM_THM_ALU_PREL_11_0 = 53;
	/** S + A - Pa */
	public static final int R_ARM_THM_PC12 = 54;
	/** S + A */
	public static final int R_ARM_ABS32_NOI = 55;
	/** S + A - P */
	public static final int R_ARM_REL32_NOI = 56;
	/** ((S + A) | T) - P */
	public static final int R_ARM_ALU_PC_G0_NC = 57;
	/** ((S + A) | T) - P */
	public static final int R_ARM_ALU_PC_G0 = 58;
	/** ((S + A) | T) - P */
	public static final int R_ARM_ALU_PC_G1_NC = 59;
	/** ((S + A) | T) - P */
	public static final int R_ARM_ALU_PC_G1 = 60;
	/** ((S + A) | T) - P */
	public static final int R_ARM_ALU_PC_G2 = 61;
	/** S + A - P */
	public static final int R_ARM_LDR_PC_G1 = 62;
	/** S + A - P */
	public static final int R_ARM_LDR_PC_G2 = 63;
	/** S + A - P */
	public static final int R_ARM_LDRS_PC_G0 = 64;
	/** S + A - P */
	public static final int R_ARM_LDRS_PC_G1 = 65;
	/** S + A - P */
	public static final int R_ARM_LDRS_PC_G2 = 66;
	/** S + A - P */
	public static final int R_ARM_LDC_PC_G0 = 67;
	/** S + A - P */
	public static final int R_ARM_LDC_PC_G1 = 68;
	/** S + A - P */
	public static final int R_ARM_LDC_PC_G2 = 69;
	/** ((S + A) | T) - B(S) */
	public static final int R_ARM_ALU_SB_G0_NC = 70;
	/** ((S + A) | T) - B(S) */
	public static final int R_ARM_ALU_SB_G0 = 71;
	/** ((S + A) | T) - B(S) */
	public static final int R_ARM_ALU_SB_G1_NC = 72;
	/** ((S + A) | T) - B(S) */
	public static final int R_ARM_ALU_SB_G1 = 73;
	/** ((S + A) | T) - B(S) */
	public static final int R_ARM_ALU_SB_G2 = 74;
	/** S + A - B(S) */
	public static final int R_ARM_LDR_SB_G0 = 75;
	/** S + A - B(S) */
	public static final int R_ARM_LDR_SB_G1 = 76;
	/** S + A - B(S) */
	public static final int R_ARM_LDR_SB_G2 = 77;
	/** S + A - B(S) */
	public static final int R_ARM_LDRS_SB_G0 = 78;
	/** S + A - B(S) */
	public static final int R_ARM_LDRS_SB_G1 = 79;
	/** S + A - B(S) */
	public static final int R_ARM_LDRS_SB_G2 = 80;
	/** S + A - B(S) */
	public static final int R_ARM_LDC_SB_G0 = 81;
	/** S + A - B(S) */
	public static final int R_ARM_LDC_SB_G1 = 82;
	/** S + A - B(S) */
	public static final int R_ARM_LDC_SB_G2 = 83;
	/** ((S + A) | T) - B(S) */
	public static final int R_ARM_MOVW_BREL_NC = 84;
	/** S + A - B(S) */
	public static final int R_ARM_MOVT_BREL = 85;
	/** ((S + A) | T) - B(S) */
	public static final int R_ARM_MOVW_BREL = 86;
	/** ((S + A) | T) - B(S) */
	public static final int R_ARM_THM_MOVW_BREL_NC = 87;
	/** S + A - B(S) */
	public static final int R_ARM_THM_MOVT_BREL = 88;
	/** ((S + A) | T) - B(S) */
	public static final int R_ARM_THM_MOVW_BREL = 89;
	/** ? */
	public static final int R_ARM_TLS_GOTDESC = 90;
	/** ? */
	public static final int R_ARM_TLS_CALL = 91;
	/** TLS relaxation */
	public static final int R_ARM_TLS_DESCSEQ = 92;
	/** ? */
	public static final int R_ARM_THM_TLS_CALL = 93;
	/** PLT(S) + A */
	public static final int R_ARM_PLT32_ABS = 94;
	/** GOT(S) + A */
	public static final int R_ARM_GOT_ABS = 95;
	/** GOT(S) + A - P */
	public static final int R_ARM_GOT_PREL = 96;
	/** GOT(S) + A - GOT_ORG */
	public static final int R_ARM_GOT_BREL12 = 97;
	/** S + A - GOT_ORG */
	public static final int R_ARM_GOTOFF12 = 98;
	/** ? */
	public static final int R_ARM_GOTRELAX = 99;
	/** ? */
	public static final int R_ARM_GNU_VTENTRY = 100;
	/** ? */
	public static final int R_ARM_GNU_VTINHERIT = 101;
	/** S + A - P */
	public static final int R_ARM_THM_JUMP11 = 102;
	/** S + A - P */
	public static final int R_ARM_THM_JUMP8 = 103;
	/** GOT(S) + A - P */
	public static final int R_ARM_TLS_GD32 = 104;
	/** GOT(S) + A - P */
	public static final int R_ARM_TLS_LDM32 = 105;
	/** S + A - TLS */
	public static final int R_ARM_TLS_LDO32 = 106;
	/** GOT(S) + A - P */
	public static final int R_ARM_TLS_IE32 = 107;
	/** S + A - tp */
	public static final int R_ARM_TLS_LE32 = 108;
	/** S + A - TLS */
	public static final int R_ARM_TLS_LDO12 = 109;
	/** S + A - tp */
	public static final int R_ARM_TLS_LE12 = 110;
	/** GOT(S) + A - GOT_ORG */
	public static final int R_ARM_TLS_IE12GP = 111;
	/** ? */
	public static final int R_ARM_PRIVATE_0 = 112;
	/** ? */
	public static final int R_ARM_PRIVATE_1 = 113;
	/** ? */
	public static final int R_ARM_PRIVATE_2 = 114;
	/** ? */
	public static final int R_ARM_PRIVATE_3 = 115;
	/** ? */
	public static final int R_ARM_PRIVATE_4 = 116;
	/** ? */
	public static final int R_ARM_PRIVATE_5 = 117;
	/** ? */
	public static final int R_ARM_PRIVATE_6 = 118;
	/** ? */
	public static final int R_ARM_PRIVATE_7 = 119;
	/** ? */
	public static final int R_ARM_PRIVATE_8 = 120;
	/** ? */
	public static final int R_ARM_PRIVATE_9 = 121;
	/** ? */
	public static final int R_ARM_PRIVATE_10 = 122;
	/** ? */
	public static final int R_ARM_PRIVATE_11 = 123;
	/** ? */
	public static final int R_ARM_PRIVATE_12 = 124;
	/** ? */
	public static final int R_ARM_PRIVATE_13 = 125;
	/** ? */
	public static final int R_ARM_PRIVATE_14 = 126;
	/** ? */
	public static final int R_ARM_PRIVATE_15 = 127;
	/** ? */
	public static final int R_ARM_ME_TOO = 128;
	/** ? */
	public static final int R_ARM_THM_TLS_DESCSEQ16 = 129;
	/** ? */
	public static final int R_ARM_THM_TLS_DESCSEQ32 = 130;
	
	private ARM_ElfRelocationConstants() {
		// no construct
	}
}
