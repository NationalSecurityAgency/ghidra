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

public class AARCH64_ElfRelocationConstants {
	 
	public static final int R_AARCH64_NONE = 0;

	// .word:  (S+A) 
	public static final int R_AARCH64_P32_ABS32 = 1;

	// .half: (S+A) 
	public static final int R_AARCH64_P32_ABS16 = 2;

	// .word: (S+A-P) 
	public static final int R_AARCH64_P32_PREL32 = 3;

	// .half:  (S+A-P) 
	public static final int R_AARCH64_P32_PREL16 = 4;

	// MOV[ZK]:   ((S+A) >>  0) & 0xffff 
	public static final int R_AARCH64_P32_MOVW_UABS_G0 = 5;

	// MOV[ZK]:   ((S+A) >>  0) & 0xffff 
	public static final int R_AARCH64_P32_MOVW_UABS_G0_NC = 6;

	// MOV[ZK]:   ((S+A) >> 16) & 0xffff 
	public static final int R_AARCH64_P32_MOVW_UABS_G1 = 7;

	// MOV[ZN]:   ((S+A) >>  0) & 0xffff 
	public static final int R_AARCH64_P32_MOVW_SABS_G0 = 8;

	// LD-lit: ((S+A-P) >> 2) & 0x7ffff 
	public static final int R_AARCH64_P32_LD_PREL_LO19 = 9;

	// ADR:    (S+A-P) & 0x1fffff 
	public static final int R_AARCH64_P32_ADR_PREL_LO21 = 10;

	// ADRH:   ((PG(S+A)-PG(P)) >> 12) & 0x1fffff 
	public static final int R_AARCH64_P32_ADR_PREL_PG_HI21 = 11;

	// ADD:    (S+A) & 0xfff 
	public static final int R_AARCH64_P32_ADD_ABS_LO12_NC = 12;

	// LD/ST8: (S+A) & 0xfff 
	public static final int R_AARCH64_P32_LDST8_ABS_LO12_NC = 13;

	// LD/ST16: (S+A) & 0xffe 
	public static final int R_AARCH64_P32_LDST16_ABS_LO12_NC = 14;

	// LD/ST32: (S+A) & 0xffc 
	public static final int R_AARCH64_P32_LDST32_ABS_LO12_NC = 15;

	// LD/ST64: (S+A) & 0xff8 
	public static final int R_AARCH64_P32_LDST64_ABS_LO12_NC = 16;

	// LD/ST128: (S+A) & 0xff0 
	public static final int R_AARCH64_P32_LDST128_ABS_LO12_NC = 17;

	// TBZ/NZ: ((S+A-P) >> 2) & 0x3fff.  
	public static final int R_AARCH64_P32_TSTBR14 = 18;

	// B.cond: ((S+A-P) >> 2) & 0x7ffff.  
	public static final int R_AARCH64_P32_CONDBR19 = 19;

	// B:      ((S+A-P) >> 2) & 0x3ffffff.  
	public static final int R_AARCH64_P32_JUMP26 = 20;

	// BL:     ((S+A-P) >> 2) & 0x3ffffff.  
	public static final int R_AARCH64_P32_CALL26 = 21;


	public static final int R_AARCH64_P32_GOT_LD_PREL19 = 25;
	public static final int R_AARCH64_P32_ADR_GOT_PAGE = 26;
	public static final int R_AARCH64_P32_LD32_GOT_LO12_NC = 27;
	public static final int R_AARCH64_P32_LD32_GOTPAGE_LO14 = 28;

	public static final int R_AARCH64_P32_TLSGD_ADR_PREL21 = 80;
	public static final int R_AARCH64_P32_TLSGD_ADR_PAGE21 = 81;
	public static final int R_AARCH64_P32_TLSGD_ADD_LO12_NC = 82;
	public static final int R_AARCH64_P32_TLSLD_ADR_PREL21 = 83;
	public static final int R_AARCH64_P32_TLSLD_ADR_PAGE21 = 84;
	public static final int R_AARCH64_P32_TLSLD_ADD_LO12_NC = 85;
	public static final int R_AARCH64_P32_TLSLD_MOVW_DTPREL_G1 = 87;
	public static final int R_AARCH64_P32_TLSLD_MOVW_DTPREL_G0 = 88;
	public static final int R_AARCH64_P32_TLSLD_MOVW_DTPREL_G0_NC = 89;
	public static final int R_AARCH64_P32_TLSLD_ADD_DTPREL_HI12 = 90;
	public static final int R_AARCH64_P32_TLSLD_ADD_DTPREL_LO12 = 91;
	public static final int R_AARCH64_P32_TLSLD_ADD_DTPREL_LO12_NC = 92;
	public static final int R_AARCH64_P32_TLSIE_ADR_GOTTPREL_PAGE21 = 103;
	public static final int R_AARCH64_P32_TLSIE_LD32_GOTTPREL_LO12_NC = 104;
	public static final int R_AARCH64_P32_TLSIE_LD_GOTTPREL_PREL19 = 105;
	public static final int R_AARCH64_P32_TLSLE_MOVW_TPREL_G1 = 106;
	public static final int R_AARCH64_P32_TLSLE_MOVW_TPREL_G0 = 107;
	public static final int R_AARCH64_P32_TLSLE_MOVW_TPREL_G0_NC = 108;
	public static final int R_AARCH64_P32_TLSLE_ADD_TPREL_HI12 = 109;
	public static final int R_AARCH64_P32_TLSLE_ADD_TPREL_LO12 = 110;
	public static final int R_AARCH64_P32_TLSLE_ADD_TPREL_LO12_NC = 111;

	public static final int R_AARCH64_P32_TLSDESC_LD_PREL19 = 122;
	public static final int R_AARCH64_P32_TLSDESC_ADR_PREL21 = 123;
	public static final int R_AARCH64_P32_TLSDESC_ADR_PAGE21 = 124;
	public static final int R_AARCH64_P32_TLSDESC_LD32_LO12_NC = 125;
	public static final int R_AARCH64_P32_TLSDESC_ADD_LO12_NC = 126;
	public static final int R_AARCH64_P32_TLSDESC_CALL = 127;

	// Copy symbol at runtime.  
	public static final int R_AARCH64_P32_COPY = 180;

	// Create GOT entry.  
	public static final int R_AARCH64_P32_GLOB_DAT = 181;

	 // Create PLT entry.  
	public static final int R_AARCH64_P32_JUMP_SLOT = 182;

	// Adjust by program base.  
	public static final int R_AARCH64_P32_RELATIVE = 183;
	public static final int R_AARCH64_P32_TLS_DTPMOD = 184;
	public static final int R_AARCH64_P32_TLS_DTPREL = 185;
	public static final int R_AARCH64_P32_TLS_TPREL = 186;
	public static final int R_AARCH64_P32_TLSDESC = 187;
	public static final int R_AARCH64_P32_IRELATIVE = 188;

	public static final int R_AARCH64_NULL = 256; // No reloc 

	// Basic data relocations.  

	// .xword: (S+A) 
	public static final int R_AARCH64_ABS64 = 257;

	// .word:  (S+A) 
	public static final int R_AARCH64_ABS32 = 258;

	// .half: (S+A) 
	public static final int R_AARCH64_ABS16 = 259;

	// .xword: (S+A-P) 
	public static final int R_AARCH64_PREL64 = 260;

	// .word: (S+A-P) 
	public static final int R_AARCH64_PREL32 = 261;

	// .half:  (S+A-P) 
	public static final int R_AARCH64_PREL16 = 262; 

	// MOV[ZK]:   ((S+A) >>  0) & 0xffff 
	public static final int R_AARCH64_MOVW_UABS_G0 =           263;

	// MOV[ZK]:   ((S+A) >>  0) & 0xffff 
	public static final int R_AARCH64_MOVW_UABS_G0_NC = 264;

	// MOV[ZK]:   ((S+A) >> 16) & 0xffff 
	public static final int R_AARCH64_MOVW_UABS_G1 = 265;

	// MOV[ZK]:   ((S+A) >> 16) & 0xffff 
	public static final int R_AARCH64_MOVW_UABS_G1_NC = 266;

	// MOV[ZK]:   ((S+A) >> 32) & 0xffff 
	public static final int R_AARCH64_MOVW_UABS_G2 = 267;
	
	// MOV[ZK]:   ((S+A) >> 32) & 0xffff 
	public static final int R_AARCH64_MOVW_UABS_G2_NC = 268;

	// MOV[ZK]:   ((S+A) >> 48) & 0xffff 
	public static final int R_AARCH64_MOVW_UABS_G3 = 269;

	// MOV[ZN]:   ((S+A) >>  0) & 0xffff 
	public static final int R_AARCH64_MOVW_SABS_G0 = 270;

	// MOV[ZN]:   ((S+A) >> 16) & 0xffff 
	public static final int R_AARCH64_MOVW_SABS_G1 = 271;

	// MOV[ZN]:   ((S+A) >> 32) & 0xffff 
	public static final int R_AARCH64_MOVW_SABS_G2 = 272;

	// LD-lit: ((S+A-P) >> 2) & 0x7ffff 
	public static final int R_AARCH64_LD_PREL_LO19 = 273;

	// ADR:    (S+A-P) & 0x1fffff 
	public static final int R_AARCH64_ADR_PREL_LO21 = 274;

	// ADRH:   ((PG(S+A)-PG(P)) >> 12) & 0x1fffff 
	public static final int R_AARCH64_ADR_PREL_PG_HI21 = 275;

	// ADRH:   ((PG(S+A)-PG(P)) >> 12) & 0x1fffff 
	public static final int R_AARCH64_ADR_PREL_PG_HI21_NC = 276;

	// ADD:    (S+A) & 0xfff 
	public static final int R_AARCH64_ADD_ABS_LO12_NC = 277;

	// LD/ST8: (S+A) & 0xfff 
	public static final int R_AARCH64_LDST8_ABS_LO12_NC = 278;

	// TBZ/NZ: ((S+A-P) >> 2) & 0x3fff.  
	public static final int R_AARCH64_TSTBR14 = 279;

	// B.cond: ((S+A-P) >> 2) & 0x7ffff.  
	public static final int R_AARCH64_CONDBR19 = 280;

	// B:      ((S+A-P) >> 2) & 0x3ffffff.  
	public static final int R_AARCH64_JUMP26 = 282;

	// BL:     ((S+A-P) >> 2) & 0x3ffffff.  
	public static final int R_AARCH64_CALL26 = 283;

	// LD/ST16: (S+A) & 0xffe 
	public static final int R_AARCH64_LDST16_ABS_LO12_NC = 284;

	// LD/ST32: (S+A) & 0xffc 
	public static final int R_AARCH64_LDST32_ABS_LO12_NC = 285;

	// LD/ST64: (S+A) & 0xff8 
	public static final int R_AARCH64_LDST64_ABS_LO12_NC = 286;
	
	public static final int R_AARCH64_MOVW_PREL_G0 = 287;
	public static final int R_AARCH64_MOVW_PREL_G0_NC = 288;
	public static final int R_AARCH64_MOVW_PREL_G1 = 289;
	public static final int R_AARCH64_MOVW_PREL_G1_NC = 290;
	public static final int R_AARCH64_MOVW_PREL_G2 = 291;
	public static final int R_AARCH64_MOVW_PREL_G2_NC = 292;
	public static final int R_AARCH64_MOVW_PREL_G3 = 293;
	
	// LD/ST128: (S+A) & 0xff0
	public static final int R_AARCH64_LDST128_ABS_LO12_NC = 299;

	public static final int R_AARCH64_MOVW_GOTOFF_G0 = 300;
	public static final int R_AARCH64_MOVW_GOTOFF_G0_NC = 301;
	public static final int R_AARCH64_MOVW_GOTOFF_G1 = 302;
	public static final int R_AARCH64_MOVW_GOTOFF_G1_NC = 303;
	public static final int R_AARCH64_MOVW_GOTOFF_G2 = 304;
	public static final int R_AARCH64_MOVW_GOTOFF_G2_NC = 305;
	public static final int R_AARCH64_MOVW_GOTOFF_G3 = 306; 

	public static final int R_AARCH64_GOTREL64 = 307;
	public static final int R_AARCH64_GOTREL32 = 308; 

	public static final int R_AARCH64_GOT_LD_PREL19 = 309;
	public static final int R_AARCH64_LD64_GOTOFF_LO15 = 310;
	public static final int R_AARCH64_ADR_GOT_PAGE = 311;
	public static final int R_AARCH64_LD64_GOT_LO12_NC = 312;
	public static final int R_AARCH64_LD64_GOTPAGE_LO15 = 313;

	public static final int R_AARCH64_TLSGD_ADR_PREL21 = 512;
	public static final int R_AARCH64_TLSGD_ADR_PAGE21 = 513;
	public static final int R_AARCH64_TLSGD_ADD_LO12_NC = 514;
	public static final int R_AARCH64_TLSGD_MOVW_G1 = 515;
	public static final int R_AARCH64_TLSGD_MOVW_G0_NC = 516;  

	public static final int R_AARCH64_TLSLD_ADR_PREL21 = 517;
	public static final int R_AARCH64_TLSLD_ADR_PAGE21 = 518;
	public static final int R_AARCH64_TLSLD_ADD_LO12_NC = 519;
	public static final int R_AARCH64_TLSLD_MOVW_G1 = 520;
	public static final int R_AARCH64_TLSLD_MOVW_G0_NC = 521;
	public static final int R_AARCH64_TLSLD_LD_PREL19 = 522;
	public static final int R_AARCH64_TLSLD_MOVW_DTPREL_G2 = 523;
	public static final int R_AARCH64_TLSLD_MOVW_DTPREL_G1 = 524;
	public static final int R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC = 525;
	public static final int R_AARCH64_TLSLD_MOVW_DTPREL_G0 = 526;
	public static final int R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC = 527;
	public static final int R_AARCH64_TLSLD_ADD_DTPREL_HI12 = 528;
	public static final int R_AARCH64_TLSLD_ADD_DTPREL_LO12 = 529;
	public static final int R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC = 530;
	public static final int R_AARCH64_TLSLD_LDST8_DTPREL_LO12 = 531;
	public static final int R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC = 532;
	public static final int R_AARCH64_TLSLD_LDST16_DTPREL_LO12 = 533;
	public static final int R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC = 534;
	public static final int R_AARCH64_TLSLD_LDST32_DTPREL_LO12 = 535;
	public static final int R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC = 536;
	public static final int R_AARCH64_TLSLD_LDST64_DTPREL_LO12 = 537;
	public static final int R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC = 538; 

	public static final int R_AARCH64_TLSIE_MOVW_GOTTPREL_G1 = 539;
	public static final int R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC = 540;
	public static final int R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21 = 541;
	public static final int R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC = 542;
	public static final int R_AARCH64_TLSIE_LD_GOTTPREL_PREL19 = 543;  

	public static final int R_AARCH64_TLSLE_MOVW_TPREL_G2 = 544;
	public static final int R_AARCH64_TLSLE_MOVW_TPREL_G1 = 545;
	public static final int R_AARCH64_TLSLE_MOVW_TPREL_G1_NC = 546;
	public static final int R_AARCH64_TLSLE_MOVW_TPREL_G0 = 547;
	public static final int R_AARCH64_TLSLE_MOVW_TPREL_G0_NC = 548;
	public static final int R_AARCH64_TLSLE_ADD_TPREL_HI12 = 549;
	public static final int R_AARCH64_TLSLE_ADD_TPREL_LO12 = 550;
	public static final int R_AARCH64_TLSLE_ADD_TPREL_LO12_NC = 551;
	public static final int R_AARCH64_TLSLE_LDST8_TPREL_LO12 = 552;
	public static final int R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC = 553;
	public static final int R_AARCH64_TLSLE_LDST16_TPREL_LO12 = 554;
	public static final int R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC = 555;
	public static final int R_AARCH64_TLSLE_LDST32_TPREL_LO12 = 556;
	public static final int R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC = 557;
	public static final int R_AARCH64_TLSLE_LDST64_TPREL_LO12 = 558;
	public static final int R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC = 559;

	public static final int R_AARCH64_TLSDESC_LD_PREL19 = 560;
	public static final int R_AARCH64_TLSDESC_ADR_PREL21 = 561;
	public static final int R_AARCH64_TLSDESC_ADR_PAGE21 = 562;
	public static final int R_AARCH64_TLSDESC_LD64_LO12_NC = 563;
	public static final int R_AARCH64_TLSDESC_ADD_LO12_NC = 564;
	public static final int R_AARCH64_TLSDESC_OFF_G1 = 565;
	public static final int R_AARCH64_TLSDESC_OFF_G0_NC = 566;
	public static final int R_AARCH64_TLSDESC_LDR = 567;
	public static final int R_AARCH64_TLSDESC_ADD = 568;
	public static final int R_AARCH64_TLSDESC_CALL = 569;

	public static final int R_AARCH64_TLSLE_LDST128_TPREL_LO12 = 570;
	public static final int R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC = 571;
	public static final int R_AARCH64_TLSLD_LDST128_DTPREL_LO12 = 572;
	public static final int R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC = 573;

	// Copy symbol at runtime.  
	public static final int R_AARCH64_COPY = 1024;

	// Create GOT entry.  
	public static final int R_AARCH64_GLOB_DAT = 1025;

	 // Create PLT entry.  
	public static final int R_AARCH64_JUMP_SLOT = 1026;

	// Adjust by program base.  
	public static final int R_AARCH64_RELATIVE = 1027;
	public static final int R_AARCH64_TLS_DTPMOD64 = 1028;
	public static final int R_AARCH64_TLS_DTPREL64 = 1029;
	public static final int R_AARCH64_TLS_TPREL64 = 1030;

	public static final int R_AARCH64_TLS_DTPMOD = 1028;
	public static final int R_AARCH64_TLS_DTPREL = 1029;
	public static final int R_AARCH64_TLS_TPREL = 1030;

	public static final int R_AARCH64_TLSDESC = 1031;
	public static final int R_AARCH64_IRELATIVE = 1032;

	private AARCH64_ElfRelocationConstants() {
		// no construct
	}
}
