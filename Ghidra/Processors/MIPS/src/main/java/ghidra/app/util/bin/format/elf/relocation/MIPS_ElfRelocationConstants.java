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

public class MIPS_ElfRelocationConstants {

	public static final int R_MIPS_NONE = 0;
	public static final int R_MIPS_16 = 1;
	public static final int R_MIPS_32 = 2; /* In Elf 64: alias R_MIPS_ADD */
	public static final int R_MIPS_REL32 = 3; /* In Elf 64: alias R_MIPS_REL */
	public static final int R_MIPS_26 = 4;
	public static final int R_MIPS_HI16 = 5;
	public static final int R_MIPS_LO16 = 6;
	public static final int R_MIPS_GPREL16 = 7; /* In Elf 64: alias R_MIPS_GPREL */
	public static final int R_MIPS_LITERAL = 8;
	public static final int R_MIPS_GOT16 = 9; /* In Elf 64: alias R_MIPS_GOT */
	public static final int R_MIPS_PC16 = 10;
	public static final int R_MIPS_CALL16 = 11; /* In Elf 64: alias R_MIPS_CALL */
	public static final int R_MIPS_GPREL32 = 12;

	/* The remaining relocs are defined on Irix = although they are not
	   in the MIPS ELF ABI.  */
	public static final int R_MIPS_UNUSED1 = 13;
	public static final int R_MIPS_UNUSED2 = 14;
	public static final int R_MIPS_UNUSED3 = 15;
	public static final int R_MIPS_SHIFT5 = 16;
	public static final int R_MIPS_SHIFT6 = 17;
	public static final int R_MIPS_64 = 18;
	public static final int R_MIPS_GOT_DISP = 19;
	public static final int R_MIPS_GOT_PAGE = 20;
	public static final int R_MIPS_GOT_OFST = 21;
	public static final int R_MIPS_GOT_HI16 = 22;
	public static final int R_MIPS_GOT_LO16 = 23;
	public static final int R_MIPS_SUB = 24;
	public static final int R_MIPS_INSERT_A = 25;
	public static final int R_MIPS_INSERT_B = 26;
	public static final int R_MIPS_DELETE = 27;
	public static final int R_MIPS_HIGHER = 28;
	public static final int R_MIPS_HIGHEST = 29;
	public static final int R_MIPS_CALL_HI16 = 30;
	public static final int R_MIPS_CALL_LO16 = 31;
	public static final int R_MIPS_SCN_DISP = 32;
	public static final int R_MIPS_REL16 = 33;
	public static final int R_MIPS_ADD_IMMEDIATE = 34;
	public static final int R_MIPS_PJUMP = 35;
	public static final int R_MIPS_RELGOT = 36;
	public static final int R_MIPS_JALR = 37;

	/* TLS relocations.  */
	public static final int R_MIPS_TLS_DTPMOD32 = 38;
	public static final int R_MIPS_TLS_DTPREL32 = 39;
	public static final int R_MIPS_TLS_DTPMOD64 = 40;
	public static final int R_MIPS_TLS_DTPREL64 = 41;
	public static final int R_MIPS_TLS_GD = 42;
	public static final int R_MIPS_TLS_LDM = 43;
	public static final int R_MIPS_TLS_DTPREL_HI16 = 44;
	public static final int R_MIPS_TLS_DTPREL_LO16 = 45;
	public static final int R_MIPS_TLS_GOTTPREL = 46;
	public static final int R_MIPS_TLS_TPREL32 = 47;
	public static final int R_MIPS_TLS_TPREL64 = 48;
	public static final int R_MIPS_TLS_TPREL_HI16 = 49;
	public static final int R_MIPS_TLS_TPREL_LO16 = 50;
	public static final int R_MIPS_GLOB_DAT = 51;

	/* These relocs are used for the mips16.  */
	public static final int R_MIPS16_26 = 100;
	public static final int R_MIPS16_GPREL = 101;
	public static final int R_MIPS16_GOT16 = 102;
	public static final int R_MIPS16_CALL16 = 103;
	public static final int R_MIPS16_HI16 = 104;
	public static final int R_MIPS16_LO16 = 105;
	public static final int R_MIPS16_TLS_GD = 106;
	public static final int R_MIPS16_TLS_LDM = 107;
	public static final int R_MIPS16_TLS_DTPREL_HI16 = 108;
	public static final int R_MIPS16_TLS_DTPREL_LO16 = 109;
	public static final int R_MIPS16_TLS_GOTTPREL = 110;
	public static final int R_MIPS16_TLS_TPREL_HI16 = 111;
	public static final int R_MIPS16_TLS_TPREL_LO16 = 112;
	
	public static final int R_MIPS16_LO = 100; // First MIPS16 reloc type
	public static final int R_MIPS16_HI = 112; // Last MIPS16 reloc type

	/* These relocations are specific to VxWorks.  */
	public static final int R_MIPS_COPY = 126;
	public static final int R_MIPS_JUMP_SLOT = 127;

	/* These relocations are specific to the MicroMIPS */
	public static final int R_MICROMIPS_26_S1 = 133;
	public static final int R_MICROMIPS_HI16 = 134;
	public static final int R_MICROMIPS_LO16 = 135;
	public static final int R_MICROMIPS_GPREL16 = 136;
	public static final int R_MICROMIPS_LITERAL = 137;
	public static final int R_MICROMIPS_GOT16 = 138;
	public static final int R_MICROMIPS_PC7_S1 = 139;   // no shuffle required
	public static final int R_MICROMIPS_PC10_S1 = 140;  // no shuffle required
	public static final int R_MICROMIPS_PC16_S1 = 141;
	public static final int R_MICROMIPS_CALL16 = 142;
	
	public static final int R_MICROMIPS_GOT_DISP = 145;
	public static final int R_MICROMIPS_GOT_PAGE = 146;
	public static final int R_MICROMIPS_GOT_OFST = 147;
	public static final int R_MICROMIPS_GOT_HI16 = 148;
	public static final int R_MICROMIPS_GOT_LO16 = 149;
	public static final int R_MICROMIPS_SUB = 150;
	public static final int R_MICROMIPS_HIGHER = 151;
	public static final int R_MICROMIPS_HIGHEST = 152;
	public static final int R_MICROMIPS_CALL_HI16 = 153;
	public static final int R_MICROMIPS_CALL_LO16 = 154;
	public static final int R_MICROMIPS_SCN_DISP = 155;
	public static final int R_MICROMIPS_JALR = 156;
	public static final int R_MICROMIPS_HI0_LO16 = 157;

	/* TLS MicroMIPS related relocations */
	public static final int R_MICROMIPS_TLS_GD = 162;
	public static final int R_MICROMIPS_TLS_LDM = 163;
	public static final int R_MICROMIPS_TLS_DTPREL_HI16 = 164;
	public static final int R_MICROMIPS_TLS_DTPREL_LO16 = 165;
	public static final int R_MICROMIPS_TLS_GOTTPREL = 166;
	
	public static final int R_MICROMIPS_TLS_TPREL_HI16 = 169;
	
	public static final int R_MICROMIPS_TLS_TPREL_LO16 = 170;

	public static final int R_MICROMIPS_GPREL7_S2 = 172;
	public static final int R_MICROMIPS_PC23_S2 = 173;	
	
	public static final int R_MICROMIPS_LO = 133; // First MicroMIPS reloc type
	public static final int R_MICROMIPS_HI = 173; // Last MicroMIPS reloc type

	public static final int R_MIPS_PC32 = 248;

	// Masks for manipulating MIPS relocation targets
	public static final int MIPS_LOW26 = 0x03FFFFFF;
	
	private MIPS_ElfRelocationConstants() {
		// no construct
	}
}
