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

public enum SPARC_ElfRelocationType implements ElfRelocationType {

	R_SPARC_NONE(0),		// No calculation
	R_SPARC_8(1),			// S + A
	R_SPARC_16(2),			// S + A
	R_SPARC_32(3),			// S + A
	R_SPARC_DISP8(4),		// S + A - P
	R_SPARC_DISP16(5),		// S + A - P
	R_SPARC_DISP32(6),		// S + A - P
	R_SPARC_WDISP30(7),		// (S + A - P) >> 2
	R_SPARC_WDISP22(8),		// (S + A - P) >> 2
	R_SPARC_HI22(9),		// (S + A) >> 10
	R_SPARC_22(10),			// S + A
	R_SPARC_13(11),			// S + A
	R_SPARC_LO10(12),		// (S + A) & 0x3FF
	R_SPARC_GOT10(13),		// G & 0x3FF
	R_SPARC_GOT13(14),		// G
	R_SPARC_GOT22(15),		// G >> 10
	R_SPARC_PC10(16),		// (S + A - P) & 0x3FF
	R_SPARC_PC22(17),		// (S + A - P) >> 10
	R_SPARC_WPLT30(18),		// (L + A - P) >> 2
	R_SPARC_COPY(19),		// No calculation
	R_SPARC_GLOB_DAT(20),		// S + A
	R_SPARC_JMP_SLOT(21),		//
	R_SPARC_RELATIVE(22),		// B + A
	R_SPARC_UA32(23),		// S + A
	R_SPARC_PLT32(24),		// L + A
	R_SPARC_HIPLT22(25),		// (L + A) >> 10
	R_SPARC_LOPLT10(26),		// (L + A) & 0x3FF
	R_SPARC_PCPLT32(27),		// L + A - P
	R_SPARC_PCPLT22(28),		// (L + A - P) >> 10
	R_SPARC_PCPLT10(29),		// (L + A - P) & 0x3FF
	R_SPARC_10(30),			// S + A
	R_SPARC_11(31),			// S + A
	R_SPARC_64(32),			// S + A
	R_SPARC_OLO10(33),		// ((S + A) & 0x3ff) + O
	R_SPARC_HH22(34),		// (S + A) >> 42
	R_SPARC_HM10(35),		// ((S + A) >> 32) & 0x3ff
	R_SPARC_LM22(36),		// (S + A) >> 10
	R_SPARC_PC_H22(37),		// (S + A - P) >> 42
	R_SPARC_PC_HM10(38),		// ((S + A - P) >> 32) & 0x3ff
	R_SPARC_PC_LM22(39),		// (S + A - P) >> 10
	R_SPARC_WDISP16(40),		// (S + A - P) >> 2
	R_SPARC_WDISP19(41),		// (S + A - P) >> 2
	R_SPARC_UNUSED_42(42),		//
	R_SPARC_7(43),			// S + A
	R_SPARC_5(44),			// S + A
	R_SPARC_6(45),			// S + A
	R_SPARC_DISP64(46),		// S + A - P
	R_SPARC_PLT64(47),		// L + A
	R_SPARC_HIX22(48),		// ((S + A) ^ 0xffffffffffffffff) >> 10
	R_SPARC_LOX10(49),		// ((S + A) & 0x3ff) | 0x1c00
	R_SPARC_H44(50),		// ((S + A) >> 22
	R_SPARC_M44(51),		// ((S + A) >> 12) & 0x3ff
	R_SPARC_L44(52),		// (S + A) & 0xfff
	R_SPARC_REGISTER(53),		// S + A
	R_SPARC_UA64(54),		// S + A
	R_SPARC_UA16(55),		// S + A
	R_SPARC_TLS_GD_HI22(56),	//
	R_SPARC_TLS_GD_LO10(57),	//
	R_SPARC_TLS_GD_ADD(58),		//
	R_SPARC_TLS_GD_CALL(59),	//
	R_SPARC_TLS_LDM_HI22(60),	//
	R_SPARC_TLS_LDM_LO10(61),	//
	R_SPARC_TLS_LDM_ADD(62),	//
	R_SPARC_TLS_LDM_CALL(63),	//
	R_SPARC_TLS_LDO_HIX22(64),	//
	R_SPARC_TLS_LDO_LO10(65),	//
	R_SPARC_TLS_LDO_DD(66),		//
	R_SPARC_TLS_IE_HI22(67),	//
	R_SPARC_TLS_IE_LO10(68),	//
	R_SPARC_TLS_IE_(69),		//
	R_SPARC_TLS_IE_LDX(70),		//
	R_SPARC_TLS_IE_ADD(71),		//
	R_SPARC_TLS_LE_HIX22(72),	//
	R_SPARC_TLS_LE_LOX10(73),	//
	R_SPARC_TLS_DTPMOD32(74),	//
	R_SPARC_TLS_DTPMOD64(75),	//
	R_SPARC_TLS_DTPOFF32(76),	//
	R_SPARC_TLS_DTPOFF64(77),	//
	R_SPARC_TLS_TPOFF32(78),	//
	R_SPARC_TLS_TPOFF64(79),	//
	R_SPARC_GOTDATA_HIX22(80),	// ((S + A - GOT) >> 10) ^ ((S + A - GOT) >> 31)
	R_SPARC_GOTDATA_LOX10(81),	// ((S + A - GOT) & 0x3ff) | (((S + A - GOT) >> 31) & 0x1c00)
	R_SPARC_GOTDATA_OP_HIX22(82),	// (G >> 10) ^ (G >> 31)
	R_SPARC_GOTDATA_OP_LOX10(83),	// (G & 0x3ff) | ((G >> 31) & 0x1c00)
	R_SPARC_GOTDATA_OP(84),		//
	R_SPARC_H34(85),		// (S + A) >> 12
	R_SPARC_SIZE32(86),		// Z + A
	R_SPARC_SIZE64(87),		// Z + A
	R_SPARC_WDISP10(88),		// (S + A - P) >> 2

	// R_SPARC_max_std

	R_SPARC_JMP_IREL(248),		//
	R_SPARC_IRELATIVE(249),		//
	R_SPARC_GNU_VTIHERIT(250),	//
	R_SPARC_GNU_VTENTRY(251),	//
	R_SPARC_REV32(252);		//

	public final int typeId;

	private SPARC_ElfRelocationType(int typeId) {
		this.typeId = typeId;
	}

	@Override
	public int typeId() {
		return typeId;
	}

}
