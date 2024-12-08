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

public enum ARM_ElfRelocationType implements ElfRelocationType {

	R_ARM_NONE(0),			// No operation needed 
	R_ARM_PC24(1),			// ((S + A) | T) - P [DEPRECATED] 
	R_ARM_ABS32(2),			// (S + A) | T 
	R_ARM_REL32(3),			// ((S + A) | T) - P 
	R_ARM_LDR_PC_G0(4),		// S + A - P 
	R_ARM_ABS16(5),			// S + A 
	R_ARM_ABS12(6),			// S + A 
	R_ARM_THM_ABS5(7),		// S + A 
	R_ARM_ABS_8(8),			// S + A 
	R_ARM_SBREL32(9),		// ((S + A) | T) - B(S) 
	R_ARM_THM_CALL(10),		// ((S + A) | T) - P 
	R_ARM_THM_PC8(11),		// S + A - Pa 
	R_ARM_BREL_ADJ(12),		// DELTA(B(S)) + A 
	R_ARM_TLS_DESC(13),
	R_ARM_THM_SWI8(14),		// [OBSOLETE] 
	R_ARM_XPC25(15),		// [OBSOLETE] 
	R_ARM_THM_XPC22(16),	// [OBSOLETE] 
	R_ARM_TLS_DTPMOD32(17),	// Module[S] 
	R_ARM_TLS_DTPOFF32(18),	// S + A - TLS 
	R_ARM_TLS_TPOFF32(19),	// S + A - TLS 
	R_ARM_COPY(20),			// Miscellaneous 
	R_ARM_GLOB_DAT(21),		// (S + A) | T 
	R_ARM_JUMP_SLOT(22),	// (S + A) | T 
	R_ARM_RELATIVE(23),		// B(S) + A [Note: see Table 4-16] 
	R_ARM_GOTOFF32(24),		// ((S + A) | T) - GOT_ORG 
	R_ARM_BASE_PREL(25),	// B(S) + A - P 
	R_ARM_GOT_BREL(26),		// GOT(S) + A - GOT_ORG 
	R_ARM_PLT32(27),		// ((S + A) | T) - P 
	R_ARM_CALL(28),			// ((S + A) | T) - P 
	R_ARM_JUMP24(29),		// ((S + A) | T) - P 
	R_ARM_THM_JUMP24(30),	// ((S + A) | T) - P 
	R_ARM_BASE_ABS(31),		// B(S) + A 
	R_ARM_ALU_PCREL_7_0(32),		// Obsolete 
	R_ARM_ALU_PCREL_15_8(33),		// Obsolete 
	R_ARM_ALU_PCREL_23_15(34),		// Obsolete 
	R_ARM_LDR_SBREL_11_0_NC(35),	// S + A - B(S) 
	R_ARM_ALU_SBREL_19_12_NC(36),	// S + A - B(S) 
	R_ARM_ALU_SBREL_27_20_CK(37),	// S + A - B(S) 
	R_ARM_TARGET1(38),			// (S + A) | T or ((S + A) | T) - P 
	R_ARM_SBREL31(39),			// ((S + A) | T) - B(S) 
	R_ARM_V4BX(40),				// Miscellaneous 
	R_ARM_TARGET2(41),			// Miscellaneous 
	R_ARM_PREL31(42),			// ((S + A) | T) - P 
	R_ARM_MOVW_ABS_NC(43),		// (S + A) | T 
	R_ARM_MOVT_ABS(44),			// S + A 
	R_ARM_MOVW_PREL_NC(45),		// ((S + A) | T) - P 
	R_ARM_MOVT_PREL(46),		// S + A - P 
	R_ARM_THM_MOVW_ABS_NC(47),	// (S + A) | T 
	R_ARM_THM_MOVT_ABS(48),		// S + A 
	R_ARM_THM_MOVW_PREL_NC(49),	// ((S + A) | T) - P 
	R_ARM_THM_MOVT_PREL(50),	// S + A - P 
	R_ARM_THM_JUMP19(51),		// ((S + A) | T) - P 
	R_ARM_THM_JUMP6(52),		// S + A - P 
	R_ARM_THM_ALU_PREL_11_0(53),// ((S + A) | T) - Pa 
	R_ARM_THM_PC12(54),			// S + A - Pa 
	R_ARM_ABS32_NOI(55),		// S + A 
	R_ARM_REL32_NOI(56),		// S + A - P 
	R_ARM_ALU_PC_G0_NC(57),		// ((S + A) | T) - P 
	R_ARM_ALU_PC_G0(58),		// ((S + A) | T) - P 
	R_ARM_ALU_PC_G1_NC(59),		// ((S + A) | T) - P 
	R_ARM_ALU_PC_G1(60),		// ((S + A) | T) - P 
	R_ARM_ALU_PC_G2(61),		// ((S + A) | T) - P 
	R_ARM_LDR_PC_G1(62),		// S + A - P 
	R_ARM_LDR_PC_G2(63),		// S + A - P 
	R_ARM_LDRS_PC_G0(64),		// S + A - P 
	R_ARM_LDRS_PC_G1(65),		// S + A - P 
	R_ARM_LDRS_PC_G2(66),		// S + A - P 
	R_ARM_LDC_PC_G0(67),		// S + A - P 
	R_ARM_LDC_PC_G1(68),		// S + A - P 
	R_ARM_LDC_PC_G2(69),		// S + A - P 
	R_ARM_ALU_SB_G0_NC(70),		// ((S + A) | T) - B(S) 
	R_ARM_ALU_SB_G0(71),		// ((S + A) | T) - B(S) 
	R_ARM_ALU_SB_G1_NC(72),		// ((S + A) | T) - B(S) 
	R_ARM_ALU_SB_G1(73),		// ((S + A) | T) - B(S) 
	R_ARM_ALU_SB_G2(74),		// ((S + A) | T) - B(S) 
	R_ARM_LDR_SB_G0(75),		// S + A - B(S) 
	R_ARM_LDR_SB_G1(76),		// S + A - B(S) 
	R_ARM_LDR_SB_G2(77),		// S + A - B(S) 
	R_ARM_LDRS_SB_G0(78),		// S + A - B(S) 
	R_ARM_LDRS_SB_G1(79),		// S + A - B(S) 
	R_ARM_LDRS_SB_G2(80),		// S + A - B(S) 
	R_ARM_LDC_SB_G0(81),		// S + A - B(S) 
	R_ARM_LDC_SB_G1(82),		// S + A - B(S) 
	R_ARM_LDC_SB_G2(83),		// S + A - B(S) 
	R_ARM_MOVW_BREL_NC(84),		// ((S + A) | T) - B(S) 
	R_ARM_MOVT_BREL(85),		// S + A - B(S) 
	R_ARM_MOVW_BREL(86),		// ((S + A) | T) - B(S) 
	R_ARM_THM_MOVW_BREL_NC(87),	// ((S + A) | T) - B(S) 
	R_ARM_THM_MOVT_BREL(88),	// S + A - B(S) 
	R_ARM_THM_MOVW_BREL(89),	// ((S + A) | T) - B(S) 
	R_ARM_TLS_GOTDESC(90),
	R_ARM_TLS_CALL(91),
	R_ARM_TLS_DESCSEQ(92),		// TLS relaxation 
	R_ARM_THM_TLS_CALL(93),
	R_ARM_PLT32_ABS(94),		// PLT(S) + A 
	R_ARM_GOT_ABS(95),			// GOT(S) + A 
	R_ARM_GOT_PREL(96),			// GOT(S) + A - P 
	R_ARM_GOT_BREL12(97),		// GOT(S) + A - GOT_ORG 
	R_ARM_GOTOFF12(98),			// S + A - GOT_ORG 
	R_ARM_GOTRELAX(99),
	R_ARM_GNU_VTENTRY(100),
	R_ARM_GNU_VTINHERIT(101),
	R_ARM_THM_JUMP11(102),		// S + A - P 
	R_ARM_THM_JUMP8(103),		// S + A - P 
	R_ARM_TLS_GD32(104),		// GOT(S) + A - P 
	R_ARM_TLS_LDM32(105),		// GOT(S) + A - P 
	R_ARM_TLS_LDO32(106),		// S + A - TLS 
	R_ARM_TLS_IE32(107),		// GOT(S) + A - P 
	R_ARM_TLS_LE32(108),		// S + A - tp 
	R_ARM_TLS_LDO12(109),		// S + A - TLS 
	R_ARM_TLS_LE12(110),		// S + A - tp 
	R_ARM_TLS_IE12GP(111),		// GOT(S) + A - GOT_ORG 
	R_ARM_PRIVATE_0(112),
	R_ARM_PRIVATE_1(113),
	R_ARM_PRIVATE_2(114),
	R_ARM_PRIVATE_3(115),
	R_ARM_PRIVATE_4(116),
	R_ARM_PRIVATE_5(117),
	R_ARM_PRIVATE_6(118),
	R_ARM_PRIVATE_7(119),
	R_ARM_PRIVATE_8(120),
	R_ARM_PRIVATE_9(121),
	R_ARM_PRIVATE_10(122),
	R_ARM_PRIVATE_11(123),
	R_ARM_PRIVATE_12(124),
	R_ARM_PRIVATE_13(125),
	R_ARM_PRIVATE_14(126),
	R_ARM_PRIVATE_15(127),
	R_ARM_ME_TOO(128),
	R_ARM_THM_TLS_DESCSEQ16(129),
	R_ARM_THM_TLS_DESCSEQ32(130),
	R_ARM_THM_ALU_ABS_G0_NC(132),
	R_ARM_THM_ALU_ABS_G1_NC(133),
	R_ARM_THM_ALU_ABS_G2_NC(134),
	R_ARM_THM_ALU_ABS_G3_NC(135),
	R_ARM_THM_BF16(136),
	R_ARM_THM_BF12(137),
	R_ARM_THM_BF18(138),
	R_ARM_IRELATIVE(160),
	R_ARM_GOTFUNCDEC(161),
	R_ARM_GOTOFFFUNCDESC(162),
	R_ARM_FUNCESC(163),
	R_ARM_FUNCDESC_VALUE(164),
	R_ARM_TLS_GD32_FDPIC(165),
	R_ARM_TLS_LDM32_FDPIC(166),
	R_ARM_TLS_IE32_FDPIC(167),
	R_ARM_RXPC25(249),
	R_ARM_RSBREL32(250),
	R_ARM_THM_RPC22(251),
	R_ARM_RREL32(252),
	R_ARM_RABS32(253),
	R_ARM_RPC24(254),
	R_ARM_RBASE(255);

	public final int typeId;

	private ARM_ElfRelocationType(int typeId) {
		this.typeId = typeId;
	}

	@Override
	public int typeId() {
		return typeId;
	}
}
