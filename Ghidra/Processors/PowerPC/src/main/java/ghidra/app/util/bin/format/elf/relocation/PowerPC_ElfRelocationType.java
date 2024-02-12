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

public enum PowerPC_ElfRelocationType implements ElfRelocationType {

	R_PPC_NONE(0),
	R_PPC_ADDR32(1), 			// word32 S + A
	R_PPC_ADDR24(2), 			// low24 (S + A) >> 2
	R_PPC_ADDR16(3), 			// half16 S + A
	R_PPC_ADDR16_LO(4), 		// half16 #lo(S + A)
	R_PPC_ADDR16_HI(5), 		// half16 #hi(S + A)
	R_PPC_ADDR16_HA(6), 		// half16 #ha(S + A)
	R_PPC_ADDR14(7), 			// low14 (S + A) >> 2
	R_PPC_ADDR14_BRTAKEN(8), 	// low14 (S + A) >> 2
	R_PPC_ADDR14_BRNTAKEN(9), 	// low14 (S + A) >> 2
	R_PPC_REL24(10), 			// low24 (S + A - P) >> 2
	R_PPC_REL14(11), 			// low14 (S + A - P) >> 2
	R_PPC_REL14_BRTAKEN(12), 	// low14 (S + A - P) >> 2
	R_PPC_REL14_BRNTAKEN(13), 	// low14 (S + A - P) >> 2
	R_PPC_GOT16(14), 			// half16 G + A
	R_PPC_GOT16_LO(15), 		// half16 #lo(G + A)
	R_PPC_GOT16_HI(16), 		// half16 #hi(G + A)
	R_PPC_GOT16_HA(17), 		// half16 #ha(G + A)
	R_PPC_PLTREL24(18), 		// low24 (L + A + P) >> 2
	R_PPC_COPY(19), 			// none none
	R_PPC_GLOB_DAT(20), 		// word32 S + A
	R_PPC_JMP_SLOT(21), 		// Old ABI: word32 S + A, New ABI: generate branch instruction
	R_PPC_RELATIVE(22), 		// word32 S + A
	R_PPC_LOCAL24PC(23), 		// none
	R_PPC_UADDR32(24), 			// low24
	R_PPC_UADDR16(25), 			// half16 S + A
	R_PPC_REL32(26), 			// word32 S + A - P
	R_PPC_PLT32(27), 			// word32 L + A
	R_PPC_PLTREL32(28), 		// word32 L + A - P
	R_PPC_PLT16_LO(29), 		// half16 #lo(L + A)
	R_PPC_PLT16_HI(30), 		// half16 #hi(L + A)
	R_PPC_PLT16_HA(31), 		// half16 #ha(L + A)
	R_PPC_SDAREL16(32), 		// half16 S + A - _SDA_BASE_
	R_PPC_SECTOFF(33), 			// half16 R + A
	R_PPC_SECTOFF_LO(34), 		// half16 #lo(R + A)
	R_PPC_SECTOFF_HI(35), 		// half16 #hi(R + A)
	R_PPC_SECTOFF_HA(36), 		// half16 #ha(R + A)
	R_PPC_ADDR30(37), 			// word30 (S + A - P) >> 2

	R_POWERPC_TLS(67),
	R_POWERPC_DTPMOD(68),
	R_POWERPC_TPREL16(69),
	R_POWERPC_TPREL16_LO(70),
	R_POWERPC_TPREL16_HI(71),
	R_POWERPC_TPREL16_HA(72),
	R_POWERPC_TPREL(73),
	R_POWERPC_DTPREL16(74),
	R_POWERPC_DTPREL16_LO(75),
	R_POWERPC_DTPREL16_HI(76),
	R_POWERPC_DTPREL16_HA(77),
	R_POWERPC_DTPREL(78),
	R_POWERPC_GOT_TLSGD16(79),
	R_POWERPC_GOT_TLSGD16_LO(80),
	R_POWERPC_GOT_TLSGD16_HI(81),
	R_POWERPC_GOT_TLSGD16_HA(82),
	R_POWERPC_GOT_TLSLD16(83),
	R_POWERPC_GOT_TLSLD16_LO(84),
	R_POWERPC_GOT_TLSLD16_HI(85),
	R_POWERPC_GOT_TLSLD16_HA(86),
	R_POWERPC_GOT_TPREL16(87),
	R_POWERPC_GOT_TPREL16_LO(88),
	R_POWERPC_GOT_TPREL16_HI(89),
	R_POWERPC_GOT_TPREL16_HA(90),
	R_POWERPC_GOT_DTPREL16(91),
	R_POWERPC_GOT_DTPREL16_LO(92),
	R_POWERPC_GOT_DTPREL16_HI(93),
	R_POWERPC_GOT_DTPREL16_HA(94),
	R_PPC_TLSGD(95),
	R_PPC_TLSLD(96),

	R_PPC_EMB_NADDR32(101), 	// uword32 (A - S)
	R_PPC_EMB_NADDR16(102), 	// uhalf16 (A - S)
	R_PPC_EMB_NADDR16_LO(103), 	// uhalf16 #lo(A - S)
	R_PPC_EMB_NADDR16_HI(104), 	// uhalf16 #hi(A - S)
	R_PPC_EMB_NADDR16_HA(105), 	// uhalf16 #ha(A - S)
	R_PPC_EMB_SDAI16(106), 		// uhalf16 T
	R_PPC_EMB_SDA2I16(107), 	// uhalf16 U
	R_PPC_EMB_SDA2REL(108), 	// uhalf16 S + A - _SDA2_BASE_
	R_PPC_EMB_SDA21(109), 		// ulow21
	R_PPC_EMB_MRKREF(110), 		// none
	R_PPC_EMB_RELSEC16(111), 	// uhalf16 V + A
	R_PPC_EMB_RELST_LO(112), 	// uhalf16 #lo(W + A)
	R_PPC_EMB_RELST_HI(113), 	// uhalf16 #hi(W + A)
	R_PPC_EMB_RELST_HA(114), 	// uhalf16 #ha(W + A)
	R_PPC_EMB_BIT_FLD(115), 	// uword32
	R_PPC_EMB_RELSDA(116), 		// uhalf16

	R_POWERPC_PLTSEQ(119),
	R_POWERPC_PLTCALL(120),

	R_PPC_VLE_REL8(216),
	R_PPC_VLE_REL15(217),
	R_PPC_VLE_REL24(218),
	R_PPC_VLE_LO16A(219),
	R_PPC_VLE_LO16D(220),
	R_PPC_VLE_HI16A(221),
	R_PPC_VLE_HI16D(222),
	R_PPC_VLE_HA16A(223),
	R_PPC_VLE_HA16D(224),
	R_PPC_VLE_SDA21(225),
	R_PPC_VLE_SDA21_LO(226),
	R_PPC_VLE_SDAREL_LO16A(227),
	R_PPC_VLE_SDAREL_LO16D(228),
	R_PPC_VLE_SDAREL_HI16A(229),
	R_PPC_VLE_SDAREL_HI16D(230),
	R_PPC_VLE_SDAREL_HA16A(231),
	R_PPC_VLE_SDAREL_HA16D(232),

	R_POWERPC_REL16DX_HA(246),
	R_POWERPC_IRELATIVE(248),
	R_POWERPC_REL16(249),
	R_POWERPC_REL16_LO(250),
	R_POWERPC_REL16_HI(251),
	R_POWERPC_REL16_HA(252),
	R_POWERPC_GNU_VTINHERIT(253),
	R_POWERPC_GNU_VTENTRY(254),
	R_PPC_TOC16(255);

	public final int typeId;

	private PowerPC_ElfRelocationType(int typeId) {
		this.typeId = typeId;
	}

	@Override
	public int typeId() {
		return typeId;
	}

}
