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

public enum SH_ElfRelocationType implements ElfRelocationType {

	R_SH_NONE(0),    // No operation needed
	R_SH_DIR32(1),   // (S + A) */
	R_SH_REL32(2),   // (S + A) - P
	R_SH_DIR8WPN(3), // 8-bit PC relative branch divided by 2 :  (((S + A) - P) >> 1) & 0xff
	R_SH_IND12W(4),  // 12-bit PC relative branch divided by 2 :  (((S + A) - P) >> 1) & 0xfff
	R_SH_DIR8WPL(5), // 8-bit PC unsigned-relative branch divided by 4 :  (((S + A) - P) >> 2) & 0xff
	R_SH_DIR8WPZ(6), // 8-bit PC unsigned-relative branch divided by 2 :  (((S + A) - P) >> 1) & 0xff
	R_SH_DIR8BP(7),
	R_SH_DIR8W(8),
	R_SH_DIR8L(9),

	// Relocation numbering in this file corresponds to GNU binutils and
	// values below this point may differ significantly from those specified
	// for other uses (e.g., see https://android.googlesource.com/platform/external/elfutils/+/android-4.1.2_r1/libelf/elf.h )

	R_SH_LOOP_START(10),
	R_SH_LOOP_END(11),

	R_SH_GNU_VTINHERIT(22),
	R_SH_GNU_VTENTRY(23),
	R_SH_SWITCH8(24),

	R_SH_SWITCH16(25),
	R_SH_SWITCH32(26),
	R_SH_USES(27),
	R_SH_COUNT(28),
	R_SH_ALIGN(29),
	R_SH_CODE(30),
	R_SH_DATA(31),
	R_SH_LABEL(32),

	R_SH_DIR16(33),
	R_SH_DIR8(34),
	R_SH_DIR8UL(35),
	R_SH_DIR8UW(36),
	R_SH_DIR8U(37),
	R_SH_DIR8SW(38),
	R_SH_DIR8S(39),
	R_SH_DIR4UL(40),
	R_SH_DIR4UW(41),
	R_SH_DIR4U(42),
	R_SH_PSHA(43),
	R_SH_PSHL(44),
	R_SH_DIR5U(45),
	R_SH_DIR6U(46),
	R_SH_DIR6S(47),
	R_SH_DIR10S(48),
	R_SH_DIR10SW(49),
	R_SH_DIR10SL(50),
	R_SH_DIR10SQ(51),

	R_SH_DIR16S(53),

	R_SH_TLS_GD_32(144),
	R_SH_TLS_LD_32(145),
	R_SH_TLS_LDO_32(146),
	R_SH_TLS_IE_32(147),
	R_SH_TLS_LE_32(148),
	R_SH_TLS_DTPMOD32(149),
	R_SH_TLS_DTPOFF32(150),
	R_SH_TLS_TPOFF32(151),

	R_SH_GOT32(160),
	R_SH_PLT32(161),
	R_SH_COPY(162),
	R_SH_GLOB_DAT(163),
	R_SH_JMP_SLOT(164),
	R_SH_RELATIVE(165),
	R_SH_GOTOFF(166),
	R_SH_GOTPC(167),
	R_SH_GOTPLT32(168),
	R_SH_GOT_LOW16(169),
	R_SH_GOT_MEDLOW16(170),
	R_SH_GOT_MEDHI16(171),
	R_SH_GOT_HI16(172),
	R_SH_GOTPLT_LOW16(173),
	R_SH_GOTPLT_MEDLOW16(174),
	R_SH_GOTPLT_MEDHI16(175),
	R_SH_GOTPLT_HI16(176),
	R_SH_PLT_LOW16(177),
	R_SH_PLT_MEDLOW16(178),
	R_SH_PLT_MEDHI16(179),
	R_SH_PLT_HI16(180),
	R_SH_GOTOFF_LOW16(181),
	R_SH_GOTOFF_MEDLOW16(182),
	R_SH_GOTOFF_MEDHI16(183),
	R_SH_GOTOFF_HI16(184),
	R_SH_GOTPC_LOW16(185),
	R_SH_GOTPC_MEDLOW16(186),
	R_SH_GOTPC_MEDHI16(187),
	R_SH_GOTPC_HI16(188),
	R_SH_GOT10BY4(189),
	R_SH_GOTPLT10BY4(190),
	R_SH_GOT10BY8(191),
	R_SH_GOTPLT10BY8(192),
	R_SH_COPY64(193),
	R_SH_GLOB_DAT64(194),
	R_SH_JMP_SLOT64(195),
	R_SH_RELATIVE64(196),

	R_SH_SHMEDIA_CODE(242),
	R_SH_PT_16(243),
	R_SH_IMMS16(244),
	R_SH_IMMU16(245),
	R_SH_IMM_LOW16(246),
	R_SH_IMM_LOW16_PCREL(247),
	R_SH_IMM_MEDLOW16(248),
	R_SH_IMM_MEDLOW16_PCREL(249),
	R_SH_IMM_MEDHI16(250),
	R_SH_IMM_MEDHI16_PCREL(251),
	R_SH_IMM_HI16(252),
	R_SH_IMM_HI16_PCREL(253),
	R_SH_64(254),
	R_SH_64_PCREL(255);

	public final int typeId;

	private SH_ElfRelocationType(int typeId) {
		this.typeId = typeId;
	}

	@Override
	public int typeId() {
		return typeId;
	}
}
