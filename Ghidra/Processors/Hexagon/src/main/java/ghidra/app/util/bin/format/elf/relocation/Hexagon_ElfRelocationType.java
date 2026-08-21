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

public enum Hexagon_ElfRelocationType implements ElfRelocationType {

	/**
	 * NOTES:
	 * 1. The GP register is set to the starting address of the process's small data area, 
	 *    as referenced by the program symbol, "_SDA_BASE_".
	 * 
	 * 
	 */

	/* V2 */
	R_HEXAGON_NONE(0),
	R_HEXAGON_B22_PCREL(1),
	R_HEXAGON_B15_PCREL(2),
	R_HEXAGON_B7_PCREL(3),
	R_HEXAGON_LO16(4),
	R_HEXAGON_HI16(5),
	R_HEXAGON_32(6),
	R_HEXAGON_16(7),
	R_HEXAGON_8(8),
	R_HEXAGON_GPREL16_0(9),
	R_HEXAGON_GPREL16_1(10),
	R_HEXAGON_GPREL16_2(11),
	R_HEXAGON_GPREL16_3(12),
	R_HEXAGON_HL16(13),

	/* V3 */
	R_HEXAGON_B13_PCREL(14),

	/* V4 */
	R_HEXAGON_B9_PCREL(15),

	/* V4 (extenders) */
	R_HEXAGON_B32_PCREL_X(16),
	R_HEXAGON_32_6_X(17),

	/* V4 (extended) */
	R_HEXAGON_B22_PCREL_X(18),
	R_HEXAGON_B15_PCREL_X(19),
	R_HEXAGON_B13_PCREL_X(20),
	R_HEXAGON_B9_PCREL_X(21),
	R_HEXAGON_B7_PCREL_X(22),
	R_HEXAGON_16_X(23),
	R_HEXAGON_12_X(24),
	R_HEXAGON_11_X(25),
	R_HEXAGON_10_X(26),
	R_HEXAGON_9_X(27),
	R_HEXAGON_8_X(28),
	R_HEXAGON_7_X(29),
	R_HEXAGON_6_X(30),

	/* V2 PIC */
	R_HEXAGON_32_PCREL(31),
	R_HEXAGON_COPY(32),
	R_HEXAGON_GLOB_DAT(33),
	R_HEXAGON_JMP_SLOT(34),
	R_HEXAGON_RELATIVE(35),
	R_HEXAGON_PLT_B22_PCREL(36),
	R_HEXAGON_GOTOFF_LO16(37),
	R_HEXAGON_GOTOFF_HI16(38),
	R_HEXAGON_GOTOFF_32(39),
	R_HEXAGON_GOT_LO16(40),
	R_HEXAGON_GOT_HI16(41),
	R_HEXAGON_GOT_32(42),
	R_HEXAGON_GOT_16(43),

	R_HEXAGON_DTPMOD_32(44),
	R_HEXAGON_DTPREL_LO16(45),
	R_HEXAGON_DTPREL_HI16(46),
	R_HEXAGON_DTPREL_32(47),
	R_HEXAGON_DTPREL_16(48),
	R_HEXAGON_GD_PLT_B22_PCREL(49),
	R_HEXAGON_GD_GOT_LO16(50),
	R_HEXAGON_GD_GOT_HI16(51),
	R_HEXAGON_GD_GOT_32(52),
	R_HEXAGON_GD_GOT_16(53),
	R_HEXAGON_IE_LO16(54),
	R_HEXAGON_IE_HI16(55),
	R_HEXAGON_IE_32(56),
	R_HEXAGON_IE_GOT_LO16(57),
	R_HEXAGON_IE_GOT_HI16(58),
	R_HEXAGON_IE_GOT_32(59),
	R_HEXAGON_IE_GOT_16(60),
	R_HEXAGON_TPREL_LO16(61),
	R_HEXAGON_TPREL_HI16(62),
	R_HEXAGON_TPREL_32(63),
	R_HEXAGON_TPREL_16(64),
	R_HEXAGON_6_PCREL_X(65),
	R_HEXAGON_GOTREL_32_6_X(66),
	R_HEXAGON_GOTREL_16_X(67),
	R_HEXAGON_GOTREL_11_X(68),
	R_HEXAGON_GOT_32_6_X(69),
	R_HEXAGON_GOT_16_X(70),
	R_HEXAGON_GOT_11_X(71),
	R_HEXAGON_DTPREL_32_6_X(72),
	R_HEXAGON_DTPREL_16_X(73),
	R_HEXAGON_DTPREL_11_X(74),
	R_HEXAGON_GD_GOT_32_6_X(75),
	R_HEXAGON_GD_GOT_16_X(76),
	R_HEXAGON_GD_GOT_11_X(77),
	R_HEXAGON_IE_32_6_X(78),
	R_HEXAGON_IE_16_X(79),
	R_HEXAGON_IE_GOT_32_6_X(80),
	R_HEXAGON_IE_GOT_16_X(81),
	R_HEXAGON_IE_GOT_11_X(82),
	R_HEXAGON_TPREL_32_6_X(83),
	R_HEXAGON_TPREL_16_X(84),
	R_HEXAGON_TPREL_11_X(85),
	R_HEXAGON_LD_PLT_B22_PCREL(86),
	R_HEXAGON_LD_GOT_LO16(87),
	R_HEXAGON_LD_GOT_HI16(88),
	R_HEXAGON_LD_GOT_32(89),
	R_HEXAGON_LD_GOT_16(90),
	R_HEXAGON_LD_GOT_32_6_X(91),
	R_HEXAGON_LD_GOT_16_X(92),
	R_HEXAGON_LD_GOT_11_X(93),
	R_HEXAGON_23_REG(94),
	R_HEXAGON_GD_PLT_B22_PCREL_X(95),
	R_HEXAGON_GD_PLT_B32_PCREL_X(96),
	R_HEXAGON_LD_PLT_B22_PCREL_X(97),
	R_HEXAGON_LD_PLT_B32_PCREL_X(98),
	R_HEXAGON_27_REG(99);

	public final int typeId;

	private Hexagon_ElfRelocationType(int typeId) {
		this.typeId = typeId;
	}

	@Override
	public int typeId() {
		return typeId;
	}
}
