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

public enum MIPS_ElfRelocationType implements ElfRelocationType {

	R_MIPS_NONE(0),
	R_MIPS_16(1),
	R_MIPS_32(2), 		// In Elf 64: alias R_MIPS_ADD
	R_MIPS_REL32(3), 	// In Elf 64: alias R_MIPS_REL
	R_MIPS_26(4),
	R_MIPS_HI16(5),
	R_MIPS_LO16(6),
	R_MIPS_GPREL16(7), 	// In Elf 64: alias R_MIPS_GPREL
	R_MIPS_LITERAL(8),
	R_MIPS_GOT16(9), 	// In Elf 64: alias R_MIPS_GOT
	R_MIPS_PC16(10),
	R_MIPS_CALL16(11),	// In Elf 64: alias R_MIPS_CALL
	R_MIPS_GPREL32(12),

	/* The remaining relocs are defined on Irix(although they are not in the MIPS ELF ABI.  */
	R_MIPS_UNUSED1(13),
	R_MIPS_UNUSED2(14),
	R_MIPS_UNUSED3(15),
	R_MIPS_SHIFT5(16),
	R_MIPS_SHIFT6(17),
	R_MIPS_64(18),
	R_MIPS_GOT_DISP(19),
	R_MIPS_GOT_PAGE(20),
	R_MIPS_GOT_OFST(21),
	R_MIPS_GOT_HI16(22),
	R_MIPS_GOT_LO16(23),
	R_MIPS_SUB(24),
	R_MIPS_INSERT_A(25),
	R_MIPS_INSERT_B(26),
	R_MIPS_DELETE(27),
	R_MIPS_HIGHER(28),
	R_MIPS_HIGHEST(29),
	R_MIPS_CALL_HI16(30),
	R_MIPS_CALL_LO16(31),
	R_MIPS_SCN_DISP(32),
	R_MIPS_REL16(33),
	R_MIPS_ADD_IMMEDIATE(34),
	R_MIPS_PJUMP(35),
	R_MIPS_RELGOT(36),
	R_MIPS_JALR(37),

	/* TLS relocations.  */
	R_MIPS_TLS_DTPMOD32(38),
	R_MIPS_TLS_DTPREL32(39),
	R_MIPS_TLS_DTPMOD64(40),
	R_MIPS_TLS_DTPREL64(41),
	R_MIPS_TLS_GD(42),
	R_MIPS_TLS_LDM(43),
	R_MIPS_TLS_DTPREL_HI16(44),
	R_MIPS_TLS_DTPREL_LO16(45),
	R_MIPS_TLS_GOTTPREL(46),
	R_MIPS_TLS_TPREL32(47),
	R_MIPS_TLS_TPREL64(48),
	R_MIPS_TLS_TPREL_HI16(49),
	R_MIPS_TLS_TPREL_LO16(50),
	R_MIPS_GLOB_DAT(51),

	/* MIPSr6 relocations */
	R_MIPS_PC21_S2(60),
	R_MIPS_PC26_S2(61),
	R_MIPS_PC18_S3(62),
	R_MIPS_PC19_S2(63),
	R_MIPS_PCHI16(64),
	R_MIPS_PCLO16(65),

	/* These relocs are used for the mips16.  */
	R_MIPS16_26(100),
	R_MIPS16_GPREL(101),
	R_MIPS16_GOT16(102),
	R_MIPS16_CALL16(103),
	R_MIPS16_HI16(104),
	R_MIPS16_LO16(105),
	R_MIPS16_TLS_GD(106),
	R_MIPS16_TLS_LDM(107),
	R_MIPS16_TLS_DTPREL_HI16(108),
	R_MIPS16_TLS_DTPREL_LO16(109),
	R_MIPS16_TLS_GOTTPREL(110),
	R_MIPS16_TLS_TPREL_HI16(111),
	R_MIPS16_TLS_TPREL_LO16(112),
	R_MIPS16_PC16_S1(113),

	R_MIPS16_LO(100), // First MIPS16 reloc type
	R_MIPS16_HI(112), // Last MIPS16 reloc type

	/* These relocations are specific to VxWorks.  */
	R_MIPS_COPY(126),
	R_MIPS_JUMP_SLOT(127),

	/* These relocations are specific to the MicroMIPS */
	R_MICROMIPS_26_S1(133),
	R_MICROMIPS_HI16(134),
	R_MICROMIPS_LO16(135),
	R_MICROMIPS_GPREL16(136),
	R_MICROMIPS_LITERAL(137),
	R_MICROMIPS_GOT16(138),
	R_MICROMIPS_PC7_S1(139),   // no shuffle required
	R_MICROMIPS_PC10_S1(140),  // no shuffle required
	R_MICROMIPS_PC16_S1(141),
	R_MICROMIPS_CALL16(142),

	R_MICROMIPS_GOT_DISP(145),
	R_MICROMIPS_GOT_PAGE(146),
	R_MICROMIPS_GOT_OFST(147),
	R_MICROMIPS_GOT_HI16(148),
	R_MICROMIPS_GOT_LO16(149),
	R_MICROMIPS_SUB(150),
	R_MICROMIPS_HIGHER(151),
	R_MICROMIPS_HIGHEST(152),
	R_MICROMIPS_CALL_HI16(153),
	R_MICROMIPS_CALL_LO16(154),
	R_MICROMIPS_SCN_DISP(155),
	R_MICROMIPS_JALR(156),
	R_MICROMIPS_HI0_LO16(157),

	/* TLS MicroMIPS related relocations */
	R_MICROMIPS_TLS_GD(162),
	R_MICROMIPS_TLS_LDM(163),
	R_MICROMIPS_TLS_DTPREL_HI16(164),
	R_MICROMIPS_TLS_DTPREL_LO16(165),
	R_MICROMIPS_TLS_GOTTPREL(166),

	R_MICROMIPS_TLS_TPREL_HI16(169),

	R_MICROMIPS_TLS_TPREL_LO16(170),

	R_MICROMIPS_GPREL7_S2(172),
	R_MICROMIPS_PC23_S2(173),

	R_MICROMIPS_LO(133), // First MicroMIPS reloc type
	R_MICROMIPS_HI(173), // Last MicroMIPS reloc type

	R_MIPS_PC32(248),
	R_MIPS_EH(249),
	R_MIPS_GNU_REL16_S2(250),

	R_MIPS_GNU_VTINHERIT(253),
	R_MIPS_GNU_VTENTRY(254);

	public final int typeId;

	private MIPS_ElfRelocationType(int typeId) {
		this.typeId = typeId;
	}

	@Override
	public int typeId() {
		return typeId;
	}
}
