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

public enum Xtensa_ElfRelocationType implements ElfRelocationType {

	/* Xtensa relocations defined by the ABIs */
	R_XTENSA_NONE(0),
	R_XTENSA_32(1),
	R_XTENSA_RTLD(2),
	R_XTENSA_GLOB_DAT(3),
	R_XTENSA_JMP_SLOT(4),
	R_XTENSA_RELATIVE(5),
	R_XTENSA_PLT(6),
	R_XTENSA_OP0(8),
	R_XTENSA_OP1(9),
	R_XTENSA_OP2(10),
	R_XTENSA_ASM_EXPAND(11),
	R_XTENSA_ASM_SIMPLIFY(12),

	R_XTENSA_32_PCREL(14),
	R_XTENSA_GNU_VTINHERIT(15),
	R_XTENSA_GNU_VTENTRY(16),
	R_XTENSA_DIFF8(17),
	R_XTENSA_DIFF16(18),
	R_XTENSA_DIFF32(19),
	R_XTENSA_SLOT0_OP(20),
	R_XTENSA_SLOT1_OP(21),
	R_XTENSA_SLOT2_OP(22),
	R_XTENSA_SLOT3_OP(23),
	R_XTENSA_SLOT4_OP(24),
	R_XTENSA_SLOT5_OP(25),
	R_XTENSA_SLOT6_OP(26),
	R_XTENSA_SLOT7_OP(27),
	R_XTENSA_SLOT8_OP(28),
	R_XTENSA_SLOT9_OP(29),
	R_XTENSA_SLOT10_OP(30),
	R_XTENSA_SLOT11_OP(31),
	R_XTENSA_SLOT12_OP(32),
	R_XTENSA_SLOT13_OP(33),
	R_XTENSA_SLOT14_OP(34),
	R_XTENSA_SLOT0_ALT(35),
	R_XTENSA_SLOT1_ALT(36),
	R_XTENSA_SLOT2_ALT(37),
	R_XTENSA_SLOT3_ALT(38),
	R_XTENSA_SLOT4_ALT(39),
	R_XTENSA_SLOT5_ALT(40),
	R_XTENSA_SLOT6_ALT(41),
	R_XTENSA_SLOT7_ALT(42),
	R_XTENSA_SLOT8_ALT(43),
	R_XTENSA_SLOT9_ALT(44),
	R_XTENSA_SLOT10_ALT(45),
	R_XTENSA_SLOT11_ALT(46),
	R_XTENSA_SLOT12_ALT(47),
	R_XTENSA_SLOT13_ALT(48),
	R_XTENSA_SLOT14_ALT(49),
	R_XTENSA_TLSDESC_FN(50),
	R_XTENSA_TLSDESC_ARG(51),
	R_XTENSA_TLS_DTPOFF(52),
	R_XTENSA_TLS_TPOFF(53),
	R_XTENSA_TLS_FUNC(54),
	R_XTENSA_TLS_ARG(55),
	R_XTENSA_TLS_CALL(56),
	R_XTENSA_PDIFF8(57),
	R_XTENSA_PDIFF16(58),
	R_XTENSA_PDIFF32(59),
	R_XTENSA_NDIFF8(60),
	R_XTENSA_NDIFF16(61),
	R_XTENSA_NDIFF32(62);

	public final int typeId;

	private Xtensa_ElfRelocationType(int typeId) {
		this.typeId = typeId;
	}

	@Override
	public int typeId() {
		return typeId;
	}
}
