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

public enum PIC30_ElfRelocationType implements ElfRelocationType {

	R_PIC30_NONE(0),
	R_PIC30_8(1),
	R_PIC30_16(2),
	R_PIC30_32(3),
	R_PIC30_FILE_REG_BYTE(4),
	R_PIC30_FILE_REG(5),
	R_PIC30_FILE_REG_WORD(6),
	R_PIC30_FILE_REG_WORD_WITH_DST(7),
	R_PIC30_WORD(8),
	R_PIC30_PBYTE(9),
	R_PIC30_PWORD(10),
	R_PIC30_HANDLE(11),
	R_PIC30_PADDR(12),
	R_PIC30_P_PADDR(13),
	R_PIC30_PSVOFFSET(14),
	R_PIC30_TBLOFFSET(15),
	R_PIC30_WORD_HANDLE(16),
	R_PIC30_WORD_PSVOFFSET(17),
	R_PIC30_PSVPAGE(18),
	R_PIC30_P_PSVPAGE(19),
	R_PIC30_WORD_PSVPAGE(20),
	R_PIC30_WORD_TBLOFFSET(21),
	R_PIC30_TBLPAGE(22),
	R_PIC30_P_TBLPAGE(23),
	R_PIC30_WORD_TBLPAGE(24),
	R_PIC30_P_HANDLE(25),
	R_PIC30_P_PSVOFFSET(26),
	R_PIC30_P_TBLOFFSET(27),
	R_PIC30_PCREL_BRANCH(28),
	R_PIC30_BRANCH_ABSOLUTE(29),
	R_PIC30_PCREL_DO(30),
	R_PIC30_DO_ABSOLUTE(31),
	R_PIC30_PGM_ADDR_LSB(32),
	R_PIC30_PGM_ADDR_MSB(33),
	R_PIC30_UNSIGNED_4(34),
	R_PIC30_UNSIGNED_5(35),
	R_PIC30_BIT_SELECT_3(36),
	R_PIC30_BIT_SELECT_4_BYTE(37),
	R_PIC30_BIT_SELECT_4(38),
	R_PIC30_DSP_6(39),
	R_PIC30_DSP_PRESHIFT(40),
	R_PIC30_SIGNED_10_BYTE(41),
	R_PIC30_UNSIGNED_10(42),
	R_PIC30_UNSIGNED_14(43),
	R_PIC30_FRAME_SIZE(44),
	R_PIC30_PWRSAV_MODE(45),
	R_PIC30_DMAOFFSET(46),
	R_PIC30_P_DMAOFFSET(47),
	R_PIC30_WORD_DMAOFFSET(48),
	R_PIC30_PSVPTR(49),
	R_PIC30_P_PSVPTR(50),
	R_PIC30_L_PSVPTR(51),
	R_PIC30_WORD_PSVPTR(52),
	R_PIC30_CALL_ACCESS(53),
	R_PIC30_PCREL_ACCESS(54),
	R_PIC30_ACCESS(55),
	R_PIC30_P_ACCESS(56),
	R_PIC30_L_ACCESS(57),
	R_PIC30_WORD_ACCESS(58),
	R_PIC30_EDSPAGE(59),
	R_PIC30_P_EDSPAGE(60),
	R_PIC30_WORD_EDSPAGE(61),
	R_PIC30_EDSOFFSET(62),
	R_PIC30_P_EDSOFFSET(63),
	R_PIC30_WORD_EDSOFFSET(64),
	R_PIC30_UNSIGNED_8(65);

	public final int typeId;

	private PIC30_ElfRelocationType(int typeId) {
		this.typeId = typeId;
	}

	@Override
	public int typeId() {
		return typeId;
	}
}
