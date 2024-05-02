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

public enum AVR8_ElfRelocationType implements ElfRelocationType {

	R_AVR_NONE(0),
	R_AVR_32(1),
	R_AVR_7_PCREL(2),
	R_AVR_13_PCREL(3),
	R_AVR_16(4),
	R_AVR_16_PM(5),
	R_AVR_LO8_LDI(6),
	R_AVR_HI8_LDI(7),
	R_AVR_HH8_LDI(8),
	R_AVR_LO8_LDI_NEG(9),
	R_AVR_HI8_LDI_NEG(10),
	R_AVR_HH8_LDI_NEG(11),
	R_AVR_LO8_LDI_PM(12),
	R_AVR_HI8_LDI_PM(13),
	R_AVR_HH8_LDI_PM(14),
	R_AVR_LO8_LDI_PM_NEG(15),
	R_AVR_HI8_LDI_PM_NEG(16),
	R_AVR_HH8_LDI_PM_NEG(17),
	R_AVR_CALL(18),
	R_AVR_LDI(19),
	R_AVR_6(20),
	R_AVR_6_ADIW(21),
	R_AVR_MS8_LDI(22),
	R_AVR_MS8_LDI_NEG(23),
	R_AVR_LO8_LDI_GS(24),
	R_AVR_HI8_LDI_GS(25),
	R_AVR_8(26),
	R_AVR_8_LO8(27),
	R_AVR_8_HI8(28),
	R_AVR_8_HLO8(29),
	R_AVR_DIFF8(30),
	R_AVR_DIFF16(31),
	R_AVR_DIFF32(32),
	R_AVR_LDS_STS_16(33),
	R_AVR_PORT6(34),
	R_AVR_PORT5(35),
	R_AVR_32_PCREL(36);

	public final int typeId;

	private AVR8_ElfRelocationType(int typeId) {
		this.typeId = typeId;
	}

	@Override
	public int typeId() {
		return typeId;
	}

}
