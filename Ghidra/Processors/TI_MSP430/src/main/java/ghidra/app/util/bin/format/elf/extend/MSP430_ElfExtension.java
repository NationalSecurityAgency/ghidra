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
package ghidra.app.util.bin.format.elf.extend;

import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.opinion.ElfLoaderOptionsFactory;
import ghidra.program.model.lang.Language;

public class MSP430_ElfExtension extends ElfExtension {

	public static final int E_MSP430_MACH = 0xff;

	public static final int E_MSP430_MACH_MSP430X = 45; // 20-bit extended, all others are 16-bit

	// Elf Section Header Extensions
	public static final ElfSectionHeaderType SHT_MSP430_ATTRIBUTES = new ElfSectionHeaderType(
		0x70000003, "SHT_MSP430_ATTRIBUTES", "Section contains ABI attributes");
	public static final ElfSectionHeaderType SHT_MSP430_SEC_FLAGS = new ElfSectionHeaderType(
		0x70000005, "SHT_MSP430_SEC_FLAGS", "Section contains compiler's section flags");
	public static final ElfSectionHeaderType SHT_MSP430_SYM_ALIASES = new ElfSectionHeaderType(
		0x70000006, "SHT_MSP430_SYM_ALIASES", "Section contains compiler's symbol aliases");

	// Attribute section values
	public static final int OFBA_MSPABI_Tag_ISA = 4;
	public static final int OFBA_MSPABI_Tag_Code_Model = 6;
	public static final int OFBA_MSPABI_Tag_Data_Model = 8;
	public static final int OFBA_MSPABI_Tag_enum_size = 10;

	// Values defined for OFBA_MSPABI_Tag_ISA
	public static final int OFBA_MSPABI_Val_ISA_NONE = 0;
	public static final int OFBA_MSPABI_Val_ISA_MSP430 = 1;
	public static final int OFBA_MSPABI_Val_ISA_MSP430X = 2;

	// Values defined for OFBA_MSPABI_Tag_Code_Model.  */
	public static final int OFBA_MSPABI_Val_Code_Model_NONE = 0;
	public static final int OFBA_MSPABI_Val_Code_Model_SMALL = 1;
	public static final int OFBA_MSPABI_Val_Code_Model_LARGE = 2;

	// Values defined for OFBA_MSPABI_Tag_Data_Model.  */
	public static final int OFBA_MSPABI_Val_Data_Model_NONE = 0;
	public static final int OFBA_MSPABI_Val_Data_Model_SMALL = 1;
	public static final int OFBA_MSPABI_Val_Data_Model_LARGE = 2;
	public static final int OFBA_MSPABI_Val_Data_Model_RESTRICTED = 3; /* Unused by GNU.  */

	// Values defined for Tag_GNU_MSP430_Data_Region
	public static final int Val_GNU_MSP430_Data_Region_NONE = 0;
	// The default data region.  Assumes all data is below address 0x10000
	public static final int Val_GNU_MSP430_Data_Region_Lower = 1;
	// Set if -mdata-region={none;upper;either}.  Assumes data could be placed at or above address 0x10000
	public static final int Val_GNU_MSP430_Data_Region_Any = 2;

	@Override
	public boolean canHandle(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_MSP430;
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		Language language = elfLoadHelper.getProgram().getLanguage();
		return canHandle(elfLoadHelper.getElfHeader()) &&
			"TI_MSP430".equals(language.getProcessor().toString());
	}

	@Override
	public String getDataTypeSuffix() {
		return "_MSP430";
	}

	@Override
	public long getDefaultImageBase(ElfHeader elfHeader) {
		// same default used for 16 and 20-bit space
		return ElfLoaderOptionsFactory.IMAGE16_BASE_DEFAULT;
	}

}
