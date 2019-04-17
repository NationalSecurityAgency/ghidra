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
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;

public class AARCH64_ElfExtension extends ElfExtension {

	// Elf Program Header Extensions
	public static final ElfProgramHeaderType PT_AARCH64_ARCHEXT =
		new ElfProgramHeaderType(0x70000000, "PT_AARCH64_ARCHEXT", "AARCH64 extension");

	// Elf Section Header Extensions
	public static final ElfSectionHeaderType SHT_AARCH64_ATTRIBUTES =
		new ElfSectionHeaderType(0x70000003, "SHT_AARCH64_ATTRIBUTES", "Attribute section");

	// Section header flags
	private static final int SHF_ENTRYSECT = 0x10000000; // section contains entry point
	private static final int SHF_COMDEF = 0x80000000; // section may be multiply defined

	@Override
	public boolean canHandle(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_AARCH64;
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		Language language = elfLoadHelper.getProgram().getLanguage();
		return canHandle(elfLoadHelper.getElfHeader()) &&
			"AARCH64".equals(language.getProcessor().toString());
	}

	@Override
	public String getDataTypeSuffix() {
		return "_AARCH64";
	}

	@Override
	public Address evaluateElfSymbol(ElfLoadHelper elfLoadHelper, ElfSymbol elfSymbol,
			Address address, boolean isExternal) {

		if (isExternal) {
			return address;
		}

		String symName = elfSymbol.getNameAsString();

		if ("$x".equals(symName) || symName.startsWith("$x.")) {
			elfLoadHelper.markAsCode(address);

			// do not retain $x symbols in program due to potential function/thunk naming interference
			elfLoadHelper.setElfSymbolAddress(elfSymbol, address);
			return null;
		}
		else if ("$d".equals(symName) || symName.startsWith("$d.")) {
			// is data, need to protect as data
			elfLoadHelper.createUndefinedData(address, (int) elfSymbol.getSize());

			// do not retain $x symbols in program due to excessive duplicate symbols
			elfLoadHelper.setElfSymbolAddress(elfSymbol, address);
			return null;
		}

		return address;
	}

}
