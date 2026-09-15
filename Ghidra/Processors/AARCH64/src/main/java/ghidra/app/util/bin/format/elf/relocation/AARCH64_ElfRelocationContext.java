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

import java.util.Map;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;

/**
 * <code>AARCH64_ElfRelocationContext</code> provides ability to generate a
 * Global Offset Table (GOT) to facilitate GOT related relocations encountered within 
 * object modules.
 */
class AARCH64_ElfRelocationContext extends ElfGotRelocationContext<AARCH64_ElfRelocationHandler> {

	AARCH64_ElfRelocationContext(AARCH64_ElfRelocationHandler handler, ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		super(handler, loadHelper, symbolMap);
	}

	@Override
	protected boolean requiresGotEntry(ElfRelocation r) {

		AARCH64_ElfRelocationType type = handler.getRelocationType(r.getType());
		if (type == null) {
			return false;
		}

		switch (type) {

			// NOTE: There are many more relocation types that require a GOT allocation.
			//@formatter:off
			
			//case R_AARCH64_P32_GOT_LD_PREL19:
			case R_AARCH64_P32_ADR_GOT_PAGE:
			case R_AARCH64_P32_LD32_GOT_LO12_NC:
			//case R_AARCH64_P32_LD32_GOTPAGE_LO14:
			case R_AARCH64_ADR_GOT_PAGE:
			case R_AARCH64_LD64_GOT_LO12_NC:
				return true;
				
			//@formatter:on
			default:
				return false;
		}
	}

}
