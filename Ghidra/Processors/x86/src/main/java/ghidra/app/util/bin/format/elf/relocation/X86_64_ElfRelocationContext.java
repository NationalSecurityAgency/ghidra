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
 * <code>X86_64_ElfRelocationContext</code> provides ability to generate a
 * Global Offset Table (GOT) to facilitate GOT related relocations encountered within 
 * object modules.
 */
class X86_64_ElfRelocationContext extends ElfGotRelocationContext<X86_64_ElfRelocationHandler> {

	X86_64_ElfRelocationContext(X86_64_ElfRelocationHandler handler, ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		super(handler, loadHelper, symbolMap);
	}

	@Override
	protected boolean requiresGotEntry(ElfRelocation r) {

		X86_64_ElfRelocationType type = handler.getRelocationType(r.getType());
		if (type == null) {
			return false;
		}

		switch (type) {
			case R_X86_64_GOTPCREL:
//			case R_X86_64_GOTOFF64:
//			case R_X86_64_GOTPC32:
//			case R_X86_64_GOT64:
			case R_X86_64_GOTPCREL64:
//			case R_X86_64_GOTPC64:
				return true;
			case R_X86_64_GOTPCRELX:
			case R_X86_64_REX_GOTPCRELX:
				// NOTE: Relocation may not actually require GOT entry in which case %got 
				// may be over-allocated, but is required in some cases.
				return true;
			default:
				return false;
		}
	}

}
