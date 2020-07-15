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

import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.app.util.bin.format.elf.ElfRelocationTable;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

class PIC30_ElfRelocationContext extends ElfRelocationContext {
	
	protected PIC30_ElfRelocationContext(ElfRelocationHandler handler, ElfLoadHelper loadHelper,
			ElfRelocationTable relocationTable, Map<ElfSymbol, Address> symbolMap) {
		super(handler, loadHelper, relocationTable, symbolMap);
	}
	
	private boolean isDebugSection(AddressSpace overlaySpace) {
		String name = overlaySpace.getName();
		return name.startsWith(".debug_") || ".comment".equals(name);
	}

	@Override
	public Address getRelocationAddress(Address baseAddress, long relocOffset) {
		if (!baseAddress.isLoadedMemoryAddress() && isDebugSection(baseAddress.getAddressSpace())) {
			relocOffset = relocOffset >> 1;
		}
		return baseAddress.addWrap(relocOffset);
	}

}
