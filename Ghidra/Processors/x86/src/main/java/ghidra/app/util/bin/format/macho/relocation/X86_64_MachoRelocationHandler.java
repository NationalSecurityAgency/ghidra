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
package ghidra.app.util.bin.format.macho.relocation;

import static ghidra.app.util.bin.format.macho.relocation.X86_64_MachoRelocationConstants.*;

import ghidra.app.util.bin.format.macho.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.NotFoundException;

/** 
 * A {@link MachoRelocationHandler} for x86 64-bit
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-7195.81.3/EXTERNAL_HEADERS/mach-o/x86_64/reloc.h.auto.html">mach-o/x86_64/reloc.h</a> 
 */
public class X86_64_MachoRelocationHandler extends MachoRelocationHandler {

	@Override
	public boolean canRelocate(MachHeader header) {
		return header.getCpuType() == CpuTypes.CPU_TYPE_X86_64;
	}

	@Override
	public boolean isPairedRelocation(RelocationInfo relocation) {
		return relocation.getType() == X86_64_RELOC_SUBTRACTOR;
	}

	@Override
	public void relocate(MachoRelocation relocation)
			throws MemoryAccessException, NotFoundException {

		if (!relocation.requiresRelocation()) {
			return;
		}
		
		RelocationInfo relocationInfo = relocation.getRelocationInfo();		
		Address relocAddr = relocation.getRelocationAddress();
		Address targetAddr = relocation.getTargetAddress();
		long addend = read(relocation);

		switch (relocationInfo.getType()) {
			case X86_64_RELOC_UNSIGNED:
				write(relocation, targetAddr.add(addend).getOffset());
				break;
			case X86_64_RELOC_SIGNED:
			case X86_64_RELOC_BRANCH:
			case X86_64_RELOC_GOT_LOAD:
			case X86_64_RELOC_GOT:
			case X86_64_RELOC_SIGNED_1: // addend should already be -1
			case X86_64_RELOC_SIGNED_2: // addend should already be -2
			case X86_64_RELOC_SIGNED_4: // addend should already be -4
				write(relocation, targetAddr.add(addend).subtract(relocAddr) - 4);
				break;
			case X86_64_RELOC_SUBTRACTOR:
				Address targetAddrExtra = relocation.getTargetAddressExtra();
				if (addend > 0) {
					write(relocation, targetAddrExtra.add(addend).subtract(targetAddr));
				}
				else {
					write(relocation, targetAddr.add(addend).subtract(targetAddrExtra));
				}
				break;
				
			case X86_64_RELOC_TLV:      // not seen yet
			default:
				throw new NotFoundException("Unimplemented relocation");
		}
	}
}
