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

import static ghidra.app.util.bin.format.macho.relocation.X86_32_MachoRelocationConstants.*;

import ghidra.app.util.bin.format.macho.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.NotFoundException;

/** 
 * A {@link MachoRelocationHandler} for x86 32-bit
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-7195.81.3/EXTERNAL_HEADERS/mach-o/reloc.h.auto.html">mach-o/reloc.h</a> 
 */
public class X86_32_MachoRelocationHandler extends MachoRelocationHandler {

	@Override
	public boolean canRelocate(MachHeader header) {
		return header.getCpuType() == CpuTypes.CPU_TYPE_X86;
	}

	@Override
	public boolean isPairedRelocation(RelocationInfo relocation) {
		return relocation.getType() == GENERIC_RELOC_SECTDIFF ||
			relocation.getType() == GENERIC_RELOC_LOCAL_SECTDIFF;
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

		switch (relocationInfo.getType()) {
			case GENERIC_RELOC_VANILLA:
				if (relocationInfo.isPcRelocated()) {
					write(relocation, targetAddr.subtract(relocAddr) - 4);
				}
				else {
					write(relocation, targetAddr.getOffset());
				}
				break;
				
			case GENERIC_RELOC_PAIR:           // should never see on its own here
			case GENERIC_RELOC_SECTDIFF:       // relocation not required (scattered)
			case GENERIC_RELOC_PB_LA_PTR:      // not seen yet
			case GENERIC_RELOC_LOCAL_SECTDIFF: // relocation not required (scattered)
			case GENERIC_RELOC_TLV:            // not seen yet
			default:
				throw new NotFoundException("Unimplemented relocation");
		}
	}
}
