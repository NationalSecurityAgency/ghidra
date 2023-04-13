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

import static ghidra.app.util.bin.format.macho.relocation.PowerPC_MachoRelocationConstants.*;

import ghidra.app.util.bin.format.RelocationException;
import ghidra.app.util.bin.format.macho.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.RelocationResult;

/** 
 * A {@link MachoRelocationHandler} for PowerPC
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-1504.9.37/EXTERNAL_HEADERS/mach-o/ppc/reloc.h.auto.html">mach-o/ppc/reloc.h</a> 
 */
public class PowerPC_MachoRelocationHandler extends MachoRelocationHandler {

	@Override
	public boolean canRelocate(MachHeader header) {
		return header.getCpuType() == CpuTypes.CPU_TYPE_POWERPC;
	}

	@Override
	public boolean isPairedRelocation(RelocationInfo relocation) {
		return switch (relocation.getType()) {
			case PPC_RELOC_HI16:
			case PPC_RELOC_LO16:
			case PPC_RELOC_HA16:
			case PPC_RELOC_LO14:
			case PPC_RELOC_SECTDIFF:
			case PPC_RELOC_HI16_SECTDIFF:
			case PPC_RELOC_LO16_SECTDIFF:
			case PPC_RELOC_HA16_SECTDIFF:
			case PPC_RELOC_JBSR:
			case PPC_RELOC_LO14_SECTDIFF:
			case PPC_RELOC_LOCAL_SECTDIFF: {
				yield true;
			}
			default:
				yield false;
		};
	}
	
	@Override
	public RelocationResult relocate(MachoRelocation relocation)
			throws MemoryAccessException, RelocationException {
		
		if (!relocation.requiresRelocation()) {
			return RelocationResult.SKIPPED;
		}
		
		RelocationInfo relocationInfo = relocation.getRelocationInfo();

		switch (relocationInfo.getType()) {
			case PPC_RELOC_VANILLA:        // not seen yet
			case PPC_RELOC_PAIR:           // not seen yet
			case PPC_RELOC_BR14:           // not seen yet
			case PPC_RELOC_BR24:           // not seen yet
			case PPC_RELOC_HI16:           // not seen yet
			case PPC_RELOC_LO16:           // not seen yet 
			case PPC_RELOC_HA16:           // not seen yet
			case PPC_RELOC_LO14:           // not seen yet
			case PPC_RELOC_SECTDIFF:       // not seen yet
			case PPC_RELOC_PB_LA_PTR:      // not seen yet
			case PPC_RELOC_HI16_SECTDIFF:  // not seen yet
			case PPC_RELOC_LO16_SECTDIFF:  // not seen yet
			case PPC_RELOC_HA16_SECTDIFF:  // not seen yet
			case PPC_RELOC_JBSR:           // not seen yet
			case PPC_RELOC_LO14_SECTDIFF:  // not seen yet
			case PPC_RELOC_LOCAL_SECTDIFF: // not seen yet
			default:
				return RelocationResult.UNSUPPORTED;
		}
	}
}
