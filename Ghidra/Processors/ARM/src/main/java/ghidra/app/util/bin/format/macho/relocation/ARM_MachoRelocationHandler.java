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

import static ghidra.app.util.bin.format.macho.relocation.ARM_MachoRelocationConstants.*;

import ghidra.app.util.bin.format.macho.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.NotFoundException;

/** 
 * A {@link MachoRelocationHandler} for ARM
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-7195.81.3/EXTERNAL_HEADERS/mach-o/arm/reloc.h.auto.html">mach-o/arm/reloc.h</a> 
 */
public class ARM_MachoRelocationHandler extends MachoRelocationHandler {

	@Override
	public boolean canRelocate(MachHeader header) {
		return header.getCpuType() == CpuTypes.CPU_TYPE_ARM;
	}

	@Override
	public boolean isPairedRelocation(RelocationInfo relocation) {
		return relocation.getType() == ARM_RELOC_SECTDIFF ||
			relocation.getType() == ARM_RELOC_LOCAL_SECTDIFF ||
			relocation.getType() == ARM_RELOC_HALF ||
			relocation.getType() == ARM_RELOC_HALF_SECTDIFF;
	}
	
	@Override
	public void relocate(MachoRelocation relocation)
			throws MemoryAccessException, NotFoundException {
		
		if (!relocation.requiresRelocation()) {
			return;
		}
		
		RelocationInfo relocationInfo = relocation.getRelocationInfo();
		Address targetAddr = relocation.getTargetAddress();
		long orig = read(relocation);

		switch (relocationInfo.getType()) {
			case ARM_RELOC_VANILLA:
				if (!relocationInfo.isPcRelocated()) {
					write(relocation, targetAddr.getOffset());
				}
				else {
					throw new NotFoundException("Unimplemented relocation");
				}
				break;
			case ARM_THUMB_RELOC_BR22: {
				// BL and BLX
				boolean blx = (orig & 0xd000f800) == 0xc000f000;
				long s = (orig >> 10) & 0x1;
				long j1 = (orig >> 29) & 0x1;
				long j2 = (orig >> 27) & 0x1;
				long i1 = ~(j1 ^ s) & 0x1;
				long i2 = ~(j2 ^ s) & 0x1;
				long imm10 = orig & 0x3ff;
				long imm11 = (orig >> 16) & 0x7ff;
				long addend = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
				addend |= s == 1 ? 0xfe000000 : 0; // sign extend
				addend &= blx ? ~0x3 : ~0; // 4-byte align BLX
				long value = targetAddr.getOffset() + addend;
				s = (value >> 24) & 0x1;
				i1 = (value >> 23) & 0x1;
				i2 = (value >> 22) & 0x1;
				j1 = ~(i1 ^ s) & 0x1;
				j2 = ~(i2 ^ s) & 0x1;
				imm10 = (value >> 12) & 0x3ff;
				imm11 = (value >> 1) & 0x7ff;
				long instr = orig & (blx ? 0xc000f800 : 0xd000f800);
				instr |= (j1 << 29) | (j2 << 27) | (imm11 << 16) | (s << 10) | imm10;
				write(relocation, instr);
				break;
			}
			
			case ARM_RELOC_PAIR:           // should never see on its own here
			case ARM_RELOC_SECTDIFF:       // relocation not required (scattered)
			case ARM_RELOC_LOCAL_SECTDIFF: // relocation not required (scattered)
			case ARM_RELOC_PB_LA_PTR:      // not seen yet
			case ARM_RELOC_BR24:           // not seen yet
			case ARM_THUMB_32BIT_BRANCH:   // not seen yet
			case ARM_RELOC_HALF:           // relocation not required (scattered)
			case ARM_RELOC_HALF_SECTDIFF:  // relocation not required (scattered)
			default:
				throw new NotFoundException("Unimplemented relocation");
		}
	}
}
