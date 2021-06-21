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

import static ghidra.app.util.bin.format.macho.relocation.AARCH64_MachoRelocationConstants.*;

import ghidra.app.util.bin.format.macho.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Conv;
import ghidra.util.exception.NotFoundException;

/** 
 * A {@link MachoRelocationHandler} for AARCH64
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-7195.81.3/EXTERNAL_HEADERS/mach-o/arm64/reloc.h.auto.html">mach-o/arm64/reloc.h</a> 
 */
public class AARCH64_MachoRelocationHandler extends MachoRelocationHandler {

	@Override
	public boolean canRelocate(MachHeader header) {
		return header.getCpuType() == CpuTypes.CPU_TYPE_ARM_64;
	}

	@Override
	public boolean isPairedRelocation(RelocationInfo relocation) {
		return relocation.getType() == ARM64_RELOC_SUBTRACTOR ||
			relocation.getType() == ARM64_RELOC_ADDEND;
	}
	
	@Override
	public void relocate(MachoRelocation relocation)
			throws MemoryAccessException, NotFoundException {
		
		if (!relocation.requiresRelocation()) {
			return;
		}
		
		RelocationInfo relocationInfo = relocation.getRelocationInfo();
		Address relocAddr = relocation.getRelocationAddress();
		Address targetAddr;
		long addendFromReloc;
		if (relocationInfo.getType() == ARM64_RELOC_ADDEND) {
			// ARM64_RELOC_ADDEND is a paired relocation, but it's a bit unique because it doesn't
			// define its own relocation target...simply an addend value to be applied to the 2nd
			// part of the relocation.  We'll just save off the addend value and proceed as if the
			// "extra" part of the relocation pair is a normal unpaired relocation.  
			targetAddr = relocation.getTargetAddressExtra();
			addendFromReloc = relocationInfo.getValue();
			relocationInfo = relocation.getRelocationInfoExtra();
		}
		else {
			targetAddr = relocation.getTargetAddress();
			addendFromReloc = 0;
			
		}
		long orig = read(relocation);

		switch (relocationInfo.getType()) {
			case ARM64_RELOC_UNSIGNED:
			case ARM64_RELOC_POINTER_TO_GOT: {
				long addend = orig;
				long value = targetAddr.getOffset() + addend;
				write(relocation, value);
				break;
			}
			case ARM64_RELOC_SUBTRACTOR: {
				Address targetAddrExtra = relocation.getTargetAddressExtra();
				if (orig > 0) {
					write(relocation, targetAddrExtra.add(orig).subtract(targetAddr));
				}
				else {
					write(relocation, targetAddr.add(orig).subtract(targetAddrExtra));
				}
				break;
			}
			case ARM64_RELOC_BRANCH26: {
				long addend = orig & 0x3ffffff;
				long value = (targetAddr.subtract(relocAddr) >> 2) + addend;
				long instr = orig | (value & 0x3ffffff);
				write(relocation, instr);
				break;
			}
			case ARM64_RELOC_PAGE21:
			case ARM64_RELOC_GOT_LOAD_PAGE21: {
				// ADRP
				long immlo = (orig >> 29) & 0x3;
				long immhi = (orig >> 5) & 0x7ffff;
				long addend = ((immhi << 2) | immlo) << 12;
				addend += addendFromReloc;
				long pageTarget = PG(targetAddr.getOffset() + addend);
				long pageReloc = PG(relocAddr.getOffset());
				long value = ((pageTarget - pageReloc) >> 12) & 0x1fffff;
				long instr =
					(orig & 0x9f00001f) | ((value << 3) & 0x7ffffe0) | ((value & 0x3) << 29);
				write(relocation, instr);
				break;
			}
			case ARM64_RELOC_PAGEOFF12:
			case ARM64_RELOC_GOT_LOAD_PAGEOFF12: {
				long instr;
				long addend = addendFromReloc;
				if ((orig & 0x08000000) > 0) {
					// LDR/STR
					long size = (orig >> 30) & 0x3;
					addend += (orig >> 10) & 0xfff;
					long value = ((targetAddr.getOffset() + addend) & 0xfff) >> size;
					instr = orig | (value << 10);
				}
				else {
					// ADD
					addend += (orig >> 10) & 0xfff;
					long value = (targetAddr.getOffset() + addend) & 0xfff;
					instr = orig | (value << 10);
				}
				write(relocation, instr);
				break;
			}
			case ARM64_RELOC_AUTHENTICATED_POINTER: {
				long addend = orig & Conv.INT_MASK;
				long value = targetAddr.getOffset() + addend;
				write(relocation, value);
				break;
			}
			
			case ARM64_RELOC_TLVP_LOAD_PAGE21:    // not seen yet
			case ARM64_RELOC_TLVP_LOAD_PAGEOFF12: // not seen yet
			case ARM64_RELOC_ADDEND:              // should never see on its own here
			default:
				throw new NotFoundException("Unimplemented relocation");
		}
	}
	
	/**
	 * Returns the page address of the given address (assumes 4KB page)
	 * 
	 * @param addr The address to get the page of
	 * @return The page address of the given address
	 */
	private long PG(long addr) {
		return addr & (~0xfff);
	}
}
