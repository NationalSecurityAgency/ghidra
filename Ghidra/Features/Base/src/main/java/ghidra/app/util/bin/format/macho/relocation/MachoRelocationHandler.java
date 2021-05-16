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

import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.RelocationInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.NotFoundException;

/**
 * An abstract class used to perform Mach-O relocations.  Classes should extend this class to
 * provide relocations in a machine/processor specific way.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-7195.81.3/EXTERNAL_HEADERS/mach-o/reloc.h.auto.html">mach-o/reloc.h</a> 
 */
abstract public class MachoRelocationHandler implements ExtensionPoint {

	/**
	 * Checks to see whether or not an instance of this Mach-O relocation handler can handle 
	 * relocating the Mach-O defined by the provided file header
	 * 
	 * @param header The header associated with the Mach-O to relocate
	 * @return True if this relocation handler can do the relocation; otherwise, false
	 */
	abstract public boolean canRelocate(MachHeader header);

	/**
	 * Checks to see if the given relocation is a "paired" relocation.  A paired relocation has a 
	 * certain expectation from the relocation that follows it.
	 * 
	 * @param relocation The relocation to check
	 * @return True if the given relocation is a "paired" relocation; otherwise, false
	 */
	abstract public boolean isPairedRelocation(RelocationInfo relocation);

	/**
	 * Performs a relocation

	 * @param relocation The relocation to perform
	 * @throws MemoryAccessException If there is a problem accessing memory during the relocation
	 * @throws NotFoundException If this handler didn't find a way to perform the relocation
	 */
	abstract public void relocate(MachoRelocation relocation)
			throws MemoryAccessException, NotFoundException;

	/**
	 * Reads bytes at the given address.  The size of the read is determined by the length of the 
	 * relocation info.
	 * 
	 * @param relocation The relocation to read
	 * @return The read bytes
	 * @throws MemoryAccessException If there is a problem accessing memory during the read
	 */
	public static long read(MachoRelocation relocation)
			throws MemoryAccessException {
		Memory mem = relocation.getProgram().getMemory();
		int len = relocation.getRelocationInfo().getLength();
		Address addr = relocation.getRelocationAddress();
		if (len == 3) {
			return mem.getLong(addr);
		}
		if (len == 2) {
			return mem.getInt(addr);
		}
		if (len == 1) {
			return mem.getShort(addr);
		}
		return mem.getByte(addr);
	}

	/**
	 * Writes bytes at the given address.  The size of the write is determined by the length of the 
	 * relocation info.
	 * 
	 * @param relocation The relocation to write
	 * @param value The value to write
	 * @throws MemoryAccessException If there is a problem accessing memory during the write
	 */
	public static void write(MachoRelocation relocation, long value) throws MemoryAccessException {
		Memory mem = relocation.getProgram().getMemory();
		int len = relocation.getRelocationInfo().getLength();
		Address addr = relocation.getRelocationAddress();
		if (len == 3) {
			mem.setLong(addr, value);
		}
		else if (len == 2) {
			mem.setInt(addr, (int) value);
		}
		else if (len == 1) {
			mem.setShort(addr, (short) value);
		}
		else {
			mem.setByte(addr, (byte) value);
		}
	}
}
