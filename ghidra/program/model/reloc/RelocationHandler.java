/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.model.reloc;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.task.TaskMonitor;

/**
 * NOTE:  ALL RelocationHandler CLASSES MUST END IN "RelocationHandler".  If not,
 * the ClassSearcher will not find them.
 *
 */
public interface RelocationHandler extends ExtensionPoint {

	/**
	 * Returns true if this relocation handler can relocate the
	 * given program. For example, an ELF program requires
	 * an ELF-specific relocation handler.
	 * @param program the program to relocation
	 * @return true if this relocation handler can relocate the given program
	 */
	public boolean canRelocate(Program program);

	/**
	 * 
	 * @param program
	 * @param newImageBase
	 * @param monitor
	 * @throws MemoryAccessException
	 */
	public void relocate(Program program, Address newImageBase, TaskMonitor monitor) throws MemoryAccessException;

	/**
	 * Relocates the memory block to the new start address.
	 * All relocations in the memory block will be fixed-up.
	 * @param program
	 * @param block
	 * @param newStartAddress
	 * @param monitor
	 * @throws MemoryAccessException
	 */
	public void relocate(Program program, MemoryBlock block, Address newStartAddress, TaskMonitor monitor) throws MemoryAccessException;


	public void performRelocation(Program program, Relocation relocation, TaskMonitor monitor) throws MemoryAccessException;
}
