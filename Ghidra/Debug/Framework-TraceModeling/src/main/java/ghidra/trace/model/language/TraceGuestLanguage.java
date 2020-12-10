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
package ghidra.trace.model.language;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.InstructionSet;
import ghidra.program.model.lang.Language;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public interface TraceGuestLanguage {
	Language getLanguage();

	TraceGuestLanguageMappedRange addMappedRange(Address hostStart, Address guestStart, long length)
			throws AddressOverflowException;

	AddressSetView getHostAddressSet();

	AddressSetView getGuestAddressSet();

	Address mapHostToGuest(Address hostAddress);

	Address mapGuestToHost(Address guestAddress);

	/**
	 * Get a memory buffer which presents the host bytes in the guest address space
	 * 
	 * This, with pseudo-disassembly, is the primary mechanism for adding instructions in the guest
	 * language.
	 * 
	 * @param snap the snap, up to which the most recent memory changes are presented
	 * @param guestAddress the starting address in the guest space
	 * @return the mapped memory buffer
	 */
	MemBuffer getMappedMemBuffer(long snap, Address guestAddress);

	/**
	 * Copy the given instruction set, but with addresses mapped from the guest space to the host
	 * space
	 * 
	 * Instructions which do not mapped are silently ignored. If concerned, the caller ought to
	 * examine the resulting instruction set and/or the resulting address set after it is added to
	 * the trace. A single instruction cannot span two mapped ranges, even if the comprised bytes
	 * are consecutive in the guest space. Mapping such an instruction back into the host space
	 * would cause the instruction to be split in the middle, which is not possible. Thus, such
	 * instructions are silently ignored.
	 * 
	 * @param set the instruction set in the guest space
	 * @return the instruction set in the host space
	 */
	InstructionSet mapGuestInstructionAddressesToHost(InstructionSet set);

	/**
	 * Remove the mapped language, including all code units of the language
	 */
	void delete(TaskMonitor monitor) throws CancelledException;
}
