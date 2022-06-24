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
package ghidra.trace.model.guest;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.trace.model.Trace;

public interface TracePlatform {
	/**
	 * Get the trace
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * Check if this is a guest platform
	 * 
	 * @return true for guest, false for host
	 */
	boolean isGuest();

	/**
	 * Check if this is the host platform
	 * 
	 * @return true for host, false for guest
	 */
	default boolean isHost() {
		return !isGuest();
	}

	/**
	 * Get the language of the guest platform
	 * 
	 * @return the language
	 */
	Language getLanguage();

	/**
	 * Get the address factory of the guest platform
	 * 
	 * @return the factory
	 */
	default AddressFactory getAddressFactory() {
		return getLanguage().getAddressFactory();
	}

	/**
	 * Get the compiler of the guest platform
	 * 
	 * @return the compiler spec
	 */
	CompilerSpec getCompilerSpec();

	/**
	 * Get the addresses in the host which are mapped to somewhere in the guest
	 * 
	 * @return the address set
	 */
	AddressSetView getHostAddressSet();

	/**
	 * Get the addresses in the guest which are mapped to somehere in the host
	 * 
	 * @return the address set
	 */
	AddressSetView getGuestAddressSet();

	/**
	 * Map an address from host to guest
	 * 
	 * @param hostAddress the host address
	 * @return the guest address
	 */
	Address mapHostToGuest(Address hostAddress);

	/**
	 * Map an address from guest to host
	 * 
	 * @param guestAddress the guest address
	 * @return the host address
	 */
	Address mapGuestToHost(Address guestAddress);

	/**
	 * Get a memory buffer, which presents the host bytes in the guest address space
	 * 
	 * <p>
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
	 * <p>
	 * Instructions which do not map are silently ignored. If concerned, the caller ought to examine
	 * the resulting instruction set and/or the resulting address set after it is added to the
	 * trace. A single instruction cannot span two mapped ranges, even if the comprised bytes are
	 * consecutive in the guest space. Mapping such an instruction back into the host space would
	 * cause the instruction to be split in the middle, which is not possible. Thus, such
	 * instructions are silently ignored.
	 * 
	 * @param set the instruction set in the guest space
	 * @return the instruction set in the host space
	 */
	InstructionSet mapGuestInstructionAddressesToHost(InstructionSet set);
}
