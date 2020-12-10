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
package ghidra.trace.model.memory;

import ghidra.program.model.address.AddressSpace;
import ghidra.trace.model.listing.TraceCodeManager;
import ghidra.trace.model.listing.TraceCodeSpace;

/**
 * A portion of the memory manager bound to a particular address space
 * 
 * <p>
 * For most memory operations, the methods on {@link TraceMemoryManager} are sufficient, as they
 * will automatically obtain the appropriate {@link TraceMemorySpace} for the address space of the
 * given address or range. If many operations on the same space are anticipated, it may be slightly
 * faster to bind to the space once and then perform all the operations. It is also necessary to
 * bind when operating on (per-thread) register spaces
 */
public interface TraceMemorySpace extends TraceMemoryOperations {
	/**
	 * Get the address space
	 * 
	 * @return the address space
	 */
	AddressSpace getAddressSpace();

	/**
	 * Get the code space for this memory space
	 * 
	 * <p>
	 * This is a convenience for {@link TraceCodeManager#getCodeSpace(AddressSpace, boolean) on this
	 * same address space.
	 * 
	 * @return the code space
	 */
	TraceCodeSpace getCodeSpace(boolean createIfAbsent);
}
