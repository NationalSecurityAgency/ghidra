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
package ghidra.dbg.target;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.program.model.address.Address;

/**
 * The memory model of a target object
 * 
 * <p>
 * This interface provides methods for reading and writing target memory. It should use addresses
 * produced by the provided address factory. The convention for modeling valid addresses is to have
 * children supporting {@link TargetMemoryRegion}. If no such children exist, then the client should
 * assume no address is valid. Thus, for the client to confidently access any memory, at least one
 * child region must exist. It may present the memory's entire address space in a single region.
 * 
 * <p>
 * TODO: Decide convention: should a single region appear in multiple locations? If it does, does it
 * imply that region's contents are common to all memories possessing it? Or, should contents be
 * distinguished by the memory objects? I'm leaning toward the latter. Duplicate locations for
 * regions may just be an efficiency bit, if used at all. This decision is primarily because, at the
 * moment, read and write belong to the memory interface, not the region.
 */
@DebuggerTargetObjectIface("Memory")
public interface TargetMemory extends TargetObject {

	/**
	 * Read memory at the given address
	 * 
	 * <p>
	 * If the target architecture is not a byte-per-address, then the implementation should
	 * interpret each unit in bytes using the target space's native byte order.
	 * 
	 * <p>
	 * TODO: This circumstance has not been well-tested, as non-x86 architectures are left for
	 * future implementation.
	 * 
	 * @param address the address to start reading at
	 * @param length the number of bytes to read
	 * @return a future which completes with the read data
	 */
	public CompletableFuture<byte[]> readMemory(Address address, int length);

	/**
	 * Write memory at the given address
	 * 
	 * <p>
	 * If the target architecture is not a byte-per-address, then the implementation should
	 * interpret each unit in bytes using the memory space's native byte order.
	 * 
	 * <p>
	 * TODO: This circumstance has not been well-tested, as non-x86 architectures are left for
	 * future implementation.
	 * 
	 * @param address the address to start writing at
	 * @param data the data to write
	 * @return a future which completes upon successfully writing
	 */
	public CompletableFuture<Void> writeMemory(Address address, byte[] data);

	/**
	 * Get the regions of valid addresses
	 * 
	 * <p>
	 * This is a convenience, exactly equivalent to getting all children supporting the
	 * {@link TargetMemoryRegion} interface.
	 * 
	 * @return the collection of child regions
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public default CompletableFuture<? extends Map<String, ? extends TargetMemoryRegion>> getRegions() {
		return fetchChildrenSupporting((Class) TargetMemoryRegion.class);
	}
}
