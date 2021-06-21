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

import java.util.Collection;
import java.util.Map.Entry;

import ghidra.program.model.address.AddressSpace;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;

/**
 * A store of memory observations over time in a trace
 * 
 * <p>
 * The manager is not bound to any particular address space and may be used to access information
 * about any memory address. For register spaces, you must use
 * {@link #getMemoryRegisterSpace(TraceThread, int, boolean)}.
 */
public interface TraceMemoryManager extends TraceMemoryOperations {

	/**
	 * Obtain a memory space bound to a particular address space
	 * 
	 * @param space the address space
	 * @param createIfAbsent true to create the space if it's not already present
	 * @return the space, or {@code null} if absent and not created
	 */
	TraceMemorySpace getMemorySpace(AddressSpace space, boolean createIfAbsent);

	/**
	 * Obtain a "memory" space bound to the register address space for a given thread and stack
	 * frame
	 * 
	 * @param thread the given thread
	 * @param frame the "level" of the given stack frame. 0 is the innermost frame.
	 * @param createIfAbsent true to create the space if it's not already present
	 * @return the space, or {@code null} if absent and not created
	 */
	TraceMemoryRegisterSpace getMemoryRegisterSpace(TraceThread thread, int frame,
			boolean createIfAbsent);

	/**
	 * Obtain a "memory" space bound to the register address space for frame 0 of a given thread
	 * 
	 * @see #getMemoryRegisterSpace(TraceThread, int, boolean)
	 */
	TraceMemoryRegisterSpace getMemoryRegisterSpace(TraceThread thread, boolean createIfAbsent);

	/**
	 * Obtain a "memory" space bound to the register address space for a stack frame
	 * 
	 * <p>
	 * Note this is simply a convenience, and does not in any way bind the space to the lifespan of
	 * the given frame. Nor, if the frame is moved, will this space move with it.
	 * 
	 * @see #getMemoryRegisterSpace(TraceThread, int, boolean)
	 */
	TraceMemoryRegisterSpace getMemoryRegisterSpace(TraceStackFrame frame, boolean createIfAbsent);

	/**
	 * Collect all the regions added between two given snaps
	 * 
	 * @param from the earlier snap
	 * @param to the later snap
	 * @return the collection of regions added
	 */
	Collection<? extends TraceMemoryRegion> getRegionsAdded(long from, long to);

	/**
	 * Collect all the regions removed between two given snaps
	 * 
	 * @param from the earlier snap
	 * @param to the later snap
	 * @return the collection of regions removed
	 */
	Collection<? extends TraceMemoryRegion> getRegionsRemoved(long from, long to);

	/**
	 * Collect all the state changes between two given snaps
	 * 
	 * @param from the earlier snap
	 * @param to the later snap
	 * @return the collection of state changes
	 */
	Collection<Entry<TraceAddressSnapRange, TraceMemoryState>> getStateChanges(long from, long to);
}
