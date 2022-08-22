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
package ghidra.trace.model.property;

import ghidra.program.model.address.AddressSpace;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceAddressSpace;

/**
 * A range map for storing properties in a trace
 *
 * <p>
 * Technically, each range is actually a "box" in two dimensions: time and space. Time is
 * represented by the span of snapshots covered, and space is represented by the range of addresses
 * covered. Currently, no effort is made to optimize coverage for entries having the same value. For
 * operations on entries, see {@link TracePropertyMapOperations}.
 * 
 * <p>
 * This interface is the root of a multi-space property map. For memory spaces, clients can
 * generally use the operations inherited on this interface. For register spaces, clients must use
 * {@link #getPropertyMapRegisterSpace(TraceThread, int, boolean)} or similar.
 *
 * @param <T> the type of values
 */
public interface TracePropertyMap<T> extends TracePropertyMapOperations<T> {
	/**
	 * Get the map space for the given address space
	 * 
	 * @param space the address space
	 * @param createIfAbsent true to create the map space if it doesn't already exist
	 * @return the space, or null
	 */
	TracePropertyMapSpace<T> getPropertyMapSpace(AddressSpace space, boolean createIfAbsent);

	/**
	 * Get the map space for the registers of a given thread and frame
	 * 
	 * @param thread the thread
	 * @param frameLevel the frame level, 0 being the innermost
	 * @param createIfAbsent true to create the map space if it doesn't already exist
	 * @return the space, or null
	 */
	TracePropertyMapRegisterSpace<T> getPropertyMapRegisterSpace(TraceThread thread, int frameLevel,
			boolean createIfAbsent);

	/**
	 * Get the map space for the registers of a given frame (which knows its thread)
	 * 
	 * @param frame the frame
	 * @param createIfAbsent true to create the map space if it doesn't already exist
	 * @return the space, or null
	 */
	default TracePropertyMapRegisterSpace<T> getPropertyMapRegisterSpace(TraceStackFrame frame,
			boolean createIfAbsent) {
		return getPropertyMapRegisterSpace(frame.getStack().getThread(), frame.getLevel(),
			createIfAbsent);
	}

	/**
	 * Get the map space for the given trace space
	 * 
	 * @param traceSpace the trace space, giving the memory space or thread/frame register space
	 * @param createIfAbsent true to create the map space if it doesn't already exist
	 * @return the space, or null
	 */
	default TracePropertyMapSpace<T> getPropertyMapSpace(TraceAddressSpace traceSpace,
			boolean createIfAbsent) {
		if (traceSpace.getAddressSpace().isRegisterSpace()) {
			return getPropertyMapRegisterSpace(traceSpace.getThread(), traceSpace.getFrameLevel(),
				createIfAbsent);
		}
		return getPropertyMapSpace(traceSpace.getAddressSpace(), createIfAbsent);
	}

	/**
	 * Delete this property and remove all of its maps
	 * 
	 * <p>
	 * The property can be re-created with the same or different value type.
	 */
	void delete();
}
