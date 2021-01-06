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
package ghidra.trace.model.listing;

import ghidra.lifecycle.Experimental;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceAddressSpace;

public interface TraceCodeManager extends TraceCodeOperations {

	/**
	 * Get the code space for the memory or registers of the given trace address space
	 * 
	 * @param space the trace address space (thread, stack frame, address space)
	 * @param createIfAbsent true to create the space if it's not already present
	 * @return the space, of {@code null} if absent and not created
	 */
	TraceCodeSpace getCodeSpace(TraceAddressSpace space, boolean createIfAbsent);

	/**
	 * Get the code space for the memory of the given address space
	 * 
	 * @param space the address space
	 * @param createIfAbsent true to create the space if it's not already present
	 * @return the space, of {@code null} if absent and not created
	 */
	TraceCodeSpace getCodeSpace(AddressSpace space, boolean createIfAbsent);

	/**
	 * Get the code space for registers of the given thread's innermost frame
	 * 
	 * @param thread the thread
	 * @param createIfAbsent true to create the space if it's not already present
	 * @return the space, of {@code null} if absent and not created
	 */
	TraceCodeRegisterSpace getCodeRegisterSpace(TraceThread thread, boolean createIfAbsent);

	/**
	 * Get the code space for registers of the given thread and frame
	 * 
	 * @param thread the thread
	 * @param frameLevel the frame (0 for innermost)
	 * @param createIfAbsent true to create the space if it's not already present
	 * @return the space, of {@code null} if absent and not created
	 */
	TraceCodeRegisterSpace getCodeRegisterSpace(TraceThread thread, int frameLevel,
			boolean createIfAbsent);

	/**
	 * Get the code space for registers of the given stack frame
	 * 
	 * <p>
	 * Note this is simply a shortcut for {@link #getCodeRegisterSpace(TraceThread, int, boolean)},
	 * and does not in any way bind the space to the lifetime of the given frame. Nor, if the frame
	 * is moved, will this space move with it.
	 * 
	 * @param frame the frame whose space to get
	 * @param createIfAbsent true to create the space if it's not already present
	 * @return the space, or {@code null} if absent and not created
	 */
	TraceCodeRegisterSpace getCodeRegisterSpace(TraceStackFrame frame, boolean createIfAbsent);

	/**
	 * Query for the address set where code units have been added between the two given snaps
	 * 
	 * @param from the beginning snap
	 * @param to the ending snap
	 * @return the view of addresses where units have been added
	 */
	@Experimental
	AddressSetView getCodeAdded(long from, long to);

	/**
	 * Query for the address set where code units have been removed between the two given snaps
	 * 
	 * @param from the beginning snap
	 * @param to the ending snap
	 * @return the view of addresses where units have been removed
	 */
	@Experimental
	AddressSetView getCodeRemoved(long from, long to);
}
