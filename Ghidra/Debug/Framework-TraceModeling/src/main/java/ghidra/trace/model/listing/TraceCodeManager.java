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

import com.google.common.collect.Range;

import ghidra.lifecycle.Experimental;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Listing;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceAddressSpace;

/**
 * The manager for trace code units, i.e., the equivalent of {@link Listing}
 *
 * <p>
 * This supports a "fluent" interface, which differs from {@link Listing}. For example, instead of
 * {@link Listing#getInstructionContaining(Address)}, a client would invoke {@link #instructions()}
 * then {@link TraceInstructionsView#getContaining(long, Address)}. Because traces include register
 * spaces, this chain could be preceded by {@link #getCodeSpace(AddressSpace, boolean)} or
 * {@link #getCodeRegisterSpace(TraceThread, int, boolean)}.
 * 
 * <p>
 * To create an instruction, see
 * {@link TraceInstructionsView#create(Range, Address, TracePlatform, InstructionPrototype, ProcessorContextView)}.
 * Since clients do not ordinarily have an {@link InstructionPrototype} in hand, the more common
 * method is to invoke the {@link Disassembler} on {@link Trace#getProgramView()}.
 * 
 * <p>
 * To create a data unit, see {@link TraceDefinedDataView#create(Range, Address, DataType, int)}.
 * The method chain to create a data unit in memory is {@link #definedData()} then
 * {@code create(...)}. The method chain to create a data unit on a register is
 * {@link #getCodeRegisterSpace(TraceThread, int, boolean)}, then
 * {@link TraceCodeSpace#definedData()}, then
 * {@link TraceDefinedDataView#create(Range, Register, DataType)}.
 */
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
	TraceCodeSpace getCodeRegisterSpace(TraceThread thread, boolean createIfAbsent);

	/**
	 * Get the code space for registers of the given thread and frame
	 * 
	 * @param thread the thread
	 * @param frameLevel the frame (0 for innermost)
	 * @param createIfAbsent true to create the space if it's not already present
	 * @return the space, of {@code null} if absent and not created
	 */
	TraceCodeSpace getCodeRegisterSpace(TraceThread thread, int frameLevel,
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
	TraceCodeSpace getCodeRegisterSpace(TraceStackFrame frame, boolean createIfAbsent);

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
