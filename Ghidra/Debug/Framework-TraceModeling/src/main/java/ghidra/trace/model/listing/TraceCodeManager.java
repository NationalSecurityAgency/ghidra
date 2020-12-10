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

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;

public interface TraceCodeManager extends TraceCodeOperations {
	/** Operand index for data. Will always be zero */
	int DATA_OP_INDEX = 0;

	TraceCodeSpace getCodeSpace(AddressSpace space, boolean createIfAbsent);

	TraceCodeRegisterSpace getCodeRegisterSpace(TraceThread thread, boolean createIfAbsent);

	TraceCodeRegisterSpace getCodeRegisterSpace(TraceThread thread, int frameLevel,
			boolean createIfAbsent);

	/**
	 * Get the code space for registers of the given stack frame
	 * 
	 * Note this is simply a shortcut for {@link #getCodeRegisterSpace(TraceThread, int, boolean)},
	 * and does not in any way bind the space to the lifetime of the given frame. Nor, if the frame
	 * is moved, will this space move with it.
	 * 
	 * @param frame the frame whose space to get
	 * @param createIfAbsent true to create the space if it's not already present
	 * @return the space, or {@code null} if absent and not created
	 */
	TraceCodeRegisterSpace getCodeRegisterSpace(TraceStackFrame frame, boolean createIfAbsent);

	AddressSetView getCodeAdded(long from, long to);

	AddressSetView getCodeRemoved(long from, long to);

}
