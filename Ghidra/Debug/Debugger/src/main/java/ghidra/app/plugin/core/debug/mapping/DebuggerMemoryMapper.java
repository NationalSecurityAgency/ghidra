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
package ghidra.app.plugin.core.debug.mapping;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;

public interface DebuggerMemoryMapper {
	/**
	 * Map the given address from the trace into the target process
	 * 
	 * @param traceAddr the address in the view's address space
	 * @return the "same address" in the target's address space
	 */
	Address traceToTarget(Address traceAddr);

	/**
	 * Map the given address range from the trace into the target process
	 * 
	 * @param traceRange the range in the view's address space
	 * @return the "same range" in the target's address space
	 */
	AddressRange traceToTarget(AddressRange traceRange);

	/**
	 * Map the given address from the target process into the trace
	 * 
	 * @param targetAddr the address in the target's address space
	 * @return the "same address" in the trace's address space
	 */
	Address targetToTrace(Address targetAddr);

	/**
	 * Map the given address range from the target process into the trace
	 * 
	 * @param targetRange the range in the target's address space
	 * @return the "same range" in the trace's address space
	 */
	AddressRange targetToTrace(AddressRange targetRange);
}
