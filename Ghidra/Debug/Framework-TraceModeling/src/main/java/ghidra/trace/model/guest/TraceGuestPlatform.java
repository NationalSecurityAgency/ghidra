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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A guest platform in a trace
 */
public interface TraceGuestPlatform extends TracePlatform {

	/**
	 * Add an address mapping from host to guest
	 * 
	 * @param hostStart the starting host address (mapped to guestStart)
	 * @param guestStart the starting guest address (mapped to hostStart)
	 * @param length the length of the range to map
	 * @return the mapped range
	 * @throws AddressOverflowException if length is too long for either start
	 */
	TraceGuestPlatformMappedRange addMappedRange(Address hostStart, Address guestStart, long length)
			throws AddressOverflowException;

	/**
	 * Add an address mapping from host register space to guest register space
	 * 
	 * <p>
	 * In guest space, the mapping is placed at 0 and has length large enough to accommodate all
	 * registers in the guest language. In host space, the mapping is placed after every other
	 * register mapping for every platform.
	 * 
	 * @return the mapped range
	 * @throws AddressOverflowException if host register space was exhausted
	 */
	TraceGuestPlatformMappedRange addMappedRegisterRange() throws AddressOverflowException;

	/**
	 * Remove the mapped language, including all code units of the language
	 */
	void delete(TaskMonitor monitor) throws CancelledException;
}
