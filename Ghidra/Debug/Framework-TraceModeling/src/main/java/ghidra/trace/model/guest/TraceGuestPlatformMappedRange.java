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
import ghidra.program.model.address.AddressRange;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A range of mapped memory from guest platform to host platform
 */
public interface TraceGuestPlatformMappedRange {
	/**
	 * Get the host platform
	 * 
	 * @return the host platform
	 */
	TracePlatform getHostPlatform();

	/**
	 * Get the address range in the host
	 * 
	 * @return the host range
	 */
	AddressRange getHostRange();

	/**
	 * Get the guest platform
	 * 
	 * @return the guest platform
	 */
	TraceGuestPlatform getGuestPlatform();

	/**
	 * Get the address range in the guest
	 * 
	 * @return the guest range
	 */
	AddressRange getGuestRange();

	/**
	 * Translate an address from host to guest, if in the host range
	 * 
	 * @param hostAddress the host address
	 * @return the guest address, or null
	 */
	Address mapHostToGuest(Address hostAddress);

	/**
	 * Translate an address range from host to guest, if wholly contained in the host range
	 * 
	 * @param hostRange the host range
	 * @return the guest range, or null
	 */
	AddressRange mapHostToGuest(AddressRange hostRange);

	/**
	 * Translate an address from guest to host, if in the guest range
	 * 
	 * @param guestAddress the guest address
	 * @return the host address, or null
	 */
	Address mapGuestToHost(Address guestAddress);

	/**
	 * Translate an address range from guest to host, if wholly contained in the guest range
	 * 
	 * @param guestRange the guest range
	 * @return the host range, or null
	 */
	AddressRange mapGuestToHost(AddressRange guestRange);

	/**
	 * Delete this mapping entry
	 * 
	 * @param monitor a monitor for cleaning up dependent objects, e.g., code units
	 * @throws CancelledException if the user cancels via the monitor
	 */
	void delete(TaskMonitor monitor) throws CancelledException;
}
