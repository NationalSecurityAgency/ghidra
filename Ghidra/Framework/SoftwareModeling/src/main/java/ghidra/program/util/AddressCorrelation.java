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
package ghidra.program.util;

import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Interface representing the address mapping for any means of correlating addresses
 * between a source program and a destination program.
 *
 */
public interface AddressCorrelation {

	/**
	 * Returns the AddressRange of a set of addresses in the destination
	 * program that correlates to corresponding range in the source program.
	 *
	 * @param sourceAddress the source program address
	 * @param monitor the task monitor
	 * @return the destination program address range, or null if there is not address range mapped
	 * @throws CancelledException if cancelled
	 */
	public AddressCorrelationRange getCorrelatedDestinationRange(Address sourceAddress,
			TaskMonitor monitor) throws CancelledException;

	/**
	 * This method is no longer part of the API.  Leaving a default implementation to reduce 
	 * breaking clients.
	 * @return the simple class name of the implementing class
	 */
	public default String getName() {
		return getClass().getSimpleName();
	}
}
