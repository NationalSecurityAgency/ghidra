/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
import ghidra.program.model.address.AddressRange;
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
	 * @param sourceAddress
	 *            the source program address
	 * @return the destination program address range, or null if the source program address maps 
	 *         to one that is "deleted" in the destination program
	 */
	public AddressRange getCorrelatedDestinationRange(Address sourceAddress, TaskMonitor monitor)
			throws CancelledException;

	/**
	 * Returns the name of the correlating algorithm.
	 * @return the name of the correlating algorithm.
	 */
	public String getName();
}
