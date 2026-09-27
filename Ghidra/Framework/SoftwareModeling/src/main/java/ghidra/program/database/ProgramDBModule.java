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
package ghidra.program.database;

import ghidra.framework.data.DomainObjectDbModule;
import ghidra.program.model.address.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Interface that all ProgramDB module managers must implement.
 */
public interface ProgramDBModule extends DomainObjectDbModule<ProgramDB> {

	/**
	 * Delete all objects which have been applied to the address range startAddr to endAddr
	 * and update the database accordingly.
	 * The specified start and end addresses must form a valid range within
	 * a single {@link AddressSpace}.
	 * 
	 * @param startAddr the first address in the range.
	 * @param endAddr the last address in the range.
	 * @param monitor the task monitor to use in any upgrade operations.
	 * @throws CancelledException if the user cancelled the operation via the task monitor.
	 */
	void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException;

	/**
	 * Move all objects within an address range to a new location.
	 * 
	 * @param fromAddr the first address of the range to be moved.
	 * @param toAddr the address where to the range is to be moved.
	 * @param length the number of addresses to move.
	 * @param monitor the task monitor to use in any upgrade operations.
	 * @throws CancelledException if the user cancelled the operation via the task monitor.
	 * @throws AddressOverflowException if the length is such that a address wrap occurs
	 */
	void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws AddressOverflowException, CancelledException;

}
