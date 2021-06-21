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

import java.io.IOException;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Interface that all subsection managers of a program must implement.
 */
public interface ManagerDB {

	/**
	 * Callback from program used to indicate all manager have been created.
	 * When this method is invoked, all managers have been instantiated but may not be fully initialized.
	 * @param program the program is set when all the initializations have been completed.
	 */
	void setProgram(ProgramDB program);

	/**
	 * Callback from program made to each manager after the program has completed initialization.
	 * This method may be used by managers to perform additional upgrading which may have been deferred.
	 * @param openMode the mode that the program is being opened.
	 * @param currentRevision current program revision.  If openMode is UPGRADE, this value reflects 
	 * the pre-upgrade value.
	 * @param monitor the task monitor to use in any upgrade operations.
	 * @throws IOException if a database io error occurs.
	 * @throws CancelledException if the user cancelled the operation via the task monitor.
	 */
	void programReady(int openMode, int currentRevision, TaskMonitor monitor) throws IOException,
			CancelledException;

	/**
	 * Clears all data caches. 
	 * @param all if false, some managers may not need to update their cache if they can
	 * tell that its not necessary.  If this flag is true, then all managers should clear
	 * their cache no matter what.
	 * @throws IOException if a database io error occurs.
	 */
	void invalidateCache(boolean all) throws IOException;

	/**
	 * Delete all objects which have been applied to the address range startAddr to endAddr
	 * and update the database accordingly.
	 * @param startAddr the first address in the range.
	 * @param endAddr the last address in the range.
	 * @param monitor the task monitor to use in any upgrade operations.
	 * @throws CancelledException if the user cancelled the operation via the task monitor.
	 */
	void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException;

	/**
	 * Move all objects within an address range to a new location.
	 * @param fromAddr the first address of the range to be moved.
	 * @param toAddr the address where to the range is to be moved.
	 * @param length the number of addresses to move.
	 * @param monitor the task monitor to use in any upgrade operations.
	 * @throws CancelledException if the user cancelled the operation via the task monitor.
	 * @throws AddressOverflowException if the length is such that a address wrap occurs
	 */
	void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws AddressOverflowException, CancelledException;

	/**
	 * Callback from the program after being closed to signal this manager to release memory and resources.
	 * <p>
	 */
	default void dispose() {
		// default do nothing
	}
}
