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
package ghidra.app.merge.listing;

import ghidra.app.merge.tool.ListingMergePanel;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.ProgramConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>ListingMerger</code> is an interface implemented by an individual 
 * listing merge manager. It defines methods that the overall ListingMergeManager
 * can call on the individual listing merge managers.
 */
interface ListingMerger {
	
	/**
	 * Performs the automatic merge for all changes in my Checked Out program version.
	 * It also determines the conflicts requiring manual resolution.
	 * @param monitor task monitor for informing the user of progress.
	 * @param progressMin minimum progress value, between 0 and 100, for this auto merge. 
	 * The merge manager's progress should be updated from progressMin to progressMax 
	 * as the autoMerge occurs.
	 * @param progressMax maximum progress value, between 0 and 100, for this auto merge.
	 * @throws ProgramConflictException if the programs for different versions are not compatible.
	 * @throws MemoryAccessException if memory can't be accessed to get/set byte values.
	 * @throws CancelledException if the user cancels the merge.
	 */
	abstract public void autoMerge(int progressMin, int progressMax, TaskMonitor monitor)
	throws ProgramConflictException, MemoryAccessException, CancelledException;
	
	/**
	 * Method called when the Apply button is pressed on the GUI conflict resolution window.
	 * @return true if apply succeeded.
	 */
	abstract public boolean apply();
	
	/**
	 * Method called when the Cancel button is pressed on the GUI conflict resolution window.
	 */
	abstract public void cancel();

	/**
	 * Returns a string indicating the type of listing conflict this merger handles.
	 * <br>For example, Function, Symbol, etc.
	 */
	abstract public String getConflictType();
	
	/**
	 * Determines the number of conflicts that have currently been resolved on 
	 * the conflict resolution window.
	 * @return the number of conflicts resolved by the user selecting buttons or checkboxes.
	 */
	abstract public int getNumConflictsResolved();

	/**
	 * Determines if there is a conflict at the specified address.
	 * @param addr
	 * @return true if there is one or more conflicts at the address.
	 */
	abstract public boolean hasConflict(Address addr);
	
	/**
	 * Determines the number of conflicts at the indicated address.
	 * @param addr the address
	 * @return the number of conflicts at the indicated address.
	 */
	abstract public int getConflictCount(Address addr);
	
	/**
	 * Performs a manual merge of all conflicts at the indicated address for 
	 * the type of conflicts that this merge manager handles.
	 * @param listingPanel the listing merge panel with the 4 version listings.
	 * @param addr
	 * @param conflictOption ASK_USER means interactively resolve conflicts. 
	 * JUnit testing also allows setting this to LATEST, MY, or ORIGINAL to force
	 * selection of a particular version change.
	 * @param monitor task monitor for informing the user of progress.
	 * @throws CancelledException if the user cancels the merge.
	 * @throws MemoryAccessException if memory can't be accessed to get/set byte values.
	 */
	abstract public void mergeConflicts(ListingMergePanel listingPanel, Address addr, int conflictOption, TaskMonitor monitor)
	throws CancelledException, MemoryAccessException;

	/**
	 * @return an address set indicating where there are conflicts to resolve.
	 */
	abstract public AddressSetView getConflicts();
	
}
