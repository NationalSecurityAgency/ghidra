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
package ghidra.app.plugin.core.diff;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;

/**
 * DiffController controls a program Diff. It maintains address sets indicating 
 * the differences between two programs. It can limit the determined differences
 * to an address set. It allows differences to be applied or ignored. It has a 
 * diff filter that controls the differences being indicated. It has a merge 
 * filter that controls the types of differences being applied. It allows
 * differences at particular addresses to be ignored.
 * 
 * The Diff controller also maintains the current location. It provides a way 
 * to navigate from one difference to the next or previous difference.
 */
public class DiffController {
	private ProgramMergeManager mergeEngine;
	private AddressSetView p1LastDiffs;
	private AddressSetView p1LimitSet;
	private Address p1CurrentAddress;
	private ArrayList<DiffControllerListener> listenerList =
		new ArrayList<DiffControllerListener>();

	/**
	 * Constructor
	 * <P>Note: This method is potentially time consuming and should normally
	 * be called from within a background task.
	 * @param p1 The first program to apply differences to.
	 * @param p2 The second program to apply differences from.
	 * @param p1LimitSet Address set the determined differences are limited to.
	 * The addresses in this set should be derived from p1.
	 * @param diffFilter filter indicating difference types to mark.
	 * @param mergeFilter filter indicating difference types to apply.
	 * @param monitor the progress monitor
	 * @throws ProgramConflictException
	 */
	public DiffController(Program p1, Program p2, AddressSetView p1LimitSet,
			ProgramDiffFilter diffFilter, ProgramMergeFilter mergeFilter, TaskMonitor monitor)
			throws ProgramConflictException {
		mergeEngine = new ProgramMergeManager(p1, p2, p1LimitSet, monitor);
		mergeEngine.setDiffFilter(diffFilter);
		mergeEngine.setMergeFilter(mergeFilter);
		this.p1LimitSet = p1LimitSet;
		if (p1LimitSet == null) {
			p1CurrentAddress = p1.getMinAddress();
		}
		else {
			p1CurrentAddress = p1LimitSet.getMinAddress();
		}
		p1LastDiffs = new AddressSet();
	}

	/** Gets the first program being compared by the ProgramDiff.
	 * @return program1. the program to apply differences to.
	 */
	Program getProgramOne() {
		return mergeEngine.getProgramOne();
	}

	/** Gets the second program being compared by the ProgramDiff.
	 * @return program2. the program to get differences from for applying.
	 */
	Program getProgramTwo() {
		return mergeEngine.getProgramTwo();
	}

	/**
	 * Gets the address set the current Program Diff is limited to.
	 * @return the address set the current diff is limited to.
	 * The addresses in this set are derived from the p1 program.
	 */
	AddressSetView getLimitedAddressSet() {
		return p1LimitSet;
	}

	/**
	 * Gets the address set indicating the addresses currently being ignored.
	 * @return the address set indicating the addresses currently being ignored.
	 * The addresses in this set are derived from the p1 program.
	 */
	AddressSetView getIgnoredAddressSet() {
		return mergeEngine.getIgnoreAddressSet();
	}

	/**
	 * Gets the address set being used to restrict the resulting difference set
	 * that is reported by getting the differences. This address set is 
	 * effectively a view port into the differences address set.
	 * @return the address set used to restrict the differences.
	 * The addresses in this set are derived from the p1 program.
	 */
	AddressSetView getRestrictedAddressSet() {
		return mergeEngine.getRestrictedAddressSet();
	}

	/** 
	 * Get a copy of the diff filter that the merge is using.
	 */
	public ProgramDiffFilter getDiffFilter() {
		return mergeEngine.getDiffFilter();
	}

	/** 
	 * Set the filter that indicates which parts of the Program should be 
	 * diffed.
	 */
	public void setDiffFilter(ProgramDiffFilter filter) {
		mergeEngine.setDiffFilter(filter);
	}

	/** 
	 * Get a copy of the filter that indicates which parts of the Program 
	 * should be merged.
	 */
	public ProgramMergeFilter getMergeFilter() {
		return mergeEngine.getMergeFilter();
	}

	/** 
	 * Set the filter that indicates which parts of the Program should be 
	 * merged.
	 */
	public void setMergeFilter(ProgramMergeFilter filter) {
		mergeEngine.setMergeFilter(filter);
	}

	/** Gets the filtered program differences for this merge. Only differences are
	 * indicated for merge filter categories that are enabled and for addresses
	 * that have not been marked as ignored.
	 * <P>Note: This method is potentially time consuming and should normally
	 * be called from within a background task.
	 * @param monitor the task monitor for indicating the progress of
	 * determining differences. This monitor also allows the user to cancel if
	 * the diff takes too long. If no monitor is desired, use null.
	 * @return the program differences.
	 * The addresses in this set are derived from the p1 program.
	 */
	public AddressSetView getFilteredDifferences(TaskMonitor monitor) throws CancelledException {
		AddressSetView diffs1 = mergeEngine.getFilteredDifferences(monitor);
		Program program1 = getProgramOne();
		Program program2 = getProgramTwo();
		monitor.setMessage("Adjusting differences to code unit boundaries...");
		AddressSet diffSet2 = DiffUtility.getCompatibleAddressSet(diffs1, program2);
		AddressSet diffCuSet2 = DiffUtility.getCodeUnitSet(diffSet2, program2);
		monitor.setMessage("Converting Diffs to program 1 set...");
		diffs1 = DiffUtility.getCompatibleAddressSet(diffCuSet2, program1);
		if (!p1LastDiffs.equals(diffs1)) {
			p1LastDiffs = diffs1;
		}
		return diffs1;
	}

	/** Restrict the resulting differences to the indicated address set.
	 * @param p1AddressSet the address set to restrict the getFilteredDifferences() to.
	 * The addresses in this set should be derived from the p1 program.
	 * @param monitor the task monitor for canceling the fix up of the 
	 * differences due to the restriction.
	 */
	public void restrictResults(AddressSetView p1AddressSet, TaskMonitor monitor) {
		mergeEngine.restrictResults(p1AddressSet);
		differencesChanged(monitor);
	}

	/** Remove the restriction for the resulting differences to the indicated address set.
	 * @param monitor the task monitor for canceling the fix up of the 
	 * differences due to the removal of the restriction.
	 */
	public void removeResultRestrictions(TaskMonitor monitor) {
		mergeEngine.removeResultRestrictions();
		differencesChanged(monitor);
	}

	/**
	 * Apply differences in the address set from program p2
	 * into the current program p1.
	 * @param p1AddressSet address set of differences
	 * The addresses in this set should be derived from the p1 program.
	 * @param filter merge filter
	 * @param monitor the task monitor for canceling the fix up of the 
	 * differences due to the removal of the restriction.
	 * @throws MemoryAccessException
	 * @throws CancelledException if user cancels via the monitor.
	 */
	boolean apply(AddressSetView p1AddressSet, TaskMonitor monitor) throws MemoryAccessException,
			CancelledException {
		boolean applied = mergeEngine.merge(p1AddressSet, monitor);
		return applied;
	}

	/**
	 * Gets any error and information messages associated with the last apply.
	 */
	String getApplyMessage() {
		return mergeEngine.getErrorMessage() + mergeEngine.getInfoMessage();
	}

	/**
	 * Ignore any differences in the specified address set.
	 * @param p1AddressSet address set set of differences
	 * The addresses in this set should be derived from the p1 program.
	 */
	void ignore(AddressSetView p1AddressSet, TaskMonitor monitor) {
		mergeEngine.ignore(p1AddressSet);
		differencesChanged(monitor);
	}

	/**
	 * Gets any warning messages associated with the initial Diff of the two programs.
	 */
	public String getWarnings() {
		return mergeEngine.getWarnings();
	}

	/**
	 * Get the address for the diff controller's current location.
	 * @return the current address.
	 * This address is derived from the p1 program.
	 */
	Address getCurrentAddress() {
		return p1CurrentAddress;
	}

	/**
	 * Go to the given address; update the last address so that
	 * iterator will be adjusted for next and previous.
	 * @param p1Address address to go to
	 * This address should be derived from the p1 program.
	 */
	private void goTo(Address p1Address) {
		p1CurrentAddress = p1Address;
		locationChanged(p1CurrentAddress);
	}

	/**
	 * set the Diff controller's current address to the specified address.
	 * @param p1NewAddress the address
	 * This address should be derived from the p1 program.
	 */
	void setLocation(Address p1NewAddress) {
		if (p1NewAddress.equals(p1CurrentAddress))
			return;
		p1CurrentAddress = p1NewAddress;
		locationChanged(p1CurrentAddress);
	}

	/**
	 * Called from the dialog when the cursor should move to the first difference.
	 * Update the buttons in the dialog according to whether there is
	 * a next or previous.
	 */
	void first() {
		if (p1LastDiffs.isEmpty()) {
			return;
		}
		goTo(p1LastDiffs.getMinAddress());
	}

	boolean hasNext() {
		return getNextAddress() != null;
	}

	private Address getNextAddress() {
		AddressRangeIterator it = p1LastDiffs.getAddressRanges(p1CurrentAddress, true);
		if (!it.hasNext()) {
			return null;
		}
		AddressRange range = it.next();
		if (range.contains(p1CurrentAddress)) {
			if (it.hasNext()) {
				return it.next().getMinAddress();
			}
			return null;
		}
		return range.getMinAddress();

	}

	private Address getPreviousAddress() {
		AddressRangeIterator it = p1LastDiffs.getAddressRanges(p1CurrentAddress, false);
		if (!it.hasNext()) {
			return null;
		}
		AddressRange range = it.next();
		if (range.getMinAddress().equals(p1CurrentAddress)) {
			if (it.hasNext()) {
				return it.next().getMinAddress();
			}
			return null;
		}
		return range.getMinAddress();

	}

	/**
	 * Called from the dialog when the "next diff" button is hit.
	 * Update the buttons in the dialog according to whether there is
	 * a next or previous.
	 */
	void next() {
		Address nextAddress = getNextAddress();
		if (nextAddress != null) {
			goTo(nextAddress);
		}
	}

	boolean hasPrevious() {
		return getPreviousAddress() != null;
	}

	/**
	 * Called from the dialog when the "previous diff" button is hit.
	 * Update the buttons in the dialog according to whether there is
	 * a next or previous.
	 */
	void previous() {
		Address previousAddress = getPreviousAddress();
		if (previousAddress != null) {
			goTo(previousAddress);
		}
	}

	/**
	 * Refreshes the differences to show what is still different between the two
	 * programs. After calling this method, any differences that were being 
	 * ignored are still being ignored. The differences are restricted to the 
	 * same address set as before the refresh.
	 * @param monitor the task monitor for canceling the fix up of the
	 * recompute of the differences.
	 * @throws ProgramConflictException
	 */
	void refresh(boolean keepIgnored, TaskMonitor monitor) throws ProgramConflictException {
		AddressSetView ignoreSet = getIgnoredAddressSet();
		recomputeDiffs(monitor);
		if (keepIgnored) {
			mergeEngine.ignore(ignoreSet);
		}
		differencesChanged(monitor);
	}

	private void recomputeDiffs(TaskMonitor monitor) throws ProgramConflictException {
		recomputeDiffs(getLimitedAddressSet(), monitor);
	}

	private void recomputeDiffs(AddressSetView newLimitSet, TaskMonitor monitor)
			throws ProgramConflictException {
		Program p1 = mergeEngine.getProgramOne();
		Program p2 = mergeEngine.getProgramTwo();
		ProgramDiffFilter diffFilter = mergeEngine.getDiffFilter();
		ProgramMergeFilter mergeFilter = mergeEngine.getMergeFilter();
		this.p1LimitSet = newLimitSet;

		mergeEngine = new ProgramMergeManager(p1, p2, newLimitSet, monitor);
		mergeEngine.setDiffFilter(diffFilter);
		mergeEngine.setMergeFilter(mergeFilter);
	}

	public void addDiffControllerListener(DiffControllerListener listener) {
		listenerList.add(listener);
	}

	public void removeDiffControllerListener(DiffControllerListener listener) {
		listenerList.remove(listener);
	}

	public void locationChanged(Address program1Location) {
		for (int i = 0; i < listenerList.size(); i++) {
			DiffControllerListener listener = listenerList.get(i);
			listener.diffLocationChanged(this, program1Location);
		}
	}

	public void differencesChanged(TaskMonitor monitor) {
		for (int i = 0; i < listenerList.size(); i++) {
			DiffControllerListener listener = listenerList.get(i);
			listener.differencesChanged(this);
		}
	}

}
