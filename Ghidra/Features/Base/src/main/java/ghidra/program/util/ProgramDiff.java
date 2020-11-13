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

import java.util.*;

import ghidra.program.database.properties.UnsupportedMapDB;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.TypeMismatchException;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * <CODE>ProgramDiff</CODE> is a class for comparing two programs and
 * determining where there are differences between them.
 * <P>
 * Currently, the differences can be determined if the two programs have
 * equivalent address spaces. If the programs have different program context
 * registers, the Diff can still occur but will not determine program context
 * differences.
 * <P>
 * @see ghidra.program.util.ProgramDiffFilter
 */

public class ProgramDiff {

	/** A filter for keeping track of all types of differences determined by
	 * this ProgramDiff so that it knows what differences to recompute.
	 */
	private ProgramDiffFilter reDiffFilter;
	/** The first program for the diff. */
	private Program program1;
	/** The second program for the diff. */
	private Program program2;
	private Listing listing1;
	private Listing listing2;
	/** Comparator that holds information about differences between the
	 *  two programs memory blocks.
	 */
	private ProgramMemoryComparator pgmMemComp;
	/** Indicator of whether or not the two programs have the same program context registers. */
	private boolean sameProgramContext;
	/** Indicator of whether or not to display the address space name in task monitor status messages. */
	private static boolean showAddressSpace = true;
//	/** Indicator of how frequently to update the monitor status message with the address being DIFFed. */
//	private static final int DISPLAY_GRANULARITY = 501;
	/**
	 * The number of bytes to get at a time when determining byte differences
	 * between program1 and program2.
	 */
	private static final int BYTE_DIFF_GRAB_SIZE = 1024;

	/** The filter for indicating program differences we are interested in. */
	private ProgramDiffFilter pdf;
	/** Hash table for holding address sets for each of the primary difference types.
	 *  The addresses in these address sets are derived from program1.
	 *  The union of these address sets gives all program differences.
	 */
	private Hashtable<Integer, AddressSet> diffAddrSets = new Hashtable<>();
	/** Whether or not the user cancelled the last getDifferences. */
	private boolean cancelled = false;
	/** The differences from the last getDifferences() call.
	 *  The addresses in this address set are derived from program1.
	 */
	private AddressSet currentDiffs;
	/** The returned diff address set is the current diffs less the ignore
	 *  address set and constrained by the restrict address set.
	 *  The addresses in this address set are derived from program1.
	 */
	private AddressSet diffsToReturn;
	/** The address set that is checked by this Program Diff.
	 *  The addresses in this address set are derived from program1.
	 */
	private AddressSetView checkAddressSet;
	/** The address set to use for restricting the view of addresses where
	 *  differences are currently reported.
	 *  The addresses in this address set are derived from program1.
	 */
	private AddressSetView restrictAddressSet;
	/** The set of addresses that should currently not appear as part of the differences.
	 *  The addresses in this address set are derived from program1.
	 */
	private AddressSet ignoreAddressSet;
	/** Indicates that the filter has been changed since the last getDifferences().
	 *  The addresses in this address set are derived from program1.
	 */
	private boolean filterChanged = true;
	/** The current prefix message to appear in the monitor's message area. */
	private static String monitorMsg = "Checking Differences";
	/** String indicating a warning message if the program context registers are not the same. */
	private String warnings = null;

	private static final BookmarkTypeComparator BOOKMARK_TYPE_COMPARATOR =
		new BookmarkTypeComparator();
	private static final BookmarkComparator BOOKMARK_COMPARATOR = new BookmarkComparator();

	/**
	 * <CODE>ProgramDiff</CODE> is used to determine the addresses where
	 * there are differences between two programs.
	 * Possible differences are:
	 * the actual bytes at an address, comments, labels, mnemonics,
	 * references, equates, properties, functions, program context.
	 * <P>Currently, the differences can be determined only if the address
	 * spaces match between the programs.
	 *
	 * @param program1 the first program
	 * @param program2 the second program
	 * @throws ProgramConflictException indicates that programs
	 * couldn't be compared to determine the differences.
	 * <P>For example,
	 * <P>the two programs have different address spaces.
	 * @throws IllegalArgumentException if one of the programs is null.
	 */
	public ProgramDiff(Program program1, Program program2)
			throws ProgramConflictException, IllegalArgumentException {
		this(program1, program2, null);
	}

	/**
	 * <CODE>ProgramDiff</CODE> is used to determine the addresses where
	 * there are differences between two programs.
	 * Possible differences are:
	 * the actual bytes at an address, comments, labels, mnemonics,
	 * references, equates, properties, functions, program context.
	 * <P>Currently, the differences can be determined only if the address
	 * spaces match between the programs.
	 *
	 * @param program1 the first program
	 * @param program2 the second program
	 * @param checkAddressSet the address set to be used to constrain where
	 * differences are found.
	 * The addresses in this address set should be derived from program1.
	 * @throws ProgramConflictException indicates that programs
	 * couldn't be compared to determine the differences.
	 * <P>For example,
	 * <P>the two programs have different address spaces.
	 * between the two programs, do not match.
	 * @throws IllegalArgumentException if one of the programs is null.
	 */
	public ProgramDiff(Program program1, Program program2, AddressSetView checkAddressSet)
			throws ProgramConflictException, IllegalArgumentException {

		if (program1 == null || program2 == null) {
			throw new IllegalArgumentException("program cannot be null.");
		}
		this.program1 = program1;
		this.program2 = program2;
		this.listing1 = program1.getListing();
		this.listing2 = program2.getListing();
		// Check the memory blocks for conflicts.
		pgmMemComp = new ProgramMemoryComparator(program1, program2);
		this.checkAddressSet = getCombinedAddressSet(checkAddressSet);
		ignoreAddressSet = new AddressSet();
		pdf = new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS);
		reDiffFilter = new ProgramDiffFilter();
		sameProgramContext =
			ProgramMemoryComparator.sameProgramContextRegisterNames(program1, program2);
		if (!sameProgramContext) {
			warnings = "Program Context Registers don't match between the programs.\n" +
				"Program Context Register differences will not be checked.";
		}
	}

	/**
	 * Determines all of the addresses that are in the Diff's two programs
	 * for the indicated address set and that are compatible with the first program.
	 * Any program2 addresses for which an equivalent (compatible) address can't be determined will not be
	 * included in the combined set.
	 * @param addrs the addresses to combine from the first program.
	 * @return the addresses which are derived from the two programs combined addresses that are in common
	 * with the ones in the address set that is passed in as a parameter.
	 */
	AddressSet getCombinedAddressSet(AddressSetView addrs) {
		AddressSet combined = ProgramMemoryComparator.getCombinedAddresses(program1, program2);
		if (addrs != null) {
			combined = combined.intersect(addrs);
		}
		return combined;
	}

	/**
	 * Determines the addresses that are in common between the Diff's two programs
	 * for the indicated address set.
	 * @param addrs the addresses to intersect with the initialized addresses
	 * in common between our two programs.
	 * The addresses in this address set should be derived from program1.
	 * @return the addresses from the indicated address set that are initialized and in common.
	 * The addresses in the returned address set are derived from program1.
	 */
	AddressSet getInCommonAddressSet(AddressSetView addrs) {
		AddressSet inCommon = pgmMemComp.getAddressesInCommon();
		if (addrs != null) {
			inCommon = inCommon.intersect(addrs);
		}
		return inCommon;
	}

	/**
	 * Determines the addresses where both programs have initialized memory.
	 * @param addrs the addresses to intersect with the initialized addresses
	 * in common between the two programs.
	 * The addresses in this address set should be derived from program1.
	 * @return the addresses from the indicated address set that are initialized and in common.
	 * The addresses in the returned address set are derived from program1.
	 */
	AddressSet getCommonInitializedAddressSet(AddressSetView addrs) {
		AddressSet initialized = pgmMemComp.getInitializedAddressesInCommon();
		if (addrs != null) {
			initialized = initialized.intersect(addrs);
		}
		return initialized;
	}

	/**
	 * Determines the addresses where both programs have uninitialized memory.
	 * @param addrs the addresses to intersect with the uninitialized addresses
	 * in common between the two programs.
	 * The addresses in this address set should be derived from program1.
	 * @return the addresses from the indicated address set that are uninitialized and in common.
	 * The addresses in the returned address set are derived from program1.
	 */
	AddressSet getCommonUninitializedAddressSet(AddressSetView addrs) {
		AddressSet inCommon = pgmMemComp.getAddressesInCommon();
		AddressSet initialized = pgmMemComp.getInitializedAddressesInCommon();
		AddressSet unInit = inCommon.subtract(initialized);
		if (addrs != null) {
			unInit = unInit.intersect(addrs);
		}
		return unInit;
	}

	/**
	 * Determines the addresses where one program initialized memory and the other didn't.
	 * @param addrs the addresses to intersect with the addresses where initialization differs
	 * between the two programs.
	 * The addresses in this address set should be derived from program1.
	 * @return the addresses from the indicated address set whre initialization differs.
	 * The addresses in the returned address set are derived from program1.
	 */
	AddressSet getInitializationDiffersAddressSet(AddressSetView addrs) {
		AddressSet inCommon = pgmMemComp.getAddressesInCommon();
		AddressSet sameType = pgmMemComp.getSameMemTypeAddressesInCommon();
		AddressSet initDiffers = inCommon.subtract(sameType);
		if (addrs != null) {
			initDiffers = initDiffers.intersect(addrs);
		}
		return initDiffers;
	}

	/**
	 * Determines the addresses that are NOT in common between the Diff's two programs
	 * for the indicated address set.
	 * @param addrs the addresses to intersect with the addresses
	 * not in common between the two programs.
	 * The addresses in this address set should be derived from program1.
	 * @return the addresses from the indicated address set that are not in common.
	 * The addresses in the returned address set are derived from program1.
	 */
	AddressSet getNonCommonAddressSet(AddressSetView addrs) {
		AddressSet addressesOnlyInOne = pgmMemComp.getAddressesOnlyInOne();
		AddressSet addressesOnlyInTwo = pgmMemComp.getAddressesOnlyInTwo();
		AddressSet onlyInTwoCompatibleWith1 =
			DiffUtility.getCompatibleAddressSet(addressesOnlyInTwo, program1);
		AddressSet nonCommon = addressesOnlyInOne.union(onlyInTwoCompatibleWith1);
		if (addrs != null) {
			nonCommon = nonCommon.intersect(addrs);
		}
		return nonCommon;
	}

	/**
	 * Return true if the programs to compare have matching memory maps.
	 */
	public boolean memoryMatches() {
		if (pgmMemComp.hasMemoryDifferences()) {
			return false;
		}
		return true;
	}

	/** Returns a copy of this ProgramDiff.
	 *  @return the copy of this ProgramDiff or null if a
	 *  MemoryConflictException occurs.
	 */
	@Override
	protected Object clone() {
		ProgramDiff diff = null;
		try {
			diff = new ProgramDiff(program1, program2, checkAddressSet);

			diff.ignoreAddressSet.add(this.ignoreAddressSet);
			diff.restrictAddressSet = new AddressSet(this.restrictAddressSet);
			diff.pdf = this.pdf;
			diff.diffAddrSets = new Hashtable<>(this.diffAddrSets);
			for (Enumeration<Integer> enu = diff.diffAddrSets.keys(); enu.hasMoreElements();) {
				Integer key = enu.nextElement();
				AddressSet addrSet = diff.diffAddrSets.get(key);
				diff.diffAddrSets.put(key, new AddressSet(addrSet));
			}
			diff.cancelled = this.cancelled;
			diff.currentDiffs = new AddressSet(this.currentDiffs);
			diff.diffsToReturn = new AddressSet(this.diffsToReturn);
			diff.filterChanged = this.filterChanged;
			diff.sameProgramContext = this.sameProgramContext;
			diff.warnings = (this.warnings == null) ? null : new String(this.warnings);
		}
		catch (ProgramConflictException exc) {
			Msg.error(this, "Unexpected Exception: " + exc.getMessage(), exc);
		}

		return diff;
	}

	/** Get a message indicating any warnings about this PRogramDiff. For example,
	 * if the program context registers don't match between the programs, the
	 * string is a message indicating this.
	 * @return the warning message string. null if no warnings.
	 */
	public String getWarnings() {
		return warnings;
	}

	/** Returns a new ProgramDiffFilter equal to the one in this program diff.
	 * The filter indicates which types of differences are to be determined.
	 * @return a copy of the program diff filter currently in use.
	 */
	public ProgramDiffFilter getFilter() {
		return new ProgramDiffFilter(pdf);
	}

	/** Sets the ProgramDiffFilter for this program diff. The filter indicates
	 * which types of differences are to be determined.
	 * @param filter the program diff filter
	 */
	public void setFilter(ProgramDiffFilter filter) {
		ProgramDiffFilter tmpFilter;
		if (filter != null) {
			tmpFilter = new ProgramDiffFilter(filter);
		}
		else {
			tmpFilter = new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS);
		}
		if (!tmpFilter.equals(this.pdf)) {
			this.pdf = tmpFilter;
			filterChanged = true;
		}
	}

	/** Gets the first program being compared by the ProgramDiff.
	 * @return program1.
	 */
	public Program getProgramOne() {
		return program1;
	}

	/** Gets the second program being compared by the ProgramDiff.
	 * @return program2.
	 */
	public Program getProgramTwo() {
		return program2;
	}

	/** Returns the addresses from combining the address sets in program1 and program2.
	 * @return the addresses for both program1 and program2.
	 * The addresses in this address set are derived from program1.
	 */
	public AddressSetView getCombinedAddresses() {
		return ProgramMemoryComparator.getCombinedAddresses(program1, program2);
	}

	/** Returns the initialized memory addresses in common between
	 * program1 and program2.
	 * @return the initialized memory addresses in common between
	 * program1 and program2.
	 * The addresses in the this set are derived from program1.
	 */
	public AddressSet getInitializedInCommon() {
		return pgmMemComp.getInitializedAddressesInCommon();
	}

	/** Returns the addresses in common between program1 and program2.
	 * @return the addresses in common between program1 and program2.
	 * The addresses in this address set are derived from program1.
	 */
	public AddressSet getAddressesInCommon() {
		return pgmMemComp.getAddressesInCommon();
	}

	/** Returns the addresses that are in program1, but not in program2.
	 * @return the addresses that are in program1, but not in program2.
	 * The addresses in this address set are derived from program1.
	 */
	public AddressSet getAddressesOnlyInOne() {
		return pgmMemComp.getAddressesOnlyInOne();
	}

	/** Returns the addresses that are in program2, but not in program1.
	 * @return the addresses that are in program2, but not in program1.
	 * The addresses in this address set are derived from program2.
	 */
	public AddressSet getAddressesOnlyInTwo() {
		return pgmMemComp.getAddressesOnlyInTwo();
	}

	/**
	 * <CODE>getDifferences</CODE> is used to determine
	 * the addresses where there are differences between two programs using
	 * the current filter. This
	 * method only indicates that there is a difference at the address, not what
	 * type of difference it is. Possible differences are:
	 * the actual bytes at an address, comments, labels, code units,
	 * references, equates, properties, and program context register values.
	 *
	 * @param monitor the task monitor for indicating the progress of
	 * determining differences. This monitor also allows the user to cancel if
	 * the diff takes too long. If no monitor is desired, use null.
	 * @return an address set of where differences were found between the two
	 * programs based on the current filter setting.
	 * The addresses in this address set are derived from program1.
	 * @throws CancelledException if the user cancelled the Diff.
	 */
	synchronized public AddressSetView getDifferences(TaskMonitor monitor)
			throws CancelledException {
		return getDifferences(pdf, monitor);
	}

	/**
	 * <CODE>getDifferences</CODE> is used to determine
	 * the addresses where there are differences between two programs. This
	 * method only indicates that there is a difference at the address, not what
	 * type of difference it is. Possible differences are:
	 * the actual bytes at an address, comments, labels, code units,
	 * references, equates, properties, tags and program context register values.
	 * <P>The specified filter will become the new current filter.
	 *
	 * @param filter the filter to use instead of the current filter defined for
	 * this ProgramDiff.
	 * @param monitor the task monitor for indicating the progress of
	 * determining differences. This monitor also allows the user to cancel if
	 * the diff takes too long. If no monitor is desired, use null.
	 * @return an address set of where differences were found between the two
	 * programs based on the specified filter setting.
	 * The addresses in this address set are derived from program1.
	 * @throws CancelledException if the user cancelled the Diff.
	 */
	synchronized public AddressSetView getDifferences(ProgramDiffFilter filter, TaskMonitor monitor)
			throws CancelledException {
		cancelled = false;
		if (monitor == null) {
			// Create a do nothing task monitor that we can pass along.
			monitor = TaskMonitorAdapter.DUMMY_MONITOR;
		}

		if (!filterChanged && ((filter != null) && (filter.equals(this.pdf)))) {
			return diffsToReturn;
		}
		this.pdf = filter;
		this.reDiffFilter.addToFilter(filter);
		filterChanged = false;
		currentDiffs = new AddressSet();

		// Create any required address sets.
		int[] pt = ProgramDiffFilter.getPrimaryTypes();
		for (int element : pt) {
			// Are we interested in this difference type?
			if (pdf.getFilter(element)) {
				Integer key = new Integer(element);
				// Do we still need to determine differences of this type?
				if (!diffAddrSets.containsKey(key)) {
					if (!cancelled) {
						try {
							createAddressSet(element, monitor);
						}
						catch (ProgramConflictException e) {
							// Ignore register differences if they aren't compatible.
						}
					}
					else {
						// Turn off this filter since user cancelled getting results.
						pdf.setFilter(element, false);
					}
				}
				// Do we now have the differences?
				if (diffAddrSets.containsKey(key)) {
					AddressSet addrSetToAdd = diffAddrSets.get(key);
					currentDiffs.add(addrSetToAdd);
				}
				// Did the user cancel the program diff?
				checkCancelled(monitor);
			}
		}
		checkCancelled(monitor);
		monitor.setMessage("Adjusting Diff set...");
		monitor.setProgress(0);
		computeDiffsToReturn();
		return diffsToReturn;
	}

	/**
	 * <CODE>reDiffSubSet</CODE> re-determines the differences between the
	 * two programs for the indicated address set.
	 *
	 * @param subSet the address set indicating which addresses should have
	 * their differences re-determined.
	 * The addresses in this address set should be derived from program1.
	 * @param monitor the task monitor for indicating the progress of
	 * determining differences. This monitor also allows the user to cancel if
	 * the diff takes too long. If no monitor is desired, use null.
	 */
	synchronized void reDiffSubSet(AddressSetView subSet, TaskMonitor monitor)
			throws CancelledException {
		if (monitor == null) {
			// Create a do nothing task monitor that we can pass along.
			monitor = TaskMonitorAdapter.DUMMY_MONITOR;
		}
		monitor.checkCanceled();

		ProgramDiff subDiff;
		try {
			subDiff = new ProgramDiff(program1, program2, subSet);
			subDiff.getDifferences(reDiffFilter, monitor);
			monitor.setMessage("Adjusting differences due to apply.");
			// Adjust any required address sets.
			int[] pt = ProgramDiffFilter.getPrimaryTypes();
			for (int element : pt) {
				Integer key = new Integer(element);
				AddressSet thisSet = diffAddrSets.get(key);
				if (thisSet == null) {
					continue; // This is not part of current address sets.
				}
				AddressSet otherSet = subDiff.diffAddrSets.get(key);
				thisSet = thisSet.subtract(subSet);
				thisSet.add(otherSet);
				diffAddrSets.put(key, thisSet);
				filterChanged = true;
			}
		}
		catch (ProgramConflictException e1) {
			Msg.error(this, "Unexpected Exception: " + e1.getMessage(), e1);
		}
		catch (IllegalArgumentException e1) {
			Msg.error(this, "Unexpected Exception: " + e1.getMessage(), e1);
		}
	}

	/**
	 * Returns an address set indicating where the user defined property differs
	 * between the Diff's two programs within the specified address set.
	 * @param property	the user defined property
	 * @param addrs the address set for limiting checking.
	 * The addresses in this address set should be derived from program1.
	 * @param monitor the progress monitor.
	 * @return the address set indicating where the property differs.
	 * The addresses in this address set are derived from program1.
	 * @throws CancelledException if the user cancelled the Diff.
	 */
	synchronized public AddressSetView getUserDefinedDiffs(String property, AddressSetView addrs,
			TaskMonitor monitor) throws CancelledException {
		// Handle case where the class for a Saveable property is missing.
		if ((listing1.getPropertyMap(property) instanceof UnsupportedMapDB) ||
			(listing2.getPropertyMap(property) instanceof UnsupportedMapDB)) {
			return new AddressSet(); // ignore property that isn't supported.
		}
		return getCuiDiffs(property, addrs, new UserDefinedComparator(program1, program2, property),
			monitor);
	}

	/** Creates an address set indicating the differences between program1 and
	 * program2 of the specified type.
	 * @param diffType the type of difference to look for between the programs.
	 * @param addrs the addresses to check for differences.
	 * The addresses in this address set should be derived from program1.
	 * @param monitor the task monitor for indicating the progress of
	 * determining differences. This monitor reports the progress to the user.
	 * @return the address set indicating the differences.
	 * The addresses in this address set are derived from program1.
	 * @throws CancelledException if the user cancelled the Diff.
	 */
	synchronized public AddressSetView getTypeDiffs(int diffType, AddressSetView addrs,
			TaskMonitor monitor) throws ProgramConflictException, CancelledException {
		AddressSetView as = new AddressSet();
		monitor.setProgress(0);

		switch (diffType) {
			case ProgramDiffFilter.BYTE_DIFFS:
				monitorMsg = "Checking Byte Differences";
				monitor.setMessage(monitorMsg);
				as = getByteDifferences(addrs, monitor);
				break;
			case ProgramDiffFilter.CODE_UNIT_DIFFS:
				monitorMsg = "Checking Code Unit Differences";
				monitor.setMessage(monitorMsg);
				as = getCodeUnitDifferences(addrs, monitor);
				break;
			case ProgramDiffFilter.PROGRAM_CONTEXT_DIFFS:
				if (sameProgramContext) {
					monitorMsg = "Checking Program Context Differences";
					monitor.setMessage(monitorMsg);
					as = getProgramContextDifferences(addrs, monitor);
				}
				break;
			case ProgramDiffFilter.EOL_COMMENT_DIFFS:
				monitorMsg = "Checking End of Line Comment Differences";
				monitor.setMessage(monitorMsg);
				as = getCommentDiffs(CodeUnit.EOL_COMMENT, addrs,
					new CommentTypeComparator(program1, program2, CodeUnit.EOL_COMMENT), monitor);
				break;
			case ProgramDiffFilter.REPEATABLE_COMMENT_DIFFS:
				monitorMsg = "Checking Repeatable Comment Differences";
				monitor.setMessage(monitorMsg);
				as = getCommentDiffs(CodeUnit.REPEATABLE_COMMENT, addrs,
					new CommentTypeComparator(program1, program2, CodeUnit.REPEATABLE_COMMENT),
					monitor);
				break;
			case ProgramDiffFilter.PRE_COMMENT_DIFFS:
				monitorMsg = "Checking Pre-Comment Differences";
				monitor.setMessage(monitorMsg);
				as = getCommentDiffs(CodeUnit.PRE_COMMENT, addrs,
					new CommentTypeComparator(program1, program2, CodeUnit.PRE_COMMENT), monitor);
				break;
			case ProgramDiffFilter.POST_COMMENT_DIFFS:
				monitorMsg = "Checking Post-Comment Differences";
				monitor.setMessage(monitorMsg);
				as = getCommentDiffs(CodeUnit.POST_COMMENT, addrs,
					new CommentTypeComparator(program1, program2, CodeUnit.POST_COMMENT), monitor);
				break;
			case ProgramDiffFilter.PLATE_COMMENT_DIFFS:
				monitorMsg = "Checking Plate Comment Differences";
				monitor.setMessage(monitorMsg);
				as = getCommentDiffs(CodeUnit.PLATE_COMMENT, addrs,
					new CommentTypeComparator(program1, program2, CodeUnit.PLATE_COMMENT), monitor);
				break;
			case ProgramDiffFilter.REFERENCE_DIFFS:
				monitorMsg = "Checking Reference Differences";
				monitor.setMessage(monitorMsg);
				as = getReferenceDifferences(addrs, monitor);
				break;
			case ProgramDiffFilter.USER_DEFINED_DIFFS:
				monitorMsg = "Checking User Defined Property Differences";
				monitor.setMessage(monitorMsg);
				as = getUserDefinedDifferences(addrs, monitor);
				break;
			case ProgramDiffFilter.BOOKMARK_DIFFS:
				monitorMsg = "Checking Bookmark Differences";
				monitor.setMessage(monitorMsg);
				as = getBookmarkDifferences(addrs, monitor);
				break;
			case ProgramDiffFilter.SYMBOL_DIFFS:
				monitorMsg = "Checking Label Differences";
				monitor.setMessage(monitorMsg);
				as = getLabelDifferences(addrs, monitor);
				break;
			case ProgramDiffFilter.EQUATE_DIFFS:
				monitorMsg = "Checking Equate Differences";
				monitor.setMessage(monitorMsg);
				as = getEquateDifferences(addrs, monitor);
				break;
			case ProgramDiffFilter.FUNCTION_DIFFS:
				monitorMsg = "Checking Function Differences";
				monitor.setMessage(monitorMsg);
				as = getFunctionDifferences(addrs, monitor);
				break;
			case ProgramDiffFilter.FUNCTION_TAG_DIFFS:
				monitorMsg = "Checking Function Tag Differences";
				monitor.setMessage(monitorMsg);
				as = getFunctionTagDifferences(addrs, monitor);
				break;
		}
		return as;
	}

	/**
	 * Get the address set that the diff process is limited to when checking for differences.
	 * Returns null if the diff is not limited (i.e. the entire program is being diffed).
	 * The addresses in the returned address set are derived from program1.
	 */
	synchronized public AddressSetView getLimitedAddressSet() {
		return checkAddressSet;
	}

	/**
	 * Set the address set that the diff process is limited to when checking for differences.
	 * @param checkSet the set of addresses to limit checking. null indicates the entire program.
	 * The addresses in this address set should be derived from program1.
	 */
	synchronized void setLimitedAddressSet(AddressSetView checkSet) {
		this.checkAddressSet = getInCommonAddressSet(checkSet);
		diffAddrSets.clear();
		currentDiffs = new AddressSet();
		computeDiffsToReturn();
	}

	/**
	 * Get the address set that the getDifferences method results are restricted to.
	 * null indicates no current restrictions.
	 * The addresses in the returned address set are derived from program1.
	 */
	synchronized public AddressSetView getRestrictedAddressSet() {
		return restrictAddressSet;
	}

	/**
	 * Set the address set that the getDifferences method results are restricted to.
	 * @param restrictSet the address set to restrict results to. null indicates no restriction.
	 * The addresses in this address set should be derived from program1.
	 */
	synchronized void setRestrictedAddressSet(AddressSetView restrictSet) {
		this.restrictAddressSet = restrictSet;
		computeDiffsToReturn();
	}

	/**
	 * Removes the address set which was restricting the results of the getDifferences method.
	 */
	synchronized void removeRestrictedAddressSet() {
		this.restrictAddressSet = null;
		computeDiffsToReturn();
	}

	/**
	 * Get the address set that contains addresses that should not be indicated as
	 * having any differences.
	 * The addresses in this address set are derived from program1.
	 */
	synchronized public AddressSetView getIgnoreAddressSet() {
		return ignoreAddressSet;
	}

	/**
	 * Set the indicated additional addresses that should not report any
	 * differences that are found at them.
	 * @param addrs the set of addresses to add to the current ignore set.
	 * The addresses in this address set should be derived from program1.
	 */
	synchronized public void ignore(AddressSetView addrs) {
		ignoreAddressSet.add(addrs);
		if (diffsToReturn != null) {
			diffsToReturn.delete(addrs);
		}
	}

	/**
	 * Clear the set of addresses that are ignored. Ignored addresses will not
	 * have differences reported by the <CODE>getDifferences</CODE> call.
	 */
	synchronized void clearIgnoreAddressSet() {
		this.ignoreAddressSet.clear();
		computeDiffsToReturn();
	}

	private void computeDiffsToReturn() {
		diffsToReturn = new AddressSet(currentDiffs);
		if (!ignoreAddressSet.isEmpty()) {
			diffsToReturn.delete(ignoreAddressSet);
		}
		if ((restrictAddressSet != null) && !restrictAddressSet.isEmpty()) {
			diffsToReturn = diffsToReturn.intersect(restrictAddressSet);
		}
	}

	/**
	 * Returns whether the last <CODE>getDifferences</CODE> call was cancelled.
	 * If a TaskMonitor displays a progress dialog to the user, then the cancel
	 * button could have been pressed.
	 * @return true if the last <CODE>getDifferences</CODE> call was cancelled.
	 */
	synchronized public boolean isCancelled() {
		return cancelled;
	}

	/**
	 * Checks the task associated with the indicated monitor to determine if it has
	 * been canceled.
	 * @param monitor the task monitor, associated with getting differences from this Diff,
	 * to be checked
	 * @throws CancelledException if the getDifferences() task has been canceled by the user.
	 */
	synchronized public void checkCancelled(TaskMonitor monitor) throws CancelledException {
		if (cancelled) {
			throw new CancelledException();
		}
		if (monitor.isCancelled()) {
			monitor.setMessage("Cancelled Finding Differences");
			cancelled = true;
			throw new CancelledException();
		}
	}

	/**
	 * Print the differences that have been found so far by calls to
	 * <CODE>getDifferences</CODE>.
	 */
	synchronized public void printDifferences() {
		Msg.info(this, "");
		if (cancelled) {
			Msg.info(this, "\nThe last getDifferences was cancelled.");
			Msg.info(this, "Therefore the differences may be incomplete...");
		}
		printKnownDifferences(ProgramDiffFilter.ALL_DIFFS);
	}

	/**
	 * Print the differences matching the types indicated that were found thus
	 * far by all calls to <CODE>getDifferences</CODE>.
	 * @param type the type(s) of differences we want to see.
	 * Valid types are: BYTE_DIFFS, CODE_UNIT_DIFFS,
	 * COMMENT_DIFFS, REFERENCE_DIFFS, USER_DEFINED_DIFFS,
	 * SYMBOL_DIFFS, EQUATE_DIFFS, PROGRAM_CONTEXT_DIFFS.
	 */
	synchronized public void printKnownDifferences(int type) {
		Msg.info(this, "\n" + ProgramDiffFilter.typeToName(type) + " differences:");
		AddressSet diffs = new AddressSet();
		int[] pt = ProgramDiffFilter.getPrimaryTypes();
		for (int element : pt) {
			AddressSet as = diffAddrSets.get(new Integer(element));
			diffs.add(as);
		}
		AddressRangeIterator iter = diffs.getAddressRanges();
		while (iter.hasNext()) {
			Msg.info(this, "  " + iter.next());
		}
	}

	/**
	 * Print the differences matching the types indicated that were found thus
	 * far by all calls to getDifferences. The differences are grouped by
	 * each of the primary difference types.
	 * @param type the type(s) of differences we want to see.
	 * Valid types are: BYTE_DIFFS, CODE_UNIT_DIFFS,
	 * COMMENT_DIFFS, REFERENCE_DIFFS, USER_DEFINED_DIFFS,
	 * SYMBOL_DIFFS, EQUATE_DIFFS, PROGRAM_CONTEXT_DIFFS.
	 */
	synchronized public void printKnownDifferencesByType(int type) {
		int[] pt = ProgramDiffFilter.getPrimaryTypes();
		for (int element : pt) {
			Msg.info(this, "\n" + ProgramDiffFilter.typeToName(element) + " differences:");
			AddressSet as = diffAddrSets.get(new Integer(element));
			if (as != null) {
				AddressRangeIterator iter = as.getAddressRanges();
				while (iter.hasNext()) {
					Msg.info(this, "  " + iter.next());
				}
			}
		}
	}

	/** Creates an address set indicating the differences between program1 and
	 * program2 of the specified type.
	 * The addresses in this address set are derived from program1
	 * and put into diffAddrSets using the diffType number as an index.
	 * @param diffType the type of difference to look for between the programs.
	 * @param monitor the task monitor for indicating the progress of
	 * determining differences. This monitor reports the progress to the user.
	 * @throws ProgramConflictException if the two programs are not comparable since registers differ.
	 * @throws CancelledException if the user cancelled the Diff.
	 */
	private void createAddressSet(int diffType, TaskMonitor monitor)
			throws ProgramConflictException, CancelledException {

		AddressSet as = null; // This address set should be derived from program1.

		switch (diffType) {
			case ProgramDiffFilter.BYTE_DIFFS:
				monitorMsg = "Checking Byte Differences";
				monitor.setMessage(monitorMsg);
				//                as = getByteDifferences(pgmMemComp.inOneMatchingTwo(),
				//                                        pgmMemComp.inTwoMatchingOne());
				as = getByteDifferences(checkAddressSet, monitor);
				break;
			case ProgramDiffFilter.CODE_UNIT_DIFFS:
				monitorMsg = "Checking Code Unit Differences";
				monitor.setMessage(monitorMsg);
				as = getCodeUnitDifferences(checkAddressSet, monitor);
				break;
			case ProgramDiffFilter.PROGRAM_CONTEXT_DIFFS:
				if (sameProgramContext) {
					monitorMsg = "Checking Program Context Differences";
					monitor.setMessage(monitorMsg);
					as = getProgramContextDifferences(checkAddressSet, monitor);
				}
				break;
			case ProgramDiffFilter.EOL_COMMENT_DIFFS:
				monitorMsg = "Checking End of Line Comment Differences";
				monitor.setMessage(monitorMsg);
				as = getCommentDiffs(CodeUnit.EOL_COMMENT, checkAddressSet,
					new CommentTypeComparator(program1, program2, CodeUnit.EOL_COMMENT), monitor);
				break;
			case ProgramDiffFilter.REPEATABLE_COMMENT_DIFFS:
				monitorMsg = "Checking Repeatable Comment Differences";
				monitor.setMessage(monitorMsg);
				as = getCommentDiffs(CodeUnit.REPEATABLE_COMMENT, checkAddressSet,
					new CommentTypeComparator(program1, program2, CodeUnit.REPEATABLE_COMMENT),
					monitor);
				break;
			case ProgramDiffFilter.PRE_COMMENT_DIFFS:
				monitorMsg = "Checking Pre-Comment Differences";
				monitor.setMessage(monitorMsg);
				as = getCommentDiffs(CodeUnit.PRE_COMMENT, checkAddressSet,
					new CommentTypeComparator(program1, program2, CodeUnit.PRE_COMMENT), monitor);
				break;
			case ProgramDiffFilter.POST_COMMENT_DIFFS:
				monitorMsg = "Checking Post-Comment Differences";
				monitor.setMessage(monitorMsg);
				as = getCommentDiffs(CodeUnit.POST_COMMENT, checkAddressSet,
					new CommentTypeComparator(program1, program2, CodeUnit.POST_COMMENT), monitor);
				break;
			case ProgramDiffFilter.PLATE_COMMENT_DIFFS:
				monitorMsg = "Checking Plate Comment Differences";
				monitor.setMessage(monitorMsg);
				as = getCommentDiffs(CodeUnit.PLATE_COMMENT, checkAddressSet,
					new CommentTypeComparator(program1, program2, CodeUnit.PLATE_COMMENT), monitor);
				break;
			case ProgramDiffFilter.REFERENCE_DIFFS:
				monitorMsg = "Checking Reference Differences";
				monitor.setMessage(monitorMsg);
				as = getReferenceDifferences(checkAddressSet, monitor);
				break;
			case ProgramDiffFilter.USER_DEFINED_DIFFS:
				monitorMsg = "Checking User Defined Property Differences";
				monitor.setMessage(monitorMsg);
				as = getUserDefinedDifferences(checkAddressSet, monitor);
				break;
			case ProgramDiffFilter.BOOKMARK_DIFFS:
				monitorMsg = "Checking Bookmark Differences";
				monitor.setMessage(monitorMsg);
				as = getBookmarkDifferences(checkAddressSet, monitor);
				break;
			case ProgramDiffFilter.SYMBOL_DIFFS:
				monitorMsg = "Checking Label Differences";
				monitor.setMessage(monitorMsg);
				as = getLabelDifferences(checkAddressSet, monitor);
				break;
			case ProgramDiffFilter.EQUATE_DIFFS:
				monitor.setMessage("Checking Equate Differences");
				monitor.setMessage(monitorMsg);
				as = getEquateDifferences(checkAddressSet, monitor);
				break;
			case ProgramDiffFilter.FUNCTION_DIFFS:
				monitorMsg = "Checking Function Differences";
				monitor.setMessage(monitorMsg);
				as = getFunctionDifferences(checkAddressSet, monitor);
				break;
			case ProgramDiffFilter.FUNCTION_TAG_DIFFS:
				monitorMsg = "Checking Function Tag Differences";
				monitor.setMessage(monitorMsg);
				as = getFunctionTagDifferences(checkAddressSet, monitor);
				break;
		}
		if (as != null) {
			diffAddrSets.put(new Integer(diffType), as);
		}
	}

	///////////////////////////
	// DIFFERENCE METHODS
	///////////////////////////
	private void compareBytes(AddressRange limitedRange, AddressSet differences,
			TaskMonitor monitor) throws MemoryAccessException, CancelledException {

		Memory mem1 = program1.getMemory();
		Memory mem2 = program2.getMemory();
		byte[] temp1 = new byte[BYTE_DIFF_GRAB_SIZE];
		byte[] temp2 = new byte[BYTE_DIFF_GRAB_SIZE];
		int nBytes;
		Address min = limitedRange.getMinAddress();
		Address max = limitedRange.getMaxAddress();
		Address addr = min;
		Address addr2 = SimpleDiffUtility.getCompatibleAddress(program1, addr, program2);
		Address endAddr = max;
		int addressSize = min.getAddressSpace().getAddressableUnitSize();
		// There may be multiple blocks that make up the range in each memory.
		do {
			MemoryBlock b1 = mem1.getBlock(addr);
			Address addrCompatibleWith2 =
				SimpleDiffUtility.getCompatibleAddress(program1, addr, program2);
			MemoryBlock b2 = mem2.getBlock(addrCompatibleWith2);
//			if (addr instanceof SegmentedAddress) {
//				int segment = ((SegmentedAddress)b1.getStart()).getSegment();
//				addr = ((SegmentedAddress)addr).normalize(segment);
//			}
			Address b1End = b1.getEnd();
			Address b2End = b2.getEnd();
			Address b2EndCompatibleWith1 =
				SimpleDiffUtility.getCompatibleAddress(program2, b2End, program1);
			// endAddr will hold the end address for checking the current blocks.
			endAddr = (b1End.compareTo(max) < 0) ? b1End : max;
			if (b2EndCompatibleWith1 != null) {
				endAddr =
					(b2EndCompatibleWith1.compareTo(endAddr) < 0) ? b2EndCompatibleWith1 : endAddr;
			}
			long size = endAddr.subtract(addr) + 1;
			for (int index = 0; index < size; index += nBytes) {
				int bytesToGet = (int) Math.min((size - index), BYTE_DIFF_GRAB_SIZE);
				int n1 = b1.getBytes(addr, temp1, 0, bytesToGet);
				int n2 = b2.getBytes(addr2, temp2, 0, bytesToGet);
				nBytes = Math.min(n1, n2);
				Address start = null;
				boolean same = true;
				for (int i = 0; i < nBytes; i++) {
					if (temp1[i] != temp2[i]) {
						if (same) {
							same = false;
							start = addr.addWrap(i);
						}
//						Address byteAddr = addr.addWrap(i);
//						if (!differences.contains(byteAddr)) {
//							CodeUnit cu1 = listing1.getCodeUnitContaining(byteAddr);
//							CodeUnit cu2 = listing2.getCodeUnitContaining(byteAddr);
//							Address min1 = cu1.getMinAddress();
//							Address min2 = cu2.getMinAddress();
//							Address max1 = cu1.getMaxAddress();
//							Address max2 = cu2.getMaxAddress();
//							Address addrMin =
//								min1.compareTo(min2) < 0 ? min1 : min2;
//							Address addrMax =
//								max1.compareTo(max2) > 0 ? max1 : max2;
//							differences.addRange(addrMin, addrMax);
//						}
					}
					else {
						if (!same) {
							same = true;
							differences.addRange(start, addr.addWrap(i - 1));
						}
					}
				}
				if (!same) {
					same = true;
					differences.addRange(start, addr.addWrap(nBytes - 1));
				}
				monitor.setProgress(monitor.getProgress() + (nBytes / addressSize));
				monitor.setMessage(monitorMsg + ": " + addr.toString(showAddressSpace));
				try {
					addr = addr.addNoWrap(nBytes);
					addr2 = SimpleDiffUtility.getCompatibleAddress(program1, addr, program2);
				}
				catch (AddressOverflowException e) {
					// Do nothing.
				}
				checkCancelled(monitor);
			}
			checkCancelled(monitor);
		}
		while (endAddr.compareTo(max) < 0);
	}

	/** Determines the addresses within the two programs where bytes differ.
	 * If a byte difference is found, the entire code unit is added to the address set.
	 * This also indicates addresses in program1 that are not in program2 as well as
	 * program2 addresses that are compatible with program1 but not in program1 memory.
	 *
	 * @param addrs the addresses to check for differences.
	 * The addresses in this address set should be derived from program1.
	 * @param monitor the task monitor for indicating the progress of
	 * determining differences. This monitor reports the progress to the user.
	 * @return the addresses where there were different byte values including where
	 * one program has bytes and the other does not.
	 * The addresses in this address set are derived from program1.
	 * @throws CancelledException if the user canceled the Diff.
	 */
	private AddressSet getByteDifferences(AddressSetView addrs, TaskMonitor monitor)
			throws CancelledException {
		AddressSet differences = new AddressSet();

		differences.add(getNonCommonAddressSet(addrs));
		differences.add(getInitializationDiffersAddressSet(addrs));

		// Check each address range from the address set for differences.
		AddressSet inCommon = getAddressesInCommon();
		if (addrs != null) {
			inCommon = inCommon.intersect(addrs);
		}
		monitor.initialize(inCommon.getNumAddresses());
		AddressRangeIterator iter = inCommon.getAddressRanges();
		while (iter.hasNext()) {
			AddressRange range = iter.next();
			try {
				compareBytes(range, differences, monitor);
			}
			catch (MemoryAccessException e) {
				// Do nothing. Shouldn't happen. Both should have bytes.
			}
			checkCancelled(monitor);
		}
		checkCancelled(monitor);
		return differences;
	}

	/** Determines the addresses for the code units that differ between program1
	 * and program2.
	 *
	 * @param addrs the addresses to check for differences.
	 * The addresses in this address set should be derived from program1.
	 * @param monitor the task monitor for indicating the progress of
	 * determining differences. This monitor reports the progress to the user.
	 *
	 * @return the addresses where there were different code units.
	 * The addresses in this address set are derived from program1.
	 * @throws CancelledException if the user cancelled the Diff.
	 */
	private AddressSet getCodeUnitDifferences(AddressSetView addrs, TaskMonitor monitor)
			throws CancelledException {

		AddressSet differences = new AddressSet();
		// Get the instruction differences.
		monitorMsg = "Checking Instruction Differences";
		AddressSet instrDiffs = getAdjustedCuiDiffs(CodeUnit.INSTRUCTION_PROPERTY, addrs,
			new InstructionComparator(program1, program2), monitor);
		instrDiffs = instrDiffs.intersect(pgmMemComp.getAddressesInCommon());
		differences.add(instrDiffs);
		// Get the defined data differences.
		monitorMsg = "Checking Defined Data Differences";
		AddressSet dataDiffs = getAdjustedCuiDiffs(CodeUnit.DEFINED_DATA_PROPERTY, addrs,
			new DefinedDataComparator(program1, program2), monitor);
		differences.add(dataDiffs);
		AddressSet contextRegDifferences = getContextRegisterDifferences(addrs, monitor);
		differences.add(contextRegDifferences);
		return differences;
	}

	/** Gets the addresses where the Program Context (register bits) differ
	 * between two programs.
	 *
	 * @param addressSet the addresses to check for differences.
	 * The addresses in this address set should be derived from program1.
	 * @param monitor the task monitor for indicating the progress of
	 * determining differences. This monitor reports the progress to the user.
	 *
	 * @return the addresses of code units where the program context (register
	 * bits values) differs.
	 * The addresses in this address set are derived from program1.
	 *
	 * @throws ProgramConflictException if the two programs are not comparable since registers differ.
	 * @throws CancelledException if the user cancelled the Diff.
	 */
	private AddressSet getProgramContextDifferences(AddressSetView addressSet, TaskMonitor monitor)
			throws ProgramConflictException, CancelledException {
		AddressSet differences = new AddressSet();

		if (!ProgramMemoryComparator.sameProgramContextRegisterNames(program1, program2)) {
			throw new ProgramConflictException(
				"Program Context Registers don't match between the programs.");
		}

		// Check each address range from the address set for differences.
		AddressSet inCommon = pgmMemComp.getAddressesInCommon();
		addressSet = (addressSet != null) ? inCommon.intersect(addressSet) : inCommon;

		ProgramContext pc1 = program1.getProgramContext();
		ProgramContext pc2 = program2.getProgramContext();

		for (String element : pc1.getRegisterNames()) {
			monitor.checkCanceled();
			Register rb1 = pc1.getRegister(element);
			Register rb2 = pc2.getRegister(element);
			if (rb1.isProcessorContext() || rb2.isProcessorContext()) {
				continue; // context handled with CodeUnit differencing
			}
			Register p1 = rb1.getParentRegister();
			Register p2 = rb2.getParentRegister();
			if (p1 != null && p2 != null && p1.getName().equals(p2.getName())) {
				continue;
			}

			getProgramContextDifferences(pc1, rb1, pc2, rb2, addressSet, differences, monitor);
		}
		return differences;
	}

	/** Gets the addresses where the Program Context (register bits) differ
	 * between two programs for the specified registers (which should generally match).
	 *
	 * @param pc1 program context for 1st program
	 * @param reg1 register corresponding to pc1 (should generally be the same as reg2)
	 * @param pc2 program context for 2nd program
	 * @param reg2 register corresponding to pc2 (should generally be the same as reg1)
	 * @param addressSet the addresses (in common to both programs) to check for differences.
	 * The addresses in this address set should be derived from program1.
	 * @param differences the addresses of code units where the register value differs will be
	 * added to this set. The addresses in this address set are derived from the 1st program.
	 * @param monitor the task monitor for indicating the progress of
	 * determining differences. This monitor reports the progress to the user.
	 *
	 * @throws ProgramConflictException if the two programs can't are not comparable.
	 * @throws CancelledException if the user cancelled the Diff.
	 */
	private void getProgramContextDifferences(ProgramContext pc1, Register reg1, ProgramContext pc2,
			Register reg2, AddressSetView addressSet, AddressSet differences, TaskMonitor monitor)
			throws CancelledException {
		AddressRangeIterator iter = addressSet.getAddressRanges();
		while (iter.hasNext()) {
			monitor.checkCanceled();
			AddressRange range = iter.next();
			Address min = range.getMinAddress();
			Address max = range.getMaxAddress();
			monitor.setMessage("Checking Program Context Differences: " + reg1.getName() + " @ " +
				min.toString(true));
			Address min2 = SimpleDiffUtility.getCompatibleAddress(program1, min, program2);
			Address max2 = SimpleDiffUtility.getCompatibleAddress(program1, max, program2);

			AddressRangeIterator it1 = pc1.getRegisterValueAddressRanges(reg1, min, max);
			AddressRangeIterator it2 = pc2.getRegisterValueAddressRanges(reg2, min2, max2);
			AddressRangeIteratorConverter convertedIt2 =
				new AddressRangeIteratorConverter(it2, program1);
			AddressRangeIterator p1CombinedIterator =
				new CombinedAddressRangeIterator(it1, convertedIt2);

			while (p1CombinedIterator.hasNext()) {
				monitor.checkCanceled();
				AddressRange addrRange = p1CombinedIterator.next();
				Address rangeMin1 = addrRange.getMinAddress();
				Address rangeMin2 =
					SimpleDiffUtility.getCompatibleAddress(program1, rangeMin1, program2);
				RegisterValue value1 = pc1.getRegisterValue(reg1, rangeMin1);
				RegisterValue value2 = pc2.getRegisterValue(reg2, rangeMin2);
				boolean sameValue;
				if (value1 == null || value2 == null) {
					sameValue = (value1 == value2);
				}
				else {
					sameValue = Arrays.equals(value1.toBytes(), value2.toBytes());
				}
				if (!sameValue) {
					differences.addRange(addrRange.getMinAddress(), addrRange.getMaxAddress());
				}
			}
		}
	}

	/** Gets the addresses where the context-register value differs
	 * between two programs.
	 *
	 * @param addressSet the addresses to check for differences.
	 * The addresses in this address set should be derived from program1.
	 * @param monitor the task monitor for indicating the progress of
	 * determining differences. This monitor reports the progress to the user.
	 *
	 * @return the addresses of code units where the program context (register
	 * bits values) differs.
	 * The addresses in this address set are derived from program1.
	 *
	 * @throws ProgramConflictException if the two programs can't are not comparable.
	 * @throws CancelledException if the user cancelled the Diff.
	 */
	private AddressSet getContextRegisterDifferences(AddressSetView addressSet, TaskMonitor monitor)
			throws CancelledException {
		AddressSet differences = new AddressSet();
		ProgramContext pc1 = program1.getProgramContext();
		ProgramContext pc2 = program2.getProgramContext();
		Register contextReg1 = pc1.getBaseContextRegister();
		Register contextReg2 = pc2.getBaseContextRegister();
		if (contextReg1 != null && contextReg2 != null) {
			AddressSet inCommon = pgmMemComp.getAddressesInCommon();
			addressSet = (addressSet != null) ? inCommon.intersect(addressSet) : inCommon;
			getProgramContextDifferences(pc1, pc1.getBaseContextRegister(), pc2,
				pc2.getBaseContextRegister(), addressSet, differences, monitor);
		}
		return differences;
	}

	/** Gets the addresses where the user defined properties differ between
	 * two programs.
	 *
	 * @param addressSet the addresses to check for differences.
	 * The addresses in this address set should be derived from program1.
	 * @param monitor the task monitor for indicating the progress of
	 * determining differences. This monitor reports the progress to the user.
	 *
	 * @return the addresses of code units where the user defined properties differed.
	 * The addresses in this address set are derived from program1.
	 * @throws CancelledException if the user cancelled the Diff.
	 */
	private AddressSet getUserDefinedDifferences(AddressSetView addressSet, TaskMonitor monitor)
			throws CancelledException {
		AddressSet differences = new AddressSet();
		Iterator<String> props1 = listing1.getUserDefinedProperties();
		Iterator<String> props2 = listing2.getUserDefinedProperties();
		// Combine the 2 property lists into 1 for use with our comparator.
		ArrayList<String> list = new ArrayList<>();
		while (props1.hasNext()) {
			list.add(props1.next());
		}
		while (props2.hasNext()) {
			String propName = props2.next();
			// Only add the names we don't have yet.
			if (!list.contains(propName)) {
				list.add(propName);
			}
		}
		int numProps = list.size();
		for (int i = 0; i < numProps; i++) {
			String property = list.get(i);
			if (property.equals("Bookmarks")) {
				continue; // ignore bookmarks as properties, since the bookmark diff gets these.
			}
			// Handle case where the class for a Saveable property is missing.
			if ((listing1.getPropertyMap(property) instanceof UnsupportedMapDB) ||
				(listing2.getPropertyMap(property) instanceof UnsupportedMapDB)) {
				continue; // ignore property that isn't supported.
			}
			// Get the differences for each user defined property type.
			differences.add(getCuiDiffs(property, addressSet,
				new UserDefinedComparator(program1, program2, property), monitor));
		}
		return differences;
	}

	/** Gets the addresses where bookmarks differ between two programs.
	 *
	 * @param addressSet the addresses to check for differences.
	 * The addresses in this address set should be derived from program1.
	 * @param monitor the task monitor for indicating the progress of
	 * determining differences. This monitor reports the progress to the user.
	 *
	 * @return the addresses of code units where the user defined properties differed.
	 * The addresses in this address set are derived from program1.
	 * @throws CancelledException if the user cancelled the Diff.
	 */
	private AddressSet getBookmarkDifferences(AddressSetView addressSet, TaskMonitor monitor)
			throws CancelledException {
		AddressSet differences = new AddressSet();
		BookmarkManager bookmarkMgr1 = program1.getBookmarkManager();
		BookmarkManager bookmarkMgr2 = program2.getBookmarkManager();
		BookmarkType[] types1 = bookmarkMgr1.getBookmarkTypes();
		BookmarkType[] types2 = bookmarkMgr2.getBookmarkTypes();
		Arrays.sort(types1, BOOKMARK_TYPE_COMPARATOR);
		Arrays.sort(types2, BOOKMARK_TYPE_COMPARATOR);
		ArrayList<BookmarkType> list = new ArrayList<>();
		for (BookmarkType element : types1) {
			list.add(element);
		}

		for (BookmarkType element : types2) {
			boolean found = false;
			for (BookmarkType type : list) {
				if (element.getTypeString().compareTo(type.getTypeString()) == 0) {
					found = true;
					break;
				}
			}
			if (!found) {
				list.add(element);
			}
		}

		AddressSet addressSet2 = DiffUtility.getCompatibleAddressSet(addressSet, program2);
		int numTypes = list.size();
		AddressSet[] sets = new AddressSet[numTypes];
		for (int i = 0; i < numTypes; i++) {
			BookmarkType type = list.get(i);
			AddressSetView addrs1 = bookmarkMgr1.getBookmarkAddresses(type.getTypeString());
			AddressSetView addrs2 = bookmarkMgr2.getBookmarkAddresses(type.getTypeString());
			addrs1 = addrs1.intersect(addressSet);
			addrs2 = addrs2.intersect(addressSet2);
			// Get the differences for each bookmark type.
			sets[i] = getObjectDiffs(new BookmarksComparator(type, program1, program2),
				new IteratorWrapper(addrs1.getAddresses(true)),
				new IteratorWrapper(addrs2.getAddresses(true)), monitor);
			differences.add(sets[i]);
		}
		return differences;
	}

	/** Determines the addresses where program1 and program2 have different
	 *  labels (symbols or aliases) specified.
	 * @param addressSet the addresses to check for differences.
	 * The addresses in this address set should be derived from program1.
	 * @param monitor the task monitor for indicating the progress of
	 * determining differences. This monitor reports the progress to the user.
	 *
	 * @return the addresses where there were different labels.
	 * The addresses in this address set are derived from program1.
	 * @throws CancelledException if the user cancelled the Diff.
	 */
	private AddressSet getLabelDifferences(AddressSetView addressSet, TaskMonitor monitor)
			throws CancelledException {
		SymbolIterator iter1;
		SymbolIterator iter2;
		if (addressSet == null) {
			iter1 = program1.getSymbolTable().getPrimarySymbolIterator(true);
			iter2 = program2.getSymbolTable().getPrimarySymbolIterator(true);
		}
		else {
			iter1 = program1.getSymbolTable().getPrimarySymbolIterator(addressSet, true);
			AddressSet addressSet2 = DiffUtility.getCompatibleAddressSet(addressSet, program2);
			iter2 = program2.getSymbolTable().getPrimarySymbolIterator(addressSet2, true);
		}
		// Symbols
		return getObjectDiffs(new SymbolComparator(program1, program2), new IteratorWrapper(iter1),
			new IteratorWrapper(iter2), monitor);
	}

	/** Determines the addresses where program1 and program2 have different equates
	 * specified.
	 * @param addressSet the addresses to check for differences.
	 * The addresses in this address set should be derived from program1.
	 * @param monitor the task monitor for indicating the progress of
	 * determining differences. This monitor reports the progress to the user.
	 * @return the addresses where the equates differed between program1 and program2.
	 * The addresses in this address set are derived from program1.
	 * @throws CancelledException if the user cancelled the Diff.
	 */
	private AddressSet getEquateDifferences(AddressSetView addressSet, TaskMonitor monitor)
			throws CancelledException {
		AddressIterator iter1;
		AddressIterator iter2;
		if (addressSet == null) {
			iter1 = program1.getEquateTable().getEquateAddresses();
			iter2 = program2.getEquateTable().getEquateAddresses();
		}
		else {
			iter1 = program1.getEquateTable().getEquateAddresses(addressSet);
			AddressSet addressSet2 = DiffUtility.getCompatibleAddressSet(addressSet, program2);
			iter2 = program2.getEquateTable().getEquateAddresses(addressSet2);
		}
		return getObjectDiffs(new EquateComparator(program1, program2), new IteratorWrapper(iter1),
			new IteratorWrapper(iter2), monitor);
	}

	/**
	 * Determines if the two programs have the same equates specified at
	 * the indicated address and operand
	 * @param address the address
	 * This address should be derived from program1.
	 * @param opIndex the operand index
	 * @return true if both programs have the same operands.
	 */
	public boolean isSameOperandEquates(Address address, int opIndex) {
		EquateTable et1 = program1.getEquateTable();
		EquateTable et2 = program2.getEquateTable();
		List<Equate> l1 = et1.getEquates(address, opIndex);
		Address address2 = SimpleDiffUtility.getCompatibleAddress(program1, address, program2);
		List<Equate> l2 = et2.getEquates(address2, opIndex);
		int len1 = l1.size();
		if (len1 != l2.size()) {
			return false;
		}
		for (int i = 0; i < len1; i++) {
			Equate e1 = l1.get(i);
			Equate e2 = l2.get(i);
			if (!e1.equals(e2)) {
				return false;
			}
		}
		return true;
	}

	/** Determines the addresses where program1 and program2 have different
	 * references specified.
	 * @param addressSet the addresses to check for differences.
	 * The addresses in this address set should be derived from program1.
	 * @param monitor the task monitor for indicating the progress of
	 * determining differences. This monitor reports the progress to the user.
	 * @return the addresses where the memory references differed between program1 and program2.
	 * The addresses in this address set are derived from program1.
	 * @throws CancelledException if the user cancelled the Diff.
	 */
	private AddressSet getReferenceDifferences(AddressSetView addressSet, TaskMonitor monitor)
			throws CancelledException {
		AddressIterator iter1;
		AddressIterator iter2;
		ReferenceManager rm1 = program1.getReferenceManager();
		ReferenceManager rm2 = program2.getReferenceManager();

		if (addressSet == null) {
			iter1 = rm1.getReferenceSourceIterator(program1.getMinAddress(), true);
			iter2 = rm2.getReferenceSourceIterator(program2.getMinAddress(), true);
		}
		else {
			iter1 = rm1.getReferenceSourceIterator(addressSet, true);
			AddressSet addressSet2 = DiffUtility.getCompatibleAddressSet(addressSet, program2);
			iter2 = rm2.getReferenceSourceIterator(addressSet2, true);
		}
		AddressSet addrs = getObjectDiffs(new ReferenceComparator(program1, program2),
			new IteratorWrapper(iter1), new IteratorWrapper(iter2), monitor);
		return addrs.intersect(pgmMemComp.getSameMemTypeAddressesInCommon());
	}

	/** Determines the addresses where program1 and program2 have different
	 * function information specified. This may be the signature, comment,
	 * stack variables, or register variables.
	 * @param addressSet the addresses to check for differences.
	 * The addresses in this address set should be derived from program1.
	 * @param monitor the task monitor for indicating the progress of
	 * determining differences. This monitor reports the progress to the user.
	 * @return the addresses where the equates differed between program1 and program2.
	 * The addresses in this address set are derived from program1.
	 * @throws CancelledException if the user cancelled the Diff.
	 */
	private AddressSet getFunctionDifferences(AddressSetView addressSet, TaskMonitor monitor)
			throws CancelledException {
		FunctionIterator iter1;
		FunctionIterator iter2;
		if (addressSet == null) {
			iter1 = program1.getListing().getFunctions(true);
			iter2 = program2.getListing().getFunctions(true);
		}
		else {
			iter1 = program1.getListing().getFunctions(addressSet, true);
			AddressSet addressSet2 = DiffUtility.getCompatibleAddressSet(addressSet, program2);
			iter2 = program2.getListing().getFunctions(addressSet2, true);
		}
		return getObjectDiffs(new FunctionComparator(program1, program2),
			new IteratorWrapper(iter1), new IteratorWrapper(iter2), monitor);
	}

	/**
	 * Returns the function start addresses of all functions where there is a difference
	 * in tags between program 1 and program 2.
	 *
	 * @param addressSet
	 * @param monitor
	 * @return
	 * @throws CancelledException
	 */
	private AddressSet getFunctionTagDifferences(AddressSetView addressSet, TaskMonitor monitor)
			throws CancelledException {

		FunctionIterator iter1 = program1.getListing().getFunctions(addressSet, true);
		AddressSet addressSet2 = DiffUtility.getCompatibleAddressSet(addressSet, program2);
		FunctionIterator iter2 = program2.getListing().getFunctions(addressSet2, true);
		return getObjectDiffs(new FunctionTagComparator(program1, program2),
			new IteratorWrapper(iter1), new IteratorWrapper(iter2), monitor);
	}

	/////////////////////////////////////////
	// Generic methods.
	/////////////////////////////////////////
	/** Determines the code unit addresses where there are differences of the
	 * indicated type between program1 and program2.
	 * @param cuiType the type of difference on the code unit. These are defined
	 * in <CODE>CodeUnit</CODE>. (i.e. CodeUnit.EOL_COMMENT_PROPERTY).
	 * @param addressSet the addresses to check for differences.
	 * The addresses in this address set should be derived from program1.
	 * @param c the comparator to use for determining where the differences are.
	 * @param monitor the task monitor for indicating the progress of
	 * determining differences. This monitor reports the progress to the user.
	 *
	 * @return the addresses where there were code unit differences of the
	 * specified type.
	 * The addresses in this address set are derived from program1.
	 * @throws CancelledException if the user cancelled the Diff.
	 * @see ghidra.program.model.listing.CodeUnit
	 */
	private AddressSet getCuiDiffs(String cuiType, AddressSetView addressSet, CodeUnitComparator c,
			TaskMonitor monitor) throws CancelledException {
		CodeUnitIterator iter1 = listing1.getCodeUnitIterator(cuiType, addressSet, true);
		AddressSet addressSet2 = DiffUtility.getCompatibleAddressSet(addressSet, program2);
		CodeUnitIterator iter2 = listing2.getCodeUnitIterator(cuiType, addressSet2, true);
		return getObjectDiffs(c, new IteratorWrapper(iter1), new IteratorWrapper(iter2), monitor);
	}

	/** Determines the code unit addresses where there are comment differences of the
	 * indicated type between program1 and program2.
	 * @param commentType the type of comment. These are defined
	 * in <CODE>CodeUnit</CODE>. (i.e. CodeUnit.EOL_COMMENT).
	 * @param addressSet the addresses to check for differences.
	 * The addresses in this address set should be derived from program1.
	 * @param c the comparator to use for determining where the differences are.
	 * @param monitor the task monitor for indicating the progress of
	 * determining differences. This monitor reports the progress to the user.
	 *
	 * @return the addresses where there were code unit differences of the
	 * specified type.
	 * The addresses in this address set are derived from program1.
	 * @throws CancelledException if the user cancelled the Diff.
	 * @see ghidra.program.model.listing.CodeUnit
	 */
	private AddressSet getCommentDiffs(int commentType, AddressSetView addressSet,
			CommentTypeComparator c, TaskMonitor monitor) throws CancelledException {
		AddressIterator iter1 = listing1.getCommentAddressIterator(commentType, addressSet, true);
		AddressSet addressSet2 = DiffUtility.getCompatibleAddressSet(addressSet, program2);
		AddressIterator iter2 = listing2.getCommentAddressIterator(commentType, addressSet2, true);
		return getObjectDiffs(c, new IteratorWrapper(iter1), new IteratorWrapper(iter2), monitor);
	}

	/** Determines the code unit addresses where there are differences of the
	 * indicated type between program1 and program2. If address ranges in the
	 * address set begin inside a code unit instead of at the beginning, the
	 * entire code unit will be added to the address set.
	 * @param cuiType the type of difference on the code unit. These are defined
	 * in <CODE>CodeUnit</CODE>. (i.e. CodeUnit.EOL_COMMENT_PROPERTY).
	 * @param addressSet the addresses to check for differences.
	 * The addresses in this address set should be derived from program1.
	 * @param c the comparator to use for determining where the differences are.
	 * @param monitor the task monitor for indicating the progress of
	 * determining differences. This monitor reports the progress to the user.
	 *
	 * @return the addresses where there were code unit differences of the
	 * specified type.
	 * The addresses in this address set are derived from program1.
	 * @throws CancelledException if the user cancelled the Diff.
	 * @see ghidra.program.model.listing.CodeUnit
	 */
	private AddressSet getAdjustedCuiDiffs(String cuiType, AddressSetView addressSet,
			CodeUnitComparator c, TaskMonitor monitor) throws CancelledException {
		// Check each address range from the address set for differences.
		AddressSet inCommon;
		inCommon = pgmMemComp.getAddressesInCommon();
		if (addressSet != null) {
			inCommon = inCommon.intersect(addressSet);
		}
		AddressSet as1 = adjustCodeUnitAddressSet(inCommon, listing1, monitor);
		CodeUnitIterator iter1 = listing1.getCodeUnitIterator(cuiType, as1, true);
		AddressSet inCommonFrom2 = DiffUtility.getCompatibleAddressSet(inCommon, program2);
		AddressSet as2 = adjustCodeUnitAddressSet(inCommonFrom2, listing2, monitor);
		CodeUnitIterator iter2 = listing2.getCodeUnitIterator(cuiType, as2, true);
		return getObjectDiffs(c, new IteratorWrapper(iter1), new IteratorWrapper(iter2), monitor);
	}

	/**
	 * adjustCodeUnitAddressSet creates a new address set from the initial
	 * address set by adjusting the address ranges so that they contain
	 * complete code units as indicated by the program listing.
	 * @param initialAddressSet the initial address set
	 * The addresses in this address set should be derived from the program
	 * passed as a parameter.
	 * @param program the program to get the code units from.
	 * @return the new address set
	 * The addresses in this address set are derived from the program
	 * that was passed as a parameter.
	 * @throws CancelledException
	 */
	private AddressSet adjustCodeUnitAddressSet(AddressSetView initialAddressSet, Listing listing,
			TaskMonitor monitor) throws CancelledException {

		if (initialAddressSet == null) {
			return null;
		}
		monitor.initialize(initialAddressSet.getNumAddressRanges());
		int count = 0;
		AddressSet tmpAddrSet = new AddressSet();
		AddressRangeIterator iter = initialAddressSet.getAddressRanges();
		while (iter.hasNext()) {
			monitor.checkCanceled();
			AddressRange range = iter.next();
			Address minAddr = range.getMinAddress();
			Address maxAddr = range.getMaxAddress();
			monitor.setMessage(
				monitorMsg + ": " + "Adjusting code unit set @ " + minAddr.toString() + ".");
			CodeUnit cu;
			cu = listing.getCodeUnitContaining(minAddr);
			if (cu != null) {
				minAddr = cu.getMinAddress();
			}
			cu = listing.getCodeUnitContaining(maxAddr);
			if (cu != null) {
				maxAddr = cu.getMaxAddress();
			}
			tmpAddrSet.addRange(minAddr, maxAddr);
			monitor.setProgress(++count);
		}
		return tmpAddrSet;
	}

	/** Determines where the property of interest to the comparator is different
	 * between program1 and program2. This is for use with object iterators as
	 * opposed to determining differences using a code unit iterator.
	 * (For example, object iterators are used for equates and functions.)
	 * @param c the comparator to use for determining where the differences are.
	 * @param iter1 the program1 object iterator for where the property type
	 * to be compared exists.
	 * @param iter2 the program2 object iterator for where the property type
	 * to be compared exists.
	 * @param monitor the task monitor for indicating the progress of
	 * determining differences. This monitor reports the progress to the user.
	 * @return the addresses where the comparator determined the property type
	 * of interest was different. null if canceled.
	 * The addresses in this address set are derived from program1.
	 * @throws CancelledException if the user canceled the Diff.
	 */
	private AddressSet getObjectDiffs(ProgramDiffComparator c, IteratorWrapper iter1,
			IteratorWrapper iter2, TaskMonitor monitor) throws CancelledException {
		AddressSet addrs = new AddressSet();
		Object o1 = null;
		Object o2 = null;
		AddressSet a1 = new AddressSet();
		AddressSet a2 = new AddressSet();
		AddressSet a2CompatibleWith1 = DiffUtility.getCompatibleAddressSet(a2, program1);
		if (iter1.hasNext()) {
			o1 = iter1.next(); // Get first object in iterator1
			a1 = c.getAddressSet(o1, c.getProgramOne());
		}
		if (iter2.hasNext()) {
			o2 = iter2.next(); // Get first object in iterator2
			a2 = c.getAddressSet(o2, c.getProgramTwo());
			a2CompatibleWith1 = DiffUtility.getCompatibleAddressSet(a2, program1);
		}
//		int i=0;
		while ((o1 != null) && (o2 != null)) {
			boolean move1 = false;
			boolean move2 = false;
			int result = c.compare(o1, o2);
			if (result < 0) {
				// o1 < o2
				addrs.add(a1);
				move1 = true;
			}
			else if (result > 0) {
				// o1 > o2
				addrs.add(a2CompatibleWith1);
				move2 = true;
			}
			else {
				// o1 == o2
				// Now see if what we're interested about in each program's
				// object is different.
				if (!c.isSame(o1, o2)) {
					addrs.add(a1);
					addrs.add(a2CompatibleWith1);
				}
				move1 = true;
				move2 = true;
			}
//			if (++i == DISPLAY_GRANULARITY) {
			monitor.setMessage(
				monitorMsg + ": " + (move1 ? a1.getMinAddress().toString(showAddressSpace)
						: a2.getMinAddress().toString(showAddressSpace)));
//				i = 0;
//			}
			if (move1) {
				if (iter1.hasNext()) {
					o1 = iter1.next();
					a1 = c.getAddressSet(o1, c.getProgramOne());
				}
				else {
					o1 = null;
				}
			}
			if (move2) {
				if (iter2.hasNext()) {
					o2 = iter2.next();
					a2 = c.getAddressSet(o2, c.getProgramTwo());
					a2CompatibleWith1 = DiffUtility.getCompatibleAddressSet(a2, program1);
				}
				else {
					o2 = null;
				}
			}
			checkCancelled(monitor);
		}
		// Put remaining iterator1 addresses in the address set.
		if (o1 != null) {
			addrs.add(a1);
		}
		while (iter1.hasNext()) {
			o1 = iter1.next();
			a1 = c.getAddressSet(o1, c.getProgramOne());
			addrs.add(a1);
			checkCancelled(monitor);
//			if (++i == DISPLAY_GRANULARITY) {
			monitor.setMessage(monitorMsg + ": " + (a1.getMinAddress().toString(showAddressSpace)));
//				i = 0;
//			}
		}
		// Put remaining iterator2 addresses in the address set.
		if (o2 != null) {
			addrs.add(a2CompatibleWith1);
		}
		while (iter2.hasNext()) {
			checkCancelled(monitor);
			o2 = iter2.next();
			a2 = c.getAddressSet(o2, c.getProgramTwo());
			Address min = a2.getMinAddress();
			if (min != null) {
				a2CompatibleWith1 = DiffUtility.getCompatibleAddressSet(a2, program1);
				addrs.add(a2CompatibleWith1);
//				if (++i == DISPLAY_GRANULARITY) {
				monitor.setMessage(monitorMsg + ": " + (min.toString(showAddressSpace)));
//					i = 0;
//				}
			}
		}

		return addrs;
	}

//	/** Compares the minimum addresses for each of the code units.
//	 * @param cu1 the first code unit.
//	 * @param cu2 the second code unit.
//	 * @return 0 if the code units have the same minimum address. -1 if first
//	 * code unit's min address is less than the second's. 1 if first code unit's
//	 * address is greater than the second's.
//	 */
//    private int compareAddress(CodeUnit cu1, CodeUnit cu2) {
//		return cu1.getMinAddress().compareTo(cu2.getMinAddress());
//	}

	///////////////////////////////////////////////////////////////////////
	// COMPARATORS
	///////////////////////////////////////////////////////////////////////
	/** Interface providing a means for comparing programs to determine their differences.
	 */
	private interface ProgramDiffComparator {
		/** Returns the first program for this diff.
		 * @return the first program.
		 */
		public Program getProgramOne();

		/** Returns the second program for this diff.
		 * @return the second program.
		 */
		public Program getProgramTwo();

		/** Compares two like objects to determine whether the first is effectively
		 *  less than (comes before it in memory), equal to (at the same spot
		 *  in memory), or greater than (comes after it in memory) the second.
		 * @param obj1 the first object
		 * @param obj2 the second object
		 * @return -1 if the first comes before the second in memory.
		 *          0 if the objects are at the same spot in memory.
		 *          1 if the first comes after the second in memory.
		 */
		public int compare(Object obj1, Object obj2);

		/** Returns whether the objects are the same with respect to the
		 *  program difference type this comparator is interested in.
		 * @param obj1 the first object
		 * @param obj2 the second object
		 * @return true if the objects are the same with respect to the type
		 * this comparator is interested in.
		 */
		public boolean isSame(Object obj1, Object obj2);

		/** Returns the addresses that are to indicate the difference of this
		 *  comparison type for this object.
		 * @param obj the object being examined by this comparator.
		 * @param program the program the object is associated with.
		 * @return the addresses that we want to indicate for a difference
		 * of this comparison type.
		 * The addresses in this address set are derived from the specified program.
		 */
		public AddressSet getAddressSet(Object obj, Program program);
	}

	/** Provides a means for comparing programs to determine their differences.
	 */
	static abstract class ProgramDiffComparatorImpl implements ProgramDiffComparator {
		/** The first program for the diff. */
		protected Program program1;
		/** The second program for the diff. */
		protected Program program2;

		/** Generic constructor for comparing program differences.
		 * @param program1 the first program
		 * @param program2 the second program
		 */
		public ProgramDiffComparatorImpl(Program program1, Program program2) {
			this.program1 = program1;
			this.program2 = program2;
		}

		/** Returns the first program being compared by this <CODE>ProgramDiff</CODE>.
		 * @return the first program for the diff.
		 */
		@Override
		public Program getProgramOne() {
			return program1;
		}

		/** Returns the second program being compared by this <CODE>ProgramDiff</CODE>.
		 * @return the second program for the diff.
		 */
		@Override
		public Program getProgramTwo() {
			return program2;
		}
	}

	/** Used to compare the symbols in two programs.
	 */
	private class SymbolComparator extends ProgramDiffComparatorImpl {
		/** Constructor
		 * @param program1 the first program
		 * @param program2 the second program
		 */
		private SymbolComparator(Program program1, Program program2) {
			super(program1, program2);
		}

		/** Compares two symbols to determine whether the first is effectively
		 *  less than (comes before it in the symbol table),
		 *  equal to (at the same spot in the symbol table),
		 *  or greater than (comes after it in the symbol table) the second.
		 * @param obj1 the address for the first program's symbol.
		 * @param obj2 the address for the second program's symbol.
		 * @return -1 if the first comes before the second in the symbol table.
		 *          0 if the objects are at the same spot in the symbol table.
		 *          1 if the first comes after the second in the symbol table.
		 */
		@Override
		public int compare(Object obj1, Object obj2) {
			Symbol s1 = (Symbol) obj1;
			Symbol s2 = (Symbol) obj2;
			Address address2CompatibleWith1 =
				SimpleDiffUtility.getCompatibleAddress(program2, s2.getAddress(), program1);
			return s1.getAddress().compareTo(address2CompatibleWith1);
		}

		/** Returns whether or not all the symbol objects are the same at the
		 *  same address as the indicated symbol objects (obj1 and obj2).
		 * @param obj1 the first object
		 * @param obj2 the second object
		 * @return true if the objects are the same symbol and have the same
		 * associated symbols (other symbols at the same address).
		 */
		@Override
		public boolean isSame(Object obj1, Object obj2) {
			Symbol s1 = (Symbol) obj1;
			Symbol s2 = (Symbol) obj2;
			if (s1.isExternalEntryPoint() != s2.isExternalEntryPoint()) {
				return false;
			}
			Symbol[] sym1 = this.program1.getSymbolTable().getSymbols(s1.getAddress());
			Symbol[] sym2 = this.program2.getSymbolTable().getSymbols(s2.getAddress());
			if (sym1.length != sym2.length) {
				return false;
			}
			SymbolNameComparator snc = new SymbolNameComparator();
			Arrays.sort(sym1, snc);
			Arrays.sort(sym2, snc);
			for (int i = 0; i < sym1.length; i++) {
				if (!equivalentSymbols(program1, program2, sym1[i], sym2[i])) {
					return false;
				}
			}
			return true;
		}

		/** Returns the address range for the code unit associated with this
		 *  symbol object.
		 * @param obj the object being examined by this comparator.
		 * @param program the program the object is associated with.
		 * @return the addresses that we want to indicate for a difference
		 * of this comparison type.
		 * The addresses in this address set are derived from the specified program.
		 */
		@Override
		public AddressSet getAddressSet(Object obj, Program program) {
			AddressSet addrs = new AddressSet();
			if (obj == null) {
				return addrs;
			}
			Symbol s = (Symbol) obj;
			Address addr = s.getAddress();
			addrs.addRange(addr, addr);
			return addrs;
		}

	}

	/** Used to compare the equates in two programs.
	 */
	private class EquateComparator extends ProgramDiffComparatorImpl {

		/** Constructor
		 * @param program1 the first program
		 * @param program2 the second program
		 */
		private EquateComparator(Program program1, Program program2) {
			super(program1, program2);
		}

		/** Compares two equate's addresses to determine whether the first is
		 *  effectively less than (comes before it in memory),
		 *  equal to (at the same spot in memory),
		 *  or greater than (comes after it in memory) the second.
		 * @param obj1 the address for the first program's equate code unit.
		 * @param obj2 the address for the second program's equate code unit.
		 * @return -1 if the first comes before the second in memory.
		 *          0 if the objects are at the same spot in memory.
		 *          1 if the first comes after the second in memory.
		 */
		@Override
		public int compare(Object obj1, Object obj2) {
			Address a1 = (Address) obj1;
			Address a2 = (Address) obj2;
			Address address2CompatibleWith1 =
				SimpleDiffUtility.getCompatibleAddress(program2, a2, program1);
			return a1.compareTo(address2CompatibleWith1);
		}

		/** Returns whether the objects are the same with respect to the
		 *  program difference type this comparator is interested in.
		 * @param obj1 the first object
		 * @param obj2 the second object
		 * @return true if the objects are the same with respect to the type
		 * this comparator is interested in.
		 */
		@Override
		public boolean isSame(Object obj1, Object obj2) {
			Address a1 = (Address) obj1;
			for (int opIndex = 0; opIndex < Program.MAX_OPERANDS; opIndex++) {
				if (!isSameOperandEquates(a1, opIndex)) {
					return false;
				}
			}
			return true;
		}

		/** Returns the addresses that are to indicate the difference of this
		 *  comparison type for this object.
		 * @param obj the object being examined by this comparator.
		 * @param program the program the object is associated with.
		 * @return the addresses that we want to indicate for a difference
		 * of this comparison type.
		 * The addresses in this address set are derived from the specified program.
		 */
		@Override
		public AddressSet getAddressSet(Object obj, Program program) {
			AddressSet addrs = new AddressSet();
			if (obj == null) {
				return addrs;
			}
			Address addr = (Address) obj;
			addrs.addRange(addr, addr);
			return addrs;
		}
	}

	/** Used to compare the bookmarks in two programs.
	 */
	private class BookmarksComparator extends ProgramDiffComparatorImpl {
		/** The first program's bookmark manager. */
		BookmarkManager bm1;
		/** The second program's bookmark manager. */
		BookmarkManager bm2;
		BookmarkType type;

		/** Constructor
		 * @param type the bookmark type to be compared.
		 * @param program1 the first program
		 * @param program2 the second program
		 */
		private BookmarksComparator(BookmarkType type, Program program1, Program program2) {
			super(program1, program2);
			this.type = type;
			bm1 = program1.getBookmarkManager();
			bm2 = program2.getBookmarkManager();
		}

		/** Compares two bookmark's addresses to determine whether the first is
		 *  effectively less than (comes before it in memory),
		 *  equal to (at the same spot in memory),
		 *  or greater than (comes after it in memory) the second.
		 * @param obj1 the address where there are bookmarks of the current
		 * bookmark type in the first program.
		 * @param obj2 the address where there are bookmarks of the current
		 * bookmark type in the second program.
		 * @return -1 if the first comes before the second in memory.
		 *          0 if the objects are at the same spot in memory.
		 *          1 if the first comes after the second in memory.
		 */
		@Override
		public int compare(Object obj1, Object obj2) {
			Address a1 = (Address) obj1;
			Address a2 = (Address) obj2;
			Address address2CompatibleWith1 =
				SimpleDiffUtility.getCompatibleAddress(program2, a2, program1);
			return a1.compareTo(address2CompatibleWith1);
		}

		/** Returns whether the objects have the same bookmarks of the current
		 * bookmark type at the indicated address.
		 * @param obj1 the first object
		 * @param obj2 the second object
		 * @return true if the objects are the same with respect to the type
		 * this comparator is interested in.
		 */
		@Override
		public boolean isSame(Object obj1, Object obj2) {
			Address a1 = (Address) obj1;
			Address a2 = (Address) obj2;
			Address address2CompatibleWith1 =
				SimpleDiffUtility.getCompatibleAddress(program2, a2, program1);
			if (!a1.equals(address2CompatibleWith1)) {
				throw new AssertException("Can only diff bookmarks at same address.");
			}
			Bookmark[] marks1 = bm1.getBookmarks(a1, type.getTypeString());
			Bookmark[] marks2 = bm2.getBookmarks(a2, type.getTypeString());
			if (marks1.length != marks2.length) {
				return false;
			}
			Arrays.sort(marks1, BOOKMARK_COMPARATOR);
			Arrays.sort(marks2, BOOKMARK_COMPARATOR);
			for (int i = 0; i < marks1.length; i++) {
				if (!marks1[i].getCategory().equals(marks2[i].getCategory()) ||
					!marks1[i].getComment().equals(marks2[i].getComment())) {
					return false;
				}
			}
			return true;
		}

		/** Returns the addresses that are to indicate the difference of this
		 *  comparison type for this object.
		 * @param obj the object being examined by this comparator.
		 * @param program the program the object is associated with.
		 * @return the addresses that we want to indicate for a difference
		 * of this comparison type.
		 * The addresses in this address set are derived from the specified program.
		 */
		@Override
		public AddressSet getAddressSet(Object obj, Program program) {
			AddressSet addrs = new AddressSet();
			if (obj == null) {
				return addrs;
			}
			Address addr = (Address) obj;
			CodeUnit cu = program.getListing().getCodeUnitContaining(addr);
			if (cu != null) {
				addrs.addRange(cu.getMinAddress(), cu.getMaxAddress());
			}
			return addrs;
		}
	}

	/**
	 * Compares an array of bookmarks from program1 with an array of bookmarks from program2 to see if they are equivalent.
	 * @param pgm1 program1
	 * @param bookmarks1 program1 array of bookmarks
	 * @param pgm2 program2
	 * @param bookmarks2 program2 array of bookmarks
	 * @return true if the arrays of bookmarks are equal.
	 */
	static boolean equivalentBookmarkArrays(Program pgm1, Program pgm2, Bookmark[] bookmarks1,
			Bookmark[] bookmarks2) {
		if (bookmarks1 == bookmarks2) {
			return true;
		}
		if (bookmarks1 == null || bookmarks2 == null) {
			return false;
		}

		int length = bookmarks1.length;
		if (bookmarks2.length != length) {
			return false;
		}

		for (int i = 0; i < length; i++) {
			Bookmark bookmark1 = bookmarks1[i];
			Bookmark bookmark2 = bookmarks2[i];
			if (!(bookmark1 == null ? bookmark2 == null
					: equivalentBookmarks(pgm1, pgm2, bookmark1, bookmark2))) {
				return false;
			}
		}

		return true;
	}

	static boolean equivalentBookmarks(Program pgm1, Program pgm2, Bookmark bookmark1,
			Bookmark bookmark2) {
		Address addr1 = bookmark1.getAddress();
		Address addr2 = bookmark2.getAddress();
		Address addr2AsP1 = SimpleDiffUtility.getCompatibleAddress(pgm2, addr2, pgm1);
		return SystemUtilities.isEqual(addr1, addr2AsP1) &&
			bookmark1.getTypeString().equals(bookmark2.getTypeString()) &&
			bookmark1.getCategory().equals(bookmark2.getCategory()) &&
			bookmark1.getComment().equals(bookmark2.getComment());
	}

	static boolean equivalentVariableArrays(Variable[] vars1, Variable[] vars2,
			boolean checkParamStorage) {
		if (vars1 == vars2) {
			return true;
		}
		if (vars1 == null || vars2 == null) {
			return false;
		}

		int length = vars1.length;
		if (vars2.length != length) {
			return false;
		}

		for (int i = 0; i < length; i++) {
			if ((vars1[i] instanceof Parameter) != (vars2[i] instanceof Parameter)) {
				return false;
			}
			boolean checkStorage = !(vars1[i] instanceof Parameter) || checkParamStorage;
			if (!(vars1[i] == null ? vars2[i] == null
					: equivalentVariables(vars1[i], vars2[i], checkStorage))) {
				return false;
			}
		}

		return true;
	}

	static boolean equivalentVariables(Variable var1, Variable var2, boolean checkStorage) {
		if ((var1 instanceof Parameter) != (var2 instanceof Parameter)) {
			return false;
		}
		boolean isReturn = false;
		if (var1 instanceof Parameter) {
			int ordinal1 = ((Parameter) var1).getOrdinal();
			int ordinal2 = ((Parameter) var2).getOrdinal();
			if (ordinal1 != ordinal2) {
				return false;
			}
			isReturn = (ordinal1 == Parameter.RETURN_ORIDINAL);
		}
		else {
			if (var1.getFirstUseOffset() != var2.getFirstUseOffset()) {
				return false;
			}
		}
		String comment1 = var1.getComment();
		String comment2 = var2.getComment();
		if (!var1.equals(var2) || !var1.getDataType().isEquivalent(var2.getDataType()) ||
			!SystemUtilities.isEqual(comment1, comment2)) {
			return false;
		}
		if (checkStorage && !DiffUtility.variableStorageMatches(var1, var2)) {
			return false;
		}
		if (isReturn) {
			return true;
		}
		if (var1.getSource() == SourceType.DEFAULT && var2.getSource() == SourceType.DEFAULT) {
			return true;
		}
		return var1.getName().equals(var2.getName());
	}

	static public boolean equivalentFunctions(Function f1, Function f2) {
		return equivalentFunctions(f1, f2, false);
	}

	static public boolean equivalentFunctions(Function f1, Function f2, boolean ignoreName) {
		if (f1 == f2) {
			return true;
		}
		if (f1 == null || f2 == null) {
			return false;
		}
		boolean f1IsThunk = f1.isThunk();
		boolean f2IsThunk = f2.isThunk();
		if (f1IsThunk != f2IsThunk) {
			return false;
		}

		Program program1 = f1.getProgram();
		Program program2 = f2.getProgram();

		boolean f1IsExternal = f1.isExternal();
		boolean f2IsExternal = f2.isExternal();
		if (f1IsExternal != f2IsExternal) {
			return false;
		}
		if (!f1IsExternal) {
			Address entry1 = f1.getEntryPoint();
			Address entry2 = f2.getEntryPoint();
			Address entry2AsP1 = SimpleDiffUtility.getCompatibleAddress(program2, entry2, program1);
			if (!entry1.equals(entry2AsP1)) {
				return false;
			}
			AddressSetView body1 = f1.getBody();
			AddressSetView body2 = f2.getBody();
			AddressSet body2AsP1 = DiffUtility.getCompatibleAddressSet(body2, program1);
			if (!body1.equals(body2AsP1)) {
				return false;
			}
		}

		if (f1IsThunk) {
			return isEquivalentThunk(f1, f2);
		}

		StackFrame frame1 = f1.getStackFrame();
		StackFrame frame2 = f2.getStackFrame();

		if ((!ignoreName && !f1.getName().equals(f2.getName())) ||
			(f1.getStackPurgeSize() != f2.getStackPurgeSize()) ||
			(f1.getSignatureSource() != f2.getSignatureSource()) ||
			(f1.hasVarArgs() != f2.hasVarArgs()) || (f1.isInline() != f2.isInline()) ||
			(f1.hasNoReturn() != f2.hasNoReturn()) ||
			(!equivalentTagSets(f1.getTags(), f2.getTags())) ||
			!f1.getCallingConventionName().equals(f2.getCallingConventionName()) ||
			// Uses frame for some values since they may be adjusted
			// It is currently impossible to create a function with
			// identical attributes since some are hidden
			// For now, we are not allowing you to set the parameter offset or local size outright.
			//			(frame1.getLocalSize() != frame2.getLocalSize()) ||
			//			(frame1.getParameterOffset() != frame2.getParameterOffset()) ||
			(frame1.getReturnAddressOffset() != frame2.getReturnAddressOffset()) ||
			(f1.hasCustomVariableStorage() != f2.hasCustomVariableStorage())) {
			return false;
		}

		boolean hasCustomStorage = f1.hasCustomVariableStorage();
		if (!equivalentVariables(f1.getReturn(), f2.getReturn(), hasCustomStorage)) {
			return false;
		}
		if (!equivalentVariableArrays(f1.getParameters(), f2.getParameters(), hasCustomStorage)) {
			return false;
		}
		if (!f1IsExternal &&
			!equivalentVariableArrays(f1.getLocalVariables(), f2.getLocalVariables(), false)) {
			return false;
		}
		return true;
	}

	/**
	 * Compares two thunk functions from different programs to determine if they are 
	 * equivalent to each other (effectively the same thunk function in the other program).
	 * @param thunkFunction1 the first thunk function
	 * @param thunkFunction2 the second thunk function
	 * @return true if the functions are equivalent thunk functions.
	 */
	public static boolean isEquivalentThunk(Function thunkFunction1, Function thunkFunction2) {
		if (!thunkFunction1.isThunk() || !thunkFunction2.isThunk()) {
			return false;
		}
		Function thunkedFunction1 = thunkFunction1.getThunkedFunction(false);
		Address thunkedEntry1 = thunkedFunction1.getEntryPoint();
		Function thunkedFunction2 = thunkFunction2.getThunkedFunction(false);
		Address thunkedEntry2 = thunkedFunction2.getEntryPoint();
		if (thunkedFunction1.isExternal() != thunkedFunction2.isExternal()) {
			return false; // Only one was external.
		}
		Symbol fSym1 = thunkFunction1.getSymbol();
		Symbol fSym2 = thunkFunction2.getSymbol();
		// Don't check names if both are default. Otherwise, compare names.
		if ((fSym1.getSource() != SourceType.DEFAULT || fSym2.getSource() != SourceType.DEFAULT) &&
			!sameFunctionNames(thunkFunction1, thunkFunction2)) {
			return false;
		}
		if (!thunkedFunction1.isExternal()) {
			// Not an external function.
			Address thunkedEntry2AsP1 = SimpleDiffUtility.getCompatibleAddress(
				thunkFunction2.getProgram(), thunkedEntry2, thunkFunction1.getProgram());
			return thunkedEntry1.equals(thunkedEntry2AsP1);
		}
		ExternalLocation external1 = thunkedFunction1.getExternalLocation();
		ExternalLocation external2 = thunkedFunction2.getExternalLocation();
		return external1.isEquivalent(external2);
	}

	public static boolean sameFunctionNames(Function f1, Function f2) {
		if (f1 == null) {
			return f2 == null;
		}
		if (f2 == null) {
			return false;
		}
		String name1 = f1.getName();
		String name2 = f2.getName();
		Symbol symbol1 = f1.getSymbol();
		Symbol symbol2 = f2.getSymbol();
		if (isDefaultName(symbol1)) {
			return isDefaultName(symbol2);
		}
		else if (isDefaultName(symbol2)) {
			return false;
		}
		return name1.equals(name2);
	}

	private static boolean isDefaultName(Symbol symbol) {
		return symbol.getSource() == SourceType.DEFAULT;
	}

	/**
	 * Returns true if the two sets contain function tags with the same
	 * name/comment pairs.
	 *
	 * @param setA the first set
	 * @param setB the second set
	 * @return true if sets contain tags with the same name/comment pairs
	 */
	static boolean equivalentTagSets(Set<FunctionTag> setA, Set<FunctionTag> setB) {

		// To do this easily, just convert the sets to sorted lists and use a .equals call. Since
		// FunctionTagDB overrides the equals method to compare the internal name/comment,
		// this will do the job.
		//
		// Note that the lists must be sorted first, which works since FunctionTagDB is a
		// Comparable.
		List<FunctionTag> listA = new ArrayList<>(setA);
		List<FunctionTag> listB = new ArrayList<>(setB);
		Collections.sort(listA);
		Collections.sort(listB);
		return listA.equals(listB);
	}

	/** Used to compare the functions in two programs.
	 */
	private class FunctionComparator extends ProgramDiffComparatorImpl {
		/** Constructor
		 * @param program1 the first program
		 * @param program2 the second program
		 */
		private FunctionComparator(Program program1, Program program2) {
			super(program1, program2);
		}

		/**
		 * @param obj1 the address for the first program's function.
		 * @param obj2 the address for the second program's function.
		 * @return  */
		/** Compares two function objects to determine whether the first
		 *  function's entry point is effectively
		 *  less than (comes before it in memory), equal to (at the same spot
		 *  in memory), or greater than (comes after it in memory) the second
		 *  function's entry point.
		 * @param obj1 the first object
		 * @param obj2 the second object
		 * @return -1 if the first comes before the second in memory.
		 *          0 if the objects are at the same spot in memory.
		 *          1 if the first comes after the second in memory.
		 */
		@Override
		public int compare(Object obj1, Object obj2) {
			Function f1 = (Function) obj1;
			Function f2 = (Function) obj2;
			// FunctionIterator is ordered by address.
			// Check the function entry point address.
			Address entryPt2CompatibleWith1 =
				SimpleDiffUtility.getCompatibleAddress(program2, f2.getEntryPoint(), program1);
			return f1.getEntryPoint().compareTo(entryPt2CompatibleWith1);
		}

		/** Returns whether the functions are the same.
		 * @param obj1 the first object
		 * @param obj2 the second object
		 * @return true if the functions have the same signature, comment,
		 * body, and stack.
		 */
		@Override
		public boolean isSame(Object obj1, Object obj2) {
			Function f1 = (Function) obj1;
			Function f2 = (Function) obj2;
			return equivalentFunctions(f1, f2);
		}

		/** Returns the address set, which contains the address for the
		 *  function object's entry point.
		 * @param obj the object being examined by this comparator.
		 * @param program the program the object is associated with.
		 * @return the function entry point address.
		 * The addresses in this address set are derived from the specified program.
		 */
		@Override
		public AddressSet getAddressSet(Object obj, Program program) {
			AddressSet addrs = new AddressSet();
			if (obj == null) {
				return addrs;
			}
			Function f = (Function) obj;
			Address addr = f.getEntryPoint();
			if (addr != null) {
				addrs.addRange(addr, addr);
			}
			return addrs;
		}
	}

	/** Abstract class for comparing two code units to determine if a particular program property
	 * differs. It provides a default implementation of the <CODE>compare</CODE> method
	 * which compares the code unit minimum addresses. It also implements the
	 * <CODE>getAddressSet</CODE> method, which gets the addresses for the specified
	 * code unit.
	 * Any class that extends this one must implement the <CODE>isSame</CODE> method.
	 * isSame should compare the desired property of the two code units to determine
	 * if it is equal in each.
	 */
	private abstract class CodeUnitComparator extends ProgramDiffComparatorImpl {
		/** Generic constructor for comparing program differences.
		 * @param program1 the first program
		 * @param program2 the second program
		 */
		private CodeUnitComparator(Program program1, Program program2) {
			super(program1, program2);
		}

		/** Compares two like objects to determine whether the first is effectively
		 *  less than (comes before it in memory), equal to (at the same spot
		 *  in memory), or greater than (comes after it in memory) the second.
		 * @param obj1 the first object
		 * @param obj2 the second object
		 * @return -1 if the first comes before the second in memory.
		 *          0 if the objects are at the same spot in memory.
		 *          1 if the first comes after the second in memory.
		 */
		@Override
		public int compare(Object obj1, Object obj2) {
			CodeUnit cu1 = (CodeUnit) obj1;
			CodeUnit cu2 = (CodeUnit) obj2;
			Address min2CompatibleWith1 =
				SimpleDiffUtility.getCompatibleAddress(program2, cu2.getMinAddress(), program1);
			return cu1.getMinAddress().compareTo(min2CompatibleWith1);
		}

		/** Returns whether the objects are the same with respect to the
		 *  program difference type this comparator is interested in.
		 * @param obj1 the first object
		 * @param obj2 the second object
		 * @return true if the objects are the same with respect to the type
		 * this comparator is interested in.
		 */
		@Override
		public abstract boolean isSame(Object obj1, Object obj2);

		/** Returns the addresses that are to indicate the difference of this
		 *  comparison type for this object.
		 * @param obj the object being examined by this comparator.
		 * @param program the program associated with the object.
		 * @return the addresses that we want to indicate for a difference
		 * of this comparison type.
		 * The addresses in this address set are derived from the specified program.
		 */
		@Override
		public AddressSet getAddressSet(Object obj, Program program) {
			AddressSet addrSet = new AddressSet();
			if (obj == null) {
				return addrSet;
			}
			CodeUnit cu = (CodeUnit) obj;
			addrSet.addRange(cu.getMinAddress(), cu.getMaxAddress());
			return addrSet;
		}
	}

	/** Used to compare the comments of a particular type in two programs.
	 */
	private class CommentTypeComparator extends ProgramDiffComparatorImpl {
		/**
		 * the type of comment to compare
		 * <br>CodeUnit.PLATE_COMMENT
		 * <br>CodeUnit.PRE_COMMENT
		 * <br>CodeUnit.EOL_COMMENT
		 * <br>CodeUnit.REPEATABLE_COMMENT
		 * <br>CodeUnit.POST_COMMENT
		 */
		int type;
		private Listing comparatorListing1;
		private Listing comparatorListing2;

		/** Generic constructor for comparing program differences.
		 * @param program1 the first program
		 * @param program2 the second program
		 * @param type the comment type
		 */
		private CommentTypeComparator(Program program1, Program program2, int type) {
			super(program1, program2);
			this.type = type;
			comparatorListing1 = program1.getListing();
			comparatorListing2 = program2.getListing();
		}

		/** Compares two comment address objects to determine whether the first
		 *  comment's address is effectively
		 *  less than (comes before it in memory), equal to (at the same spot
		 *  in memory), or greater than (comes after it in memory) the second
		 *  comment's address.
		 * @param obj1 the address for the first program's comment.
		 * @param obj2 the address for the second program's comment.
		 * @return -1 if the first comes before the second in memory.
		 *          0 if the objects are at the same spot in memory.
		 *          1 if the first comes after the second in memory.
		 */
		@Override
		public int compare(Object obj1, Object obj2) {
			Address a1 = (Address) obj1;
			Address a2 = (Address) obj2;
			Address address2CompatibleWith1 =
				SimpleDiffUtility.getCompatibleAddress(program2, a2, program1);
			return a1.compareTo(address2CompatibleWith1);
		}

		/** Returns whether the comments are the same.
		 * @param obj1 the first object
		 * @param obj2 the second object
		 * @return true if the comments are the same.
		 */
		@Override
		public boolean isSame(Object obj1, Object obj2) {
			Address a1 = (Address) obj1;
			Address a2 = (Address) obj2;
			String c1 = comparatorListing1.getComment(type, a1);
			String c2 = comparatorListing2.getComment(type, a2);
			return SystemUtilities.isEqual(c1, c2);
		}

		/** Returns the address set, which contains the address for the comment.
		 * @param obj the object being examined by this comparator.
		 * @param program the program the object is associated with.
		 * @return the comment address.
		 * The addresses in this address set are derived from the specified program.
		 */
		@Override
		public AddressSet getAddressSet(Object obj, Program program) {
			AddressSet addrs = new AddressSet();
			if (obj == null) {
				return addrs;
			}
			Address addr = (Address) obj;
			addrs.addRange(addr, addr);
			return addrs;
		}
	}

	/**
	 * Compares an array of references from program1 with an array of references from program2 to see if they are equivalent.
	 * @param refs1 program1 array of references
	 * @param refs2 program2 array of references
	 * @return true if the arrays of references are equal.
	 */
	public boolean equalRefArrays(Reference[] refs1, Reference[] refs2) {
		return equivalentReferenceArrays(program1, program2, refs1, refs2);
	}

	/**
	 * Compares an array of references from program1 with an array of references from program2 to see if they are equivalent.
	 * @param pgm1 program1
	 * @param pgm2 program2
	 * @param refs1 program1 array of references
	 * @param refs2 program2 array of references
	 * @return true if the arrays of references are equal.
	 */
	static boolean equivalentReferenceArrays(Program pgm1, Program pgm2, Reference[] refs1,
			Reference[] refs2) {
		if (refs1 == refs2) {
			return true;
		}
		if (refs1 == null || refs2 == null) {
			return false;
		}

		int length = refs1.length;
		if (refs2.length != length) {
			return false;
		}

		for (int i = 0; i < length; i++) {
			Reference ref1 = refs1[i];
			Reference ref2 = refs2[i];
			if (!(ref1 == null ? ref2 == null : equivalentReferences(pgm1, pgm2, ref1, ref2))) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Compares reference from program1 with reference from program2 to see if they are equivalent.
	 * @param ref1 program1 reference
	 * @param ref2 program2 reference
	 * @return true if they are equivalent
	 */
	public boolean equalRefs(Reference ref1, Reference ref2) {
		return equivalentReferences(program1, program2, ref1, ref2);
	}

	/**
	 * Compares reference from program1 with reference from program2 to see if they are equivalent.
	 * @param p1 program1
	 * @param p2 program2
	 * @param ref1 program1 reference
	 * @param ref2 program2 reference
	 * @return true if they are equivalent
	 */
	static boolean equivalentReferences(Program p1, Program p2, Reference ref1, Reference ref2) {
		if (ref1 == ref2) {
			return true;
		}
		if (ref1 == null || ref2 == null) {
			return false;
		}
		if (ref1.getOperandIndex() != ref2.getOperandIndex() ||
			ref1.getReferenceType() != ref2.getReferenceType() ||
			//        		ref1.getSource() != ref2.getSource() || // ignore source type since we can't change it anyway.
			ref1.isPrimary() != ref2.isPrimary()) {
			return false;
		}
		Address fromAddr1 = ref1.getFromAddress();
		Address fromAddr2 = ref2.getFromAddress();
		Address fromAddr2AsP1 = SimpleDiffUtility.getCompatibleAddress(p2, fromAddr2, p1);
		if (!fromAddr1.equals(fromAddr2AsP1)) {
			return false;
		}
		if (!ref1.isExternalReference()) {
			Address toAddr1 = ref1.getToAddress();
			Address toAddr2 = ref2.getToAddress();
			Address toAddr2AsP1 = SimpleDiffUtility.getCompatibleAddress(p2, toAddr2, p1);
			if (!toAddr1.equals(toAddr2AsP1)) {
				return false;
			}
		}
		Symbol p1Symbol = p1.getSymbolTable().getSymbol(ref1.getSymbolID());
		Symbol p2Symbol = p2.getSymbolTable().getSymbol(ref2.getSymbolID());
		if (!ProgramDiff.equivalentSymbols(p1, p2, p1Symbol, p2Symbol)) {
			return false;
		}

		// Entry Point Reference
		if (ref1.isEntryPointReference()) {
			return ref2.isEntryPointReference();
		}
		// External Reference
		if (ref1.isExternalReference()) {
			if (!ref2.isExternalReference()) {
				return false;
			}
			ExternalReference extRef1 = (ExternalReference) ref1;
			ExternalReference extRef2 = (ExternalReference) ref2;
			ExternalLocation extLoc1 = extRef1.getExternalLocation();
			ExternalLocation extLoc2 = extRef2.getExternalLocation();
			return isEquivalent(extLoc1, extLoc2);
		}
		// Offset Reference
		if (ref1.isOffsetReference()) {
			if (!ref2.isOffsetReference()) {
				return false;
			}
			OffsetReference offsetRef1 = (OffsetReference) ref1;
			OffsetReference offsetRef2 = (OffsetReference) ref2;
			return offsetRef1.getOffset() == offsetRef2.getOffset();
		}
		// Shifted Reference
		if (ref1.isShiftedReference()) {
			if (!ref2.isShiftedReference()) {
				return false;
			}
			ShiftedReference shiftedRef1 = (ShiftedReference) ref1;
			ShiftedReference shiftedRef2 = (ShiftedReference) ref2;
			return shiftedRef1.getShift() == shiftedRef2.getShift();
		}
		// Stack Reference
		if (ref1.isStackReference()) {
			if (!ref2.isStackReference()) {
				return false;
			}
			StackReference stackRef1 = (StackReference) ref1;
			StackReference stackRef2 = (StackReference) ref2;
			return stackRef1.getStackOffset() == stackRef2.getStackOffset();
		}
		// Register Reference
		if (ref1.isRegisterReference()) {
			if (!ref2.isRegisterReference()) {
				return false;
			}
		}
		// Memory Reference
		if (ref1.isMemoryReference()) {
			return ref2.isMemoryReference();
		}

		return true;
	}

	private static boolean isEquivalent(ExternalLocation extLoc1, ExternalLocation extLoc2) {
		if (extLoc1 == null && extLoc2 == null) {
			return true;
		}
		if (extLoc1 == null || extLoc2 == null) {
			return false;
		}

		return extLoc1.isEquivalent(extLoc2);

	}

	/**
	 *
	 * @param addressTranslator
	 * @param p1Ref
	 * @param p2Ref
	 * @return
	 */
	static boolean equivalentReferences(AddressTranslator p2ToP1Translator, Reference p1Ref,
			final Reference p2Ref) {
		if (p1Ref == p2Ref) {
			return true;
		}
		if (p1Ref == null || p2Ref == null) {
			return false;
		}
		if (p1Ref.getOperandIndex() != p2Ref.getOperandIndex() ||
			p1Ref.getReferenceType() != p2Ref.getReferenceType() ||
			//        		p1Ref.getSource() != p2Ref.getSource() || // ignore source type since we can't change it anyway.
			p1Ref.isPrimary() != p2Ref.isPrimary()) {
			return false;
		}
		Address fromAddr1 = p1Ref.getFromAddress();
		Address fromAddr2 = p2Ref.getFromAddress();
		Address fromAddr2AsP1 = p2ToP1Translator.getAddress(fromAddr2);
		if (!fromAddr1.equals(fromAddr2AsP1)) {
			return false;
		}
		if (!p1Ref.isExternalReference()) {
			Address toAddr1 = p1Ref.getToAddress();
			Address toAddr2 = p2Ref.getToAddress();
			Address toAddr2AsP1 = p2ToP1Translator.getAddress(toAddr2);
			if (!toAddr1.equals(toAddr2AsP1)) {
				return false;
			}
		}
		Symbol p1Symbol = p2ToP1Translator.getDestinationProgram().getSymbolTable().getSymbol(
			p1Ref.getSymbolID());
		Symbol p2Symbol =
			p2ToP1Translator.getSourceProgram().getSymbolTable().getSymbol(p2Ref.getSymbolID());
		if (!ProgramDiff.equivalentSymbols(p2ToP1Translator, p1Symbol, p2Symbol)) {
			return false;
		}

		// Entry Point Reference
		if (p1Ref.isEntryPointReference()) {
			return p2Ref.isEntryPointReference();
		}
		// External Reference
		if (p1Ref.isExternalReference()) {
			if (!p2Ref.isExternalReference()) {
				return false;
			}
			ExternalReference extRef1 = (ExternalReference) p1Ref;
			ExternalReference extRef2 = (ExternalReference) p2Ref;
			ExternalLocation extLoc1 = extRef1.getExternalLocation();
			ExternalLocation extLoc2 = extRef2.getExternalLocation();
			return SystemUtilities.isEqual(extLoc1, extLoc2);
		}
		// Offset Reference
		if (p1Ref.isOffsetReference()) {
			if (!p2Ref.isOffsetReference()) {
				return false;
			}
			OffsetReference offsetRef1 = (OffsetReference) p1Ref;
			OffsetReference offsetRef2 = (OffsetReference) p2Ref;
			return offsetRef1.getOffset() == offsetRef2.getOffset();
		}
		// Shifted Reference
		if (p1Ref.isShiftedReference()) {
			if (!p2Ref.isShiftedReference()) {
				return false;
			}
			ShiftedReference shiftedRef1 = (ShiftedReference) p1Ref;
			ShiftedReference shiftedRef2 = (ShiftedReference) p2Ref;
			return shiftedRef1.getShift() == shiftedRef2.getShift();
		}
		// Stack Reference
		if (p1Ref.isStackReference()) {
			if (!p2Ref.isStackReference()) {
				return false;
			}
			StackReference stackRef1 = (StackReference) p1Ref;
			StackReference stackRef2 = (StackReference) p2Ref;
			return stackRef1.getStackOffset() == stackRef2.getStackOffset();
		}
		// Register Reference
		if (p1Ref.isRegisterReference()) {
			if (!p2Ref.isRegisterReference()) {
				return false;
			}
		}
		// Memory Reference
		if (p1Ref.isMemoryReference()) {
			return p2Ref.isMemoryReference();
		}

		return true; // Don't recognize this kind of reference.
	}

	/** Compares two addresses to determine if their memory references differ.
	 * References include mnemonic, operand, and value references.
	 * These can be memory references or external references.
	 */
	private class ReferenceComparator extends ProgramDiffComparatorImpl {
		/** The first program's reference manager. */
		ReferenceManager rm1;
		/** THe second program's reference manager. */
		ReferenceManager rm2;

		/** Constructor for comparing program memory reference differences.
		 * @param program1 the first program
		 * @param program2 the second program
		 */
		private ReferenceComparator(Program program1, Program program2) {
			super(program1, program2);
			rm1 = program1.getReferenceManager();
			rm2 = program2.getReferenceManager();
		}

		/** Compares two reference addresses to determine whether the first is
		 *  effectively less than (comes before it in memory),
		 *  equal to (at the same spot in memory),
		 *  or greater than (comes after it in memory) the second.
		 * @param obj1 the address for the first program's reference.
		 * @param obj2 the address for the second program's reference.
		 * @return -1 if the first comes before the second in memory.
		 *          0 if the objects are at the same spot in memory.
		 *          1 if the first comes after the second in memory.
		 */
		@Override
		public int compare(Object obj1, Object obj2) {
			Address a1 = (Address) obj1;
			Address a2 = (Address) obj2;
			Address address2CompatibleWith1 =
				SimpleDiffUtility.getCompatibleAddress(program2, a2, program1);
			return a1.compareTo(address2CompatibleWith1);
		}

		/** Returns whether the objects are the same with respect to the
		 *  program difference type this comparator is interested in.
		 *  Returns whether the memory, stack and external references are
		 *  the same for the mnemonic, operand, and value at the indicated address.
		 * @param obj1 the first address object
		 * @param obj2 the second address object
		 * @return true if the references are the same at the indicated address.
		 */
		@Override
		public boolean isSame(Object obj1, Object obj2) {
			Address addr1 = (Address) obj1;
			Address addr2 = (Address) obj2;
			// Check the references.
			Reference[] refs1 = rm1.getReferencesFrom(addr1);
			Reference[] refs2 = rm2.getReferencesFrom(addr2);
			// Want to compare refs other than fallthrough refs.
			Reference[] diffRefs1 = getDiffRefs(refs1);
			Reference[] diffRefs2 = getDiffRefs(refs2);
			Arrays.sort(diffRefs1);
			Arrays.sort(diffRefs2);
			return equalRefArrays(diffRefs1, diffRefs2);
		}

		/** Returns the addresses that are to indicate the difference of this
		 *  comparison type for this object.
		 * @param obj the object being examined by this comparator.
		 * @param program the program the object is associated with.
		 * @return the addresses that we want to indicate for a difference
		 * of this comparison type.
		 * The addresses in this address set are derived from the specified program.
		 */
		@Override
		public AddressSet getAddressSet(Object obj, Program program) {
			AddressSet addrs = new AddressSet();
			if (obj == null) {
				return addrs;
			}
			Address addr = (Address) obj;
			CodeUnit cu = program.getListing().getCodeUnitContaining(addr);
			if (cu != null) {
				addrs.addRange(cu.getMinAddress(), cu.getMaxAddress());
			}
			return addrs;
		}
	}

	/**
	 * Gets the references that need to be checked for differences from those that are handed
	 * to it via the refs parameter.
	 * @param refs the references before removing those that we don't want to diff.
	 * @return only the references that should be part of the diff.
	 */
	public static Reference[] getDiffRefs(Reference[] refs) {
		List<Reference> refList = new ArrayList<>();
		for (Reference reference : refs) {
			if (reference.getReferenceType().isFallthrough()) {
				continue; // Discard fallthrough refs, which are handled by Instruction.
			}
			refList.add(reference);
		}
		return refList.toArray(new Reference[refList.size()]);
	}

	/** Compares two code units to determine if their user defined properties differ.
	 */
	private class UserDefinedComparator extends CodeUnitComparator {
		/** The name of the user defined property to be compared. */
		String propertyName;

		/** Constructor for comparing program differences.
		 * @param program1 the first program
		 * @param program2 the second program
		 * @param property the name of the user defined property to be
		 * compared in program1 and program2.
		 */
		private UserDefinedComparator(Program program1, Program program2, String property) {
			super(program1, program2);
			this.propertyName = property;
		}

		/** Returns whether the code units have the same user defined properties.
		 * @param obj1 the first code unit object
		 * @param obj2 the second code unit object
		 * @return true if the code unit objects have the same user defined
		 * properties.
		 */
		@Override
		public boolean isSame(Object obj1, Object obj2) {
			CodeUnit cu1 = (CodeUnit) obj1;
			CodeUnit cu2 = (CodeUnit) obj2;
			Object p1 = null;
			Object p2 = null;
			p1 = getProperty(cu1, propertyName);
			p2 = getProperty(cu2, propertyName);
			return SystemUtilities.isEqual(p1, p2);
		}

		private Object getProperty(CodeUnit cu, String localPropertyName) {
			Object obj = null;
			if (cu.hasProperty(localPropertyName)) {
				// int property.
				try {
					int intProp = cu.getIntProperty(localPropertyName);
					return new Integer(intProp);
				}
				catch (NoValueException e) {
					// Do nothing. Instead fall-through to next property type.
				}
				catch (TypeMismatchException e) {
					// Do nothing. Instead fall-through to next property type.
				}

				// String property.
				try {
					String stringProp = cu.getStringProperty(localPropertyName);
					return stringProp;
				}
				catch (TypeMismatchException e) {
					// Do nothing. Instead fall-through to next property type.
				}

				// Object (Saveable) property.
				try {
					Saveable objProp = cu.getObjectProperty(localPropertyName);
					return objProp;
				}
				catch (TypeMismatchException e) {
					// Do nothing. Instead fall-through to next property type.
				}

				// void property.
				try {
					boolean voidProp = cu.getVoidProperty(localPropertyName);
					return new Boolean(voidProp);
				}
				catch (TypeMismatchException e) {
					// Do nothing. Instead fall-through to next property type.
				}
			}
			return obj;
		}
	}

	/** Provides comparisons between two instruction code units.
	 */
	private class InstructionComparator extends CodeUnitComparator {
		/** Constructor for comparing program differences.
		 * @param program1 the first program
		 * @param program2 the second program
		 */
		private InstructionComparator(Program program1, Program program2) {
			super(program1, program2);
		}

		/** Returns whether the two instructions are the same.
		 * @param obj1 the first instruction object
		 * @param obj2 the second instruction object
		 * @return true if the instruction objects are the same.
		 */
		@Override
		public boolean isSame(Object obj1, Object obj2) {
			Instruction i1 = (Instruction) obj1;
			Instruction i2 = (Instruction) obj2;
			if (i1 == i2) {
				return true;
			}
			if (i1.getLength() != i2.getLength()) {
				return false;
			}

			if (!equivalentInstructionPrototypes(i1, i2)) {
				return false;
			}

			if (i1.getFlowOverride() != i2.getFlowOverride()) {
				return false;
			}

			if (!isSameFallthrough(program1, i1, program2, i2)) {
				return false;
			}

			try {
				if (!Arrays.equals(i1.getBytes(), i2.getBytes())) {
					return false; // bytes differ
				}
			}
			catch (MemoryAccessException e) {
				String message =
					"Diff couldn't get the underlying bytes when comparing instructions." +
						" instruction1 is at " + i1.getAddress().toString(true) +
						". instruction2 is at " + i2.getAddress().toString(true) + ".  " +
						e.getMessage();
				Msg.error(this, message, e);
				return false;
			}

			return true;
		}
	}

	static boolean equivalentInstructionPrototypes(Instruction i1, Instruction i2) {
		// Can't compare prototypes if languages are not the exact same language
		boolean samePrototypes = false;
		if (i1.getPrototype().getLanguage().equals(i2.getPrototype().getLanguage())) {
			samePrototypes = i1.getPrototype().equals(i2.getPrototype());
		}
		else {
			samePrototypes = i1.toString().equals(i2.toString());
		}
		return samePrototypes;
	}

	/**
	 * Determines whether the fallthrough is the same for the two indicated instructions.
	 * @param program1 the program for the first instruction
	 * @param i1 the first instruction
	 * @param program2 the program for the second instruction
	 * @param i2 the second instruction
	 * @return true if the fallthrough is the same for the two instructions.
	 */
	static boolean isSameFallthrough(Program program1, Instruction i1, Program program2,
			Instruction i2) {
		boolean overridden1 = i1.isFallThroughOverridden();
		boolean overridden2 = i2.isFallThroughOverridden();
		if (overridden1 != overridden2) {
			return false;
		}
		// If instruction in program1 has modified fall through, then does it match program2.
		Address fallThrough1 = i1.getFallThrough();
		Address fallThrough1As2 =
			SimpleDiffUtility.getCompatibleAddress(program1, fallThrough1, program2);
		if (!SystemUtilities.isEqual(i2.getFallThrough(), fallThrough1As2)) {
			return false;
		}
		return true;
	}

	/** Provides comparisons between two defined data code units.
	 */
	private class DefinedDataComparator extends CodeUnitComparator {
		/** Constructor for comparing program differences.
		 * @param program1 the first program
		 * @param program2 the second program
		 */
		private DefinedDataComparator(Program program1, Program program2) {
			super(program1, program2);
		}

		/** Returns whether the two defined data objects are the same.
		 * @param obj1 the first defined data object
		 * @param obj2 the second defined data object
		 * @return true if the defined data objects are the same.
		 */
		@Override
		public boolean isSame(Object obj1, Object obj2) {
			Data d1 = (Data) obj1;
			Data d2 = (Data) obj2;
			if (d1.getLength() != d2.getLength()) {
				return false;
			}
			ghidra.program.model.data.DataType dt1 = d1.getDataType();
			ghidra.program.model.data.DataType dt2 = d2.getDataType();
			if (!dt1.isEquivalent(dt2)) {
				return false;
			}
			// Detect that data type name or path differs?
			if (!dt1.getPathName().equals(dt2.getPathName())) {
				return false;
			}

			return true;
		}
	}

	/** An IteratorWrapper provides a common class for accessing the methods
	 * for several different iterator types (Iterator, CodeUnitIterator, and
	 * AddressIterator).
	 */
	private static class IteratorWrapper {

		/** The iterator that this object wraps. */
		Object iterator;

		/** Creates a wrapper for the specified iterator.
		 * @param iterator the iterator object.
		 * Must be Iterator, AddressIterator, or CodeUnitIterator. */
		public IteratorWrapper(Object iterator) {
			this.iterator = iterator;
		}

		/**
		 * Returns <tt>true</tt> if the iteration has more elements. (In other
		 * words, returns <tt>true</tt> if <tt>next</tt> would return an element
		 * rather than throwing an exception.)
		 *
		 * @return <tt>true</tt> if the iterator has more elements.
		 */
		public boolean hasNext() {
			if (iterator instanceof AddressIterator) {
				return ((AddressIterator) iterator).hasNext();
			}
			else if (iterator instanceof CodeUnitIterator) {
				return ((CodeUnitIterator) iterator).hasNext();
			}
			else if (iterator instanceof SymbolIterator) {
				return ((SymbolIterator) iterator).hasNext();
			}
			else if (iterator instanceof FunctionIterator) {
				return ((FunctionIterator) iterator).hasNext();
			}
			return false;
		}

		/** Returns the next element in the iteration.
		 *
		 * @return the next element in the iteration.
		 * @exception NoSuchElementException iteration has no more elements.
		 */
		public Object next() throws java.util.NoSuchElementException {
			if (iterator instanceof AddressIterator) {
				return ((AddressIterator) iterator).next();
			}
			else if (iterator instanceof CodeUnitIterator) {
				return ((CodeUnitIterator) iterator).next();
			}
			else if (iterator instanceof SymbolIterator) {
				return ((SymbolIterator) iterator).next();
			}
			else if (iterator instanceof FunctionIterator) {
				return ((FunctionIterator) iterator).next();
			}
			return null;
		}

	}

	private class SymbolNameComparator implements Comparator<Symbol> {
		SymbolNameComparator() {
		}

		@Override
		public int compare(Symbol s1, Symbol s2) {
			int comparison = s1.getName().compareTo(s2.getName());
			return comparison;
		}
	}

	static boolean equivalentSymbols(Program p1, Program p2, Symbol p1Symbol, Symbol p2Symbol) {
		if (p1Symbol == p2Symbol) {
			return true;
		}
		if (p1Symbol == null) {
			return (p2Symbol == null);
		}
		if (p2Symbol == null) {
			return false;
		}
		SourceType p1SourceType = (p1Symbol instanceof GlobalSymbol) ? null : p1Symbol.getSource();
		SourceType p2SourceType = (p2Symbol instanceof GlobalSymbol) ? null : p2Symbol.getSource();
		if (p1SourceType != p2SourceType) {
			return false;
		}
		if ((p1SourceType != SourceType.DEFAULT) &&
			!p1Symbol.getName().equals(p2Symbol.getName())) {
			return false;
		}
		if (p1Symbol.isDynamic()) {
			return p2Symbol.isDynamic();
		}
		else if (p2Symbol.isDynamic()) {
			return false;
		}
		Address p1SymbolAddress = p1Symbol.getAddress();
		Address p2SymbolAddress = p2Symbol.getAddress();
		Address p2SymbolAddressAsP1 =
			SimpleDiffUtility.getCompatibleAddress(p2, p2SymbolAddress, p1);
		if (!p1SymbolAddress.equals(p2SymbolAddressAsP1)) {
			return false;
		}
		if (!p1Symbol.getSymbolType().equals(p2Symbol.getSymbolType())) {
			return false;
		}
		if (p1Symbol.isPrimary() != p2Symbol.isPrimary()) {
			return false;
		}
		if (p1Symbol.isPinned() != p2Symbol.isPinned()) {
			return false;
		}

		Symbol p1Parent = p1Symbol.getParentSymbol();
		Symbol p2Parent = p2Symbol.getParentSymbol();
		if (!equivalentSymbols(p1, p2, p1Parent, p2Parent)) {
			return false;
		}
		return true;
	}

	static boolean equivalentSymbols(AddressTranslator p2ToP1Translator, Symbol p1Symbol,
			Symbol p2Symbol) {
		if (p1Symbol == p2Symbol) {
			return true;
		}
		if (p1Symbol == null) {
			return (p2Symbol == null);
		}
		if (p2Symbol == null) {
			return false;
		}
		if (p1Symbol.isDynamic()) {
			return p2Symbol.isDynamic();
		}
		else if (p2Symbol.isDynamic()) {
			return false;
		}
		SourceType p1SourceType = (p1Symbol instanceof GlobalSymbol) ? null : p1Symbol.getSource();
		SourceType p2SourceType = (p2Symbol instanceof GlobalSymbol) ? null : p2Symbol.getSource();
		if (p1SourceType != p2SourceType) {
			return false;
		}
		if ((p1SourceType != SourceType.DEFAULT) &&
			!p1Symbol.getName().equals(p2Symbol.getName())) {
			return false;
		}
		Address p1SymbolAddress = p1Symbol.getAddress();
		Address p2SymbolAddress = p2Symbol.getAddress();
		Address p2SymbolAddressAsP1 = p2ToP1Translator.getAddress(p2SymbolAddress);
		if (!p1SymbolAddress.equals(p2SymbolAddressAsP1)) {
			return false;
		}
		if (!p1Symbol.getSymbolType().equals(p2Symbol.getSymbolType())) {
			return false;
		}
		if (p1Symbol.isPrimary() != p2Symbol.isPrimary()) {
			return false;
		}
		if (p1Symbol.isPinned() != p2Symbol.isPinned()) {
			return false;
		}

		Symbol p1Parent = p1Symbol.getParentSymbol();
		Symbol p2Parent = p2Symbol.getParentSymbol();
		if (!equivalentSymbols(p2ToP1Translator, p1Parent, p2Parent)) {
			return false;
		}
		return true;
	}

}
