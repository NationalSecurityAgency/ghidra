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

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * <CODE>ProgramMergeManager</CODE> is a class for merging the differences between two
 * programs as specified by a <CODE>ProgramMergeFilter</CODE> and the address 
 * ranges to be merged.
 * <P>Program1 is the program being modified by the merge. Program2 is source
 * for obtaining differences to apply to program1.
 * <P>
 * <CODE>ProgramDiff</CODE> is being used to determine the differences between
 * the two programs.
 * <P>If name conflicts occur while merging, the item (for example, symbol) will
 * be merged with a new name that consists of the original name followed by "_conflict"
 * and a one up number.
 * 
 * @see ghidra.program.util.ProgramMergeFilter
 * @see ghidra.program.util.ProgramDiff
 */

public class ProgramMergeManager {
	private StringBuffer errorMsg;
	private StringBuffer infoMsg;
	/** The first program (used as read only) for the merge. */
	private Program program1;
	/** The second program (used as read only) for the merge. */
	private Program program2;
	/** The last filter externally applied to the ProgramDiff. */
	private ProgramDiffFilter diffFilter;
	/** Differences between program1 and program2 determined thus far. */
	private ProgramDiff programDiff;
	private ProgramMergeFilter mergeFilter;
	private ProgramMerge merger;

	/**
	 * <CODE>ProgramMergeManager</CODE> allows the merging of differences from program1
	 * or program2 into the merged program.
	 *
	 * @param program1 the first program (read only) for the merge.
	 * @param program2 the second program (read only) for the merge.
	 * @param monitor the task monitor for indicating progress at determining
	 *  the differences. This also allows the user to cancel the merge.
	 *
	 * @throws ProgramConflictException if the memory blocks, that overlap
	 * between the two programs, do not match. This indicates that programs
	 * couldn't be compared to determine the differences.
	 */
	public ProgramMergeManager(Program program1, Program program2, TaskMonitor monitor)
			throws ProgramConflictException {
		this(program1, program2, null, monitor);
	}

	/**
	 * <CODE>ProgramMergeManager</CODE> allows the merging of differences from program1
	 * or program2 into the merged program.
	 *
	 * @param program1 the first program for the merge. This program will get 
	 * modified by merge.
	 * @param program2 the second program (read only) for the merge.
	 * @param p1LimitedAddressSet the limited address set. program differences
	 * can only be merged if they overlap this address set. null means find
	 * differences in each of the entire programs.
	 * The addresses in this set should be derived from program1.
	 * @param monitor the task monitor for indicating progress at determining
	 *  the differences. This also allows the user to cancel the merge.
	 *
	 * @throws ProgramConflictException if the memory blocks, that overlap
	 * between the two programs, do not match. This indicates that programs
	 * couldn't be compared to determine the differences.
	 */
	public ProgramMergeManager(Program program1, Program program2,
			AddressSetView p1LimitedAddressSet, TaskMonitor monitor)
			throws ProgramConflictException {
		this.program1 = program1;
		this.program2 = program2;
		if (program1 == null || program2 == null) {
			throw new IllegalArgumentException("program cannot be null.");
		}

		// Create a diff between programs and check the memory blocks for conflicts.
		// This is used to get the differences as needed.
		programDiff = new ProgramDiff(program1, program2, p1LimitedAddressSet);
		diffFilter = programDiff.getFilter();
		mergeFilter = new ProgramMergeFilter();
		merger = new ProgramMerge(program1, program2);
		errorMsg = new StringBuffer();
		infoMsg = new StringBuffer();
	}

	/**
	 * Determine whether memory between the two programs matches.
	 * For example, if one program has more memory than the other then it 
	 * doesn't match or if the address ranges for memory are different for 
	 * the two programs then they don't match.
	 * @return whether the memory matches between the two programs.
	 */
	public boolean memoryMatches() {
		return programDiff.memoryMatches();
	}

	/** Gets the filtered program differences for this merge. Only differences are
	 * indicated for merge filter categories that are enabled and for address
	 * that have not been marked as ignored.
	 * @return the program differences.
	 * The addresses in this address set are derived from program2.
	 */
	public AddressSetView getFilteredDifferences() {
		AddressSetView p2DiffSet = null;
		try {
			p2DiffSet = programDiff.getDifferences(diffFilter, null);
		}
		catch (CancelledException e) {
			// Shouldn't ever throw cancelled since this method uses a dummy monitor.
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
		return new AddressSet(p2DiffSet);
	}

	/** Gets the filtered program differences for this merge. Only differences are
	 * indicated for merge filter categories that are enabled and for address
	 * that have not been marked as ignored.
	 * @param monitor the task monitor for indicating the progress of
	 * determining differences. This monitor also allows the user to cancel if
	 * the diff takes too long. If no monitor is desired, use null.
	 * @return the program differences.
	 * The addresses in this address set are derived from program2.
	 */
	public AddressSetView getFilteredDifferences(TaskMonitor monitor) throws CancelledException {
		return new AddressSet(programDiff.getDifferences(diffFilter, monitor));
	}

	/** 
	 * Get a copy of the diff filter that the merge is using.
	 */
	public ProgramDiffFilter getDiffFilter() {
		return diffFilter;
	}

	/** 
	 * Set the filter that indicates which parts of the Program should be 
	 * diffed.
	 * @param filter the filter indicating the types of differences to be 
	 * determined by this ProgramMerge.
	 */
	public void setDiffFilter(ProgramDiffFilter filter) {
		programDiff.setFilter(filter);
		diffFilter = programDiff.getFilter();
	}

	/** 
	 * Get a copy of the filter that indicates which parts of the Program 
	 * should be merged.
	 */
	public ProgramMergeFilter getMergeFilter() {
		return new ProgramMergeFilter(mergeFilter);
	}

	/** 
	 * Set the filter that indicates which parts of the Program should be 
	 * applied from the second program to the first program.
	 * @param filter the filter indicating the types of differences to apply.
	 */
	public void setMergeFilter(ProgramMergeFilter filter) {
		if (filter != null) {
			this.mergeFilter = new ProgramMergeFilter(filter);
		}
		else {
			this.mergeFilter = new ProgramMergeFilter();
		}
	}

	/** Returns the addresses from combining the address sets in program1 and program2
	 * @return the addresses for both program1 and program2.
	 * The addresses in this address set are derived from program1.
	 */
	public AddressSetView getCombinedAddresses() {
		return programDiff.getCombinedAddresses();
	}

	/** Returns the addresses in common between program1 and program2
	 * @return the addresses in common between program1 and program2.
	 * The addresses in this address set are derived from program1.
	 */
	public AddressSetView getAddressesInCommon() {
		return programDiff.getAddressesInCommon();
	}

	/** Returns the addresses that are in program1, but not in program2
	 * @return the addresses that are in program1, but not in program2.
	 * The addresses in this address set are derived from program1.
	 */
	public AddressSetView getAddressesOnlyInOne() {
		return programDiff.getAddressesOnlyInOne();
	}

	/** Returns the addresses that are in program2, but not in program1
	 * @return the addresses that are in program2, but not in program1.
	 * The addresses in this address set are derived from program2.
	 */
	public AddressSetView getAddressesOnlyInTwo() {
		return programDiff.getAddressesOnlyInTwo();
	}

	/** Gets the first program being compared by the ProgramDiff.
	 * @return program1. This is the program being modified by the merge.
	 * The addresses in this address set are derived from program1.
	 */
	public Program getProgramOne() {
		return program1;
	}

	/** Gets the second program being compared by the ProgramDiff.
	 * @return program2. This is the program for obtaining the program information to merge.
	 */
	public Program getProgramTwo() {
		return program2;
	}

	/**
	 * Get the address set indicating the addresses to be ignored (not checked) when determining
	 * differences between the two programs.
	 * @return the set of addresses to ignore.
	 * The addresses in this address set are derived from program1.
	 */
	public AddressSetView getIgnoreAddressSet() {
		return programDiff.getIgnoreAddressSet();
	}

	/**
	 * Get the address set that the process of determining differences is limited to. 
	 * In other words, only addresses in this set will be checked by the Diff.
	 * @return the address set
	 * The addresses in this address set are derived from program1.
	 */
	public AddressSetView getLimitedAddressSet() {
		return programDiff.getLimitedAddressSet();
	}

	/**
	 * Gets a string indicating warnings that occurred during the initial Diff 
	 * of the two programs.
	 * @return the warnings
	 */
	public String getWarnings() {
		return programDiff.getWarnings();
	}

	/** Merge the differences from the indicated program at the specified
	 *  address with the indicated filtering.
	 * @param p2Address the address to be merged. 
	 * This address should be derived from program2.
	 * @param filter the filter indicating what types of differences to merge.
	 * @return true if merge succeeds
	 * 
	 * @throws MemoryAccessException if bytes can't be copied.
	 * @throws CancelledException if user cancels via the monitor.
	 */
	public boolean merge(Address p2Address, ProgramMergeFilter filter)
			throws MemoryAccessException, CancelledException {
		return merge(p2Address, filter, (TaskMonitor) null);
	}

	/** Merge the differences from the indicated program at the specified
	 *  address with the current filtering.
	 * @param p2Address the address to be merged. 
	 * This address should be derived from program2.
	 * @param monitor monitor for reporting merge status to the user.
	 * @return true if merge succeeds
	 * 
	 * @throws MemoryAccessException if bytes can't be copied.
	 * @throws CancelledException if user cancels via the monitor.
	 */
	public boolean merge(Address p2Address, TaskMonitor monitor) throws MemoryAccessException,
			CancelledException {
		return merge(p2Address, mergeFilter, monitor);
	}

	/** Merge the differences from the indicated program at the specified
	 *  address with the indicated filtering.
	 * @param p2Address the address to be merged. 
	 * This address should be derived from program2.
	 * @param filter the filter indicating what types of differences to merge.
	 * @param monitor monitor for reporting merge status to the user.
	 * @return true if merge succeeds
	 * 
	 * @throws MemoryAccessException if bytes can't be copied.
	 * @throws CancelledException if user cancels via the monitor.
	 */
	public boolean merge(Address p2Address, ProgramMergeFilter filter, TaskMonitor monitor)
			throws MemoryAccessException, CancelledException {
		AddressSet p2AddressSet = new AddressSet(new AddressRangeImpl(p2Address, p2Address));
		return merge(p2AddressSet, filter, monitor);
	}

	/** Ignore the differences for the indicated address set.
	 * @param p1AddressSet the address set to be merged. 
	 * The addresses in this set should be derived from program1.
	 */
	public void ignore(AddressSetView p1AddressSet) {
		programDiff.ignore(p1AddressSet);
	}

	/** Restrict the resulting differences to the indicated address set.
	 * Although the Diff will check for differences based on the limited set, the resulting
	 * differences from calls to getDifferences() will only return addresses contained in
	 * this restricted address set.
	 * @param p1AddressSet the address set to restrict the getFilteredDifferences() to.
	 * The addresses in this set are derived from program1.
	 */
	public void restrictResults(AddressSetView p1AddressSet) {
		programDiff.setRestrictedAddressSet(p1AddressSet);
	}

	/** Return the address set that is currently being used to restrict the
	 * differences that get returned.
	 * @return the address set being used to restrict the Diff results.
	 * The addresses in this set are derived from program1.
	 */
	public AddressSetView getRestrictedAddressSet() {
		return programDiff.getRestrictedAddressSet();
	}

	/** Remove the restriction for the resulting differences to the indicated address set.
	 */
	public void removeResultRestrictions() {
		programDiff.removeRestrictedAddressSet();
	}

	/**
	 * Get the error messages that resulted from doing the merge.
	 * @return String empty string if there were no problems with the merge.
	 */
	public String getErrorMessage() {
		errorMsg.append(merger.getErrorMessage());
		merger.clearErrorMessage();
		return errorMsg.toString();
	}

	/**
	 * Get the informational messages that resulted from doing the merge.
	 * @return String empty string if there were no information messages
	 * generated during the merge.
	 */
	public String getInfoMessage() {
		infoMsg.append(merger.getInfoMessage());
		merger.clearInfoMessage();
		return infoMsg.toString();
	}

	void clearMessages() {
		if (infoMsg.length() > 0) {
			infoMsg = new StringBuffer();
		}
		if (errorMsg.length() > 0) {
			errorMsg = new StringBuffer();
		}
	}

	/** Merge the differences from the indicated program on the specified
	 *  address set with the indicated filtering.
	 * @param p1MergeSet the address set to be merged. 
	 * The addresses in this set should be derived from program1.
	 * @param filter the filter indicating what types of differences to merge.
	 * @return true if merge succeeds
	 * 
	 * @throws MemoryAccessException if bytes can't be copied.
	 * @throws CancelledException if user cancels via the monitor.
	 */
	public boolean merge(AddressSetView p1MergeSet, ProgramMergeFilter filter)
			throws MemoryAccessException, CancelledException {
		return merge(p1MergeSet, filter, (TaskMonitor) null);
	}

	/** Merge the differences from the indicated program on the specified
	 *  address set with the filtering that is currently set.
	 * @param p1MergeSet the address set to be merged
	 * The addresses in this set should be derived from program1.
	 * @param monitor task monitor for reporting merge status to the user.
	 * @return true if merge succeeds
	 * 
	 * @throws MemoryAccessException if bytes can't be copied.
	 * @throws CancelledException if user cancels via the monitor.
	 */
	public boolean merge(AddressSetView p1MergeSet, TaskMonitor monitor)
			throws MemoryAccessException, CancelledException {
		return merge(p1MergeSet, mergeFilter, monitor);
	}

	/** Merge the differences from the indicated program on the specified
	 *  address set with the indicated filtering.
	 * @param p1MergeSet the address set to be merged
	 * The addresses in this set should be derived from program1.
	 * @param filter the filter indicating what types of differences to merge.
	 * @param monitor task monitor for reporting merge status to the user.
	 * @return true if merge succeeds
	 * 
	 * @throws MemoryAccessException if bytes can't be copied.
	 * @throws CancelledException if user cancels via the monitor.
	 */
	public boolean merge(AddressSetView p1MergeSet, ProgramMergeFilter filter, TaskMonitor monitor)
			throws MemoryAccessException, CancelledException {
		clearMessages();
		merger.clearMessages();
		merger.clearDuplicateSymbols();
		merger.clearDuplicateEquates();
		AddressSet p1CodeUnitSet = DiffUtility.getCodeUnitSet(p1MergeSet, this.program1);
		if (monitor == null) {
			// Create a "do nothing" task monitor that we can pass along.
			monitor = TaskMonitorAdapter.DUMMY_MONITOR;
		}

		// Check that the needed memory addresses are available in the merge program.
		if (!hasMergeAddresses(p1MergeSet)) {
			errorMsg.append("The Difference cannot be applied.\n"
				+ "The program does not have memory defined\n"
				+ "for some of the indicated addresses.\n");
			return false;
		}

		// NOTE: The order in which the following merge methods are called
		//       is important in some cases. For example, calling the
		//       mergeReferences() before mergeLabels() would lead to extra
		//       default labels appearing in the merge program. Also, you
		//       want to apply code unit differences before applying
		//       other merge differences to them.

		mergeBytes(p1MergeSet, filter, monitor);
		mergeProgramContext(p1MergeSet, filter, monitor);
		mergeCodeUnits(p1MergeSet, filter, monitor); // Code Units should  follow program context.
		mergeComments(p1MergeSet, filter, monitor);
		mergeFunctions(p1MergeSet, filter, monitor); // Functions should follow code units.
		// Note: This should follow code units and functions so that we already
		//       have a "FUN..." label since we can't create default labels.
		mergeLabels(p1MergeSet, filter, monitor); // Labels should follow code units & functions.
		mergeReferences(p1MergeSet, filter, monitor); // References should follow labels and code units.
		mergeBookmarks(p1MergeSet, filter, monitor);
		mergeProperties(p1MergeSet, filter, monitor);
		mergeFunctionTags(p1MergeSet, filter, monitor);

		merger.reApplyDuplicateEquates();
		String dupEquatesMessage = merger.getDuplicateEquatesInfo();
		if (dupEquatesMessage.length() > 0) {
			infoMsg.append(dupEquatesMessage);
		}

		merger.reApplyDuplicateSymbols();
		String dupSymbolsMessage = merger.getDuplicateSymbolsInfo();
		if (dupSymbolsMessage.length() > 0) {
			infoMsg.append(dupSymbolsMessage);
		}

		programDiff.reDiffSubSet(p1CodeUnitSet, monitor);
		return (errorMsg.length() == 0 && !merger.hasErrorMessage());
	}

	private boolean hasMergeAddresses(AddressSetView p1AddressSet) {
		if (program1.getMemory().contains(p1AddressSet)) {
			return true;
		}
		return false;
	}

	/**
	 * <CODE>mergeProgramContext</CODE> merges all program context register values
	 * (as indicated) in the specified address set from the second program. 
	 * It merges them into the merge program.
	 *
	 * @param p1MergeSet the addresses to be merged.
	 * The addresses in this set should be derived from program1.
	 * @param filter the current merge filter settings indicating what types
	 * of differences should be merged.
	 * @param monitor the task monitor for notifying the user of this merge's
	 * progress.
	 * 
	 * @throws CancelledException if user cancels via the monitor.
	 */
	void mergeProgramContext(AddressSetView p1MergeSet, ProgramMergeFilter filter,
			TaskMonitor monitor) throws CancelledException {

		monitor.setMessage("Applying Program Context...");
		if (filter.getFilter(ProgramMergeFilter.PROGRAM_CONTEXT) == ProgramMergeFilter.IGNORE) {
			return;
		}

		ProgramDiffFilter programContextDiffFilter =
			new ProgramDiffFilter(ProgramDiffFilter.PROGRAM_CONTEXT_DIFFS);
		AddressSet diffAddrSet =
			p1MergeSet.intersect(programDiff.getDifferences(programContextDiffFilter, monitor));
		AddressSet diffAddrSet2 = DiffUtility.getCompatibleAddressSet(diffAddrSet, program2);
		if (diffAddrSet2.isEmpty()) {
			return;
		}
		merger.mergeProgramContext(diffAddrSet2, monitor);
	}

	/** <CODE>mergeBytes</CODE> merges byte differences within the specified
	 *  address set. The program number indicates whether to get the bytes from
	 *  program1 or program2 of the merge.
	 *
	 * @param p1MergeSet the addresses to be merged.
	 * The addresses in this set should be derived from program1.
	 * @param filter the current merge filter settings indicating what types
	 * of differences should be merged.
	 * @param monitor the task monitor for notifying the user of this merge's
	 * progress.
	 * 
	 * @throws MemoryAccessException if bytes can't be merged.
	 * @throws CancelledException if user cancels via the monitor.
	 */
	void mergeBytes(AddressSetView p1MergeSet, ProgramMergeFilter filter, TaskMonitor monitor)
			throws MemoryAccessException, CancelledException {
		int setting = filter.getFilter(ProgramMergeFilter.BYTES);
		if (setting == ProgramMergeFilter.IGNORE) {
			return;
		}

		ProgramDiffFilter byteDiffFilter = new ProgramDiffFilter(ProgramDiffFilter.BYTE_DIFFS);
		AddressSet diffAddrSet =
			p1MergeSet.intersect(programDiff.getDifferences(byteDiffFilter, monitor));
		AddressSet diffAddrSet2 = DiffUtility.getCompatibleAddressSet(diffAddrSet, program2);
		if (diffAddrSet2.isEmpty()) {
			return;
		}
		merger.mergeBytes(diffAddrSet2,
			filter.getFilter(ProgramMergeFilter.INSTRUCTIONS) != ProgramMergeFilter.REPLACE,
			monitor);
	}

	/**
	 * <CODE>mergeCodeUnits</CODE> merges all instructions and/or data
	 * (as indicated) in the specified address set from the second program. 
	 * It merges them into the merge program. When merging
	 * instructions, the bytes are also moved if they differ.
	 *
	 * @param p1MergeSet the addresses to be merged.
	 * The addresses in this set should be derived from program1.
	 * @param filter the current merge filter settings indicating what types
	 * of differences should be merged.
	 * @param monitor the task monitor for notifying the user of this merge's
	 * progress.
	 * 
	 * @throws MemoryAccessException if bytes can't be copied.
	 */
	void mergeCodeUnits(AddressSetView p1MergeSet, ProgramMergeFilter filter, TaskMonitor monitor)
			throws MemoryAccessException, CancelledException {
		boolean mergeInstructions =
			(filter.getFilter(ProgramMergeFilter.INSTRUCTIONS) == ProgramMergeFilter.REPLACE);
		boolean mergeData =
			(filter.getFilter(ProgramMergeFilter.DATA) == ProgramMergeFilter.REPLACE);
		if (!mergeInstructions && !mergeData) {
			return;
		}

		AddressSet byteDiffs2 = null;
		ProgramDiffFilter byteDiffFilter = new ProgramDiffFilter(ProgramDiffFilter.BYTE_DIFFS);
		if (filter.getFilter(ProgramMergeFilter.BYTES) == ProgramMergeFilter.IGNORE) {
			byteDiffs2 =
				DiffUtility.getCompatibleAddressSet(
					programDiff.getDifferences(byteDiffFilter, monitor), program2);
		}

		// ** Equates **
		ProgramDiffFilter equateDiffFilter = new ProgramDiffFilter(ProgramDiffFilter.EQUATE_DIFFS);
		AddressSetView equateDiffs1 = programDiff.getDifferences(equateDiffFilter, monitor);
		AddressSet equateDiffSet1 = equateDiffs1.intersect(p1MergeSet);
		AddressSet equateDiffSet2 = DiffUtility.getCompatibleAddressSet(equateDiffSet1, program2);

		// ** Code Units (Instructions/Data) **
		ProgramDiffFilter cuDiffFilter = new ProgramDiffFilter(ProgramDiffFilter.CODE_UNIT_DIFFS);
		AddressSetView codeUnitDiffs1 = programDiff.getDifferences(cuDiffFilter, monitor);
		AddressSet codeUnitDiffSet1 = codeUnitDiffs1.intersect(p1MergeSet);
		AddressSet codeUnitDiffSet2 =
			DiffUtility.getCompatibleAddressSet(codeUnitDiffSet1, program2);
		// MergeCodeUnits won't clear any code units where instruction prototypes match.
		merger.mergeCodeUnits(codeUnitDiffSet2, byteDiffs2, false, monitor);

		// Merge the references anywhere we replaced code units. 
		// Do a merge of references rather than replace so that we don't lose any non-default 
		// references where the instruction prototypes matched.
		// Use only the source's default references if we are ignoring reference diffs.
		boolean ignoreReferenceDiffs =
			filter.getFilter(ProgramMergeFilter.REFERENCES) == ProgramMergeFilter.IGNORE;
		boolean onlyKeepDefaults = ignoreReferenceDiffs;
		merger.mergeReferences(codeUnitDiffSet2, onlyKeepDefaults, monitor);

		merger.mergeEquates(equateDiffSet2, monitor);
	}

	/**
	 * Determines which addresses in the given set contain function tag differences 
	 * between the two programs being compared. This address set is then passed
	 * to the {@link ProgramMerge} to be processed.
	 *  
	 * @param p1AddressSet the address set to be merged
	 * @param filter the types of differences to merge
	 * @param monitor task monitor
	 */
	void mergeFunctionTags(AddressSetView p1AddressSet, ProgramMergeFilter filter,
			TaskMonitor monitor) {
		int applyTags = filter.getFilter(ProgramMergeFilter.FUNCTION_TAGS);
		int diffType = ProgramDiffFilter.FUNCTION_DIFFS;

		try {
			AddressSetView p1DiffSet =
				programDiff.getDifferences(new ProgramDiffFilter(diffType), monitor);
			AddressSet p1MergeSet = p1DiffSet.intersect(p1AddressSet);
			AddressSet p2MergeSet = DiffUtility.getCompatibleAddressSet(p1MergeSet, program2);

			merger.applyFunctionTagChanges(p2MergeSet, applyTags, null, null, monitor);
		}
		catch (CancelledException e1) {
			// user cancellation
		}
	}

	/**
	 * <CODE>mergeComments</CODE> merges all comments
	 * in the specified address set from the second program 
	 * based on the current merge filter setting.
	 * It merges them into the merge program.
	 * This merges eol, pre, post, and plate comments.
	 *
	 * @param p1MergeSet the addresses to be merged.
	 * The addresses in this set should be derived from program1.
	 * @param filter the current merge filter settings indicating what types
	 * of differences should be merged.
	 * @param monitor the task monitor for notifying the user of this merge's
	 * progress.
	 */
	void mergeComments(AddressSetView p1MergeSet, ProgramMergeFilter filter, TaskMonitor monitor)
			throws CancelledException {
		int applyPlateComments = filter.getFilter(ProgramMergeFilter.PLATE_COMMENTS);
		int applyPreComments = filter.getFilter(ProgramMergeFilter.PRE_COMMENTS);
		int applyEolComments = filter.getFilter(ProgramMergeFilter.EOL_COMMENTS);
		int applyRepeatableComments = filter.getFilter(ProgramMergeFilter.REPEATABLE_COMMENTS);
		int applyPostComments = filter.getFilter(ProgramMergeFilter.POST_COMMENTS);

		mergeTypeOfComments(p1MergeSet, ProgramMergeFilter.PLATE_COMMENTS, applyPlateComments,
			monitor);
		mergeTypeOfComments(p1MergeSet, ProgramMergeFilter.PRE_COMMENTS, applyPreComments, monitor);
		mergeTypeOfComments(p1MergeSet, ProgramMergeFilter.EOL_COMMENTS, applyEolComments, monitor);
		mergeTypeOfComments(p1MergeSet, ProgramMergeFilter.REPEATABLE_COMMENTS,
			applyRepeatableComments, monitor);
		mergeTypeOfComments(p1MergeSet, ProgramMergeFilter.POST_COMMENTS, applyPostComments,
			monitor);
	}

	void mergeTypeOfComments(AddressSetView p1AddressSet, int mergeCommentType, int applyType,
			TaskMonitor monitor) throws CancelledException {
		int diffType = 0;
		switch (mergeCommentType) {
			case ProgramMergeFilter.PLATE_COMMENTS:
				diffType = ProgramDiffFilter.PLATE_COMMENT_DIFFS;
				break;
			case ProgramMergeFilter.EOL_COMMENTS:
				diffType = ProgramDiffFilter.EOL_COMMENT_DIFFS;
				break;
			case ProgramMergeFilter.PRE_COMMENTS:
				diffType = ProgramDiffFilter.PRE_COMMENT_DIFFS;
				break;
			case ProgramMergeFilter.POST_COMMENTS:
				diffType = ProgramDiffFilter.POST_COMMENT_DIFFS;
				break;
			case ProgramMergeFilter.REPEATABLE_COMMENTS:
				diffType = ProgramDiffFilter.REPEATABLE_COMMENT_DIFFS;
				break;
			default:
				return;
		}
		AddressSetView p1DiffSet =
			programDiff.getDifferences(new ProgramDiffFilter(diffType), monitor);
		AddressSet p1MergeSet = p1DiffSet.intersect(p1AddressSet);
		AddressSet p2MergeSet = DiffUtility.getCompatibleAddressSet(p1MergeSet, program2);
		merger.mergeCommentType(p2MergeSet, mergeCommentType, applyType, monitor);
	}

	/** <CODE>replaceFunctionSymbols</CODE> merges function symbol differences within the specified
	 *  address set. The program number indicates whether to get the functions from
	 *  program1 or program2 of the merge.
	 *
	 * @param p1MergeSet the addresses to be merged.
	 * The addresses in this set should be derived from program1.
	 * @param filter the current merge filter settings indicating what types
	 * of differences should be merged.
	 * @param monitor the task monitor for notifying the user of this merge's
	 * progress.
	 */
	void replaceFunctionSymbols(AddressSetView p1MergeSet, ProgramMergeFilter filter,
			TaskMonitor monitor) throws CancelledException {
		int setting = filter.getFilter(ProgramMergeFilter.FUNCTIONS);
		if (setting == ProgramMergeFilter.IGNORE) {
			return;
		}
		AddressSet p2MergeSet = DiffUtility.getCompatibleAddressSet(p1MergeSet, program2);
		merger.replaceFunctionNames(p2MergeSet, monitor);
	}

	/** <CODE>mergeFunctions</CODE> merges function differences within the specified
	 *  address set based on the current merge filter setting.
	 *
	 * @param p1MergeSet the addresses to be merged.
	 * The addresses in this set should be derived from program1.
	 * @param filter the current merge filter settings indicating what types
	 * of differences should be merged.
	 * @param monitor the task monitor for notifying the user of this merge's
	 * progress.
	 */
	void mergeFunctions(AddressSetView p1MergeSet, ProgramMergeFilter filter, TaskMonitor monitor)
			throws CancelledException {
		int setting = filter.getFilter(ProgramMergeFilter.FUNCTIONS);
		if (setting == ProgramMergeFilter.IGNORE) {
			return;
		}
		ProgramDiffFilter functionDiffFilter =
			new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);
		AddressSetView functionDiffSet = programDiff.getDifferences(functionDiffFilter, monitor);
		AddressSetView diffAddrSet = p1MergeSet.intersect(functionDiffSet);
		AddressSet diffAddrSet2 = DiffUtility.getCompatibleAddressSet(diffAddrSet, program2);
		merger.mergeFunctions(diffAddrSet2, monitor);
	}

	/**
	 * <CODE>mergeReferences</CODE> merges all references
	 * in the specified address set from the second program
	 * based on the current merge filter setting.
	 * It merges them into the merge program.
	 *
	 * @param p1MergeSet the addresses to be merged.
	 * The addresses in this set should be derived from program1.
	 * @param filter the current merge filter settings indicating what types
	 * of differences should be merged.
	 * @param monitor the task monitor for notifying the user of this merge's
	 * progress.
	 */
	void mergeReferences(AddressSetView p1MergeSet, ProgramMergeFilter filter, TaskMonitor monitor)
			throws CancelledException {
		boolean mergeRefs =
			(filter.getFilter(ProgramMergeFilter.REFERENCES) == ProgramMergeFilter.REPLACE);
		if (!mergeRefs) {
			return;
		}
		ProgramDiffFilter refDiffFilter = new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS);
		AddressSetView refDiffSet = programDiff.getDifferences(refDiffFilter, monitor);
		AddressSetView diffAddrSet = p1MergeSet.intersect(refDiffSet);
		AddressSet diffAddrSet2 = DiffUtility.getCompatibleAddressSet(diffAddrSet, program2);
		merger.replaceReferences(diffAddrSet2, monitor);
	}

	/**
	 * <CODE>mergeLabels</CODE> merges all symbols and aliases
	 * in the specified address set from the second program 
	 * based on the current merge filter setting.
	 * It merges them into the merge program.
	 *
	 * @param p1MergeSet the addresses to be merged.
	 * The addresses in this set should be derived from program1.
	 * @param filter the current merge filter settings indicating what types
	 * of differences should be merged.
	 * @param monitor the task monitor for notifying the user of this merge's
	 * progress.
	 */
	void mergeLabels(AddressSetView p1MergeSet, ProgramMergeFilter filter, TaskMonitor monitor)
			throws CancelledException {
		int setting = filter.getFilter(ProgramMergeFilter.SYMBOLS);
		boolean replacePrimary = filter.getFilter(ProgramMergeFilter.PRIMARY_SYMBOL) != 0;
		boolean replaceFunction = filter.getFilter(ProgramMergeFilter.FUNCTIONS) != 0;

		ProgramDiffFilter symbolDiffFilter = new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS);
		AddressSetView symbolDiffSet = programDiff.getDifferences(symbolDiffFilter, monitor);
		AddressSetView diffAddrSet = p1MergeSet.intersect(symbolDiffSet);
		AddressSet diffAddrSet2 = DiffUtility.getCompatibleAddressSet(diffAddrSet, program2);

		if (setting != ProgramMergeFilter.IGNORE) {
			merger.mergeLabels(diffAddrSet2, setting, replacePrimary, replaceFunction, monitor);
		}
		else if (replaceFunction) {
			merger.replaceFunctionNames(diffAddrSet2, monitor);
		}
	}

	/** <CODE>mergeBookmarks</CODE> merges bookmark differences 
	 *  within the specified address set.
	 *
	 * @param p1MergeSet the addresses to be merged.
	 * The addresses in this set should be derived from program1.
	 * @param filter the current merge filter settings indicating what types
	 * of differences should be merged.
	 * @param monitor the task monitor for notifying the user of this merge's
	 * progress.
	 */
	void mergeBookmarks(AddressSetView p1MergeSet, ProgramMergeFilter filter, TaskMonitor monitor)
			throws CancelledException {
		int setting = filter.getFilter(ProgramMergeFilter.BOOKMARKS);
		if (setting == ProgramMergeFilter.IGNORE) {
			return;
		}
		ProgramDiffFilter bookmarkDiffFilter =
			new ProgramDiffFilter(ProgramDiffFilter.BOOKMARK_DIFFS);
		AddressSetView bookmarkDiffSet = programDiff.getDifferences(bookmarkDiffFilter, monitor);
		AddressSetView diffAddrSet = p1MergeSet.intersect(bookmarkDiffSet);
		AddressSet diffAddrSet2 = DiffUtility.getCompatibleAddressSet(diffAddrSet, program2);
		merger.mergeBookmarks(diffAddrSet2, monitor);
	}

	/** <CODE>mergeProperties</CODE> merges user defined property differences 
	 *  within the specified address set based on the current merge filter setting.
	 *
	 * @param p1MergeSet the addresses to be merged.
	 * The addresses in this set should be derived from program1.
	 * @param filter the current merge filter settings indicating what types
	 * of differences should be merged.
	 * @param monitor the task monitor for notifying the user of this merge's
	 * progress.
	 */
	void mergeProperties(AddressSetView p1MergeSet, ProgramMergeFilter filter, TaskMonitor monitor)
			throws CancelledException {
		int setting = filter.getFilter(ProgramMergeFilter.PROPERTIES);
		if (setting == ProgramMergeFilter.IGNORE) {
			return;
		}
		ProgramDiffFilter propertyDiffFilter =
			new ProgramDiffFilter(ProgramDiffFilter.USER_DEFINED_DIFFS);
		AddressSetView propertyDiffSet = programDiff.getDifferences(propertyDiffFilter, monitor);
		AddressSetView diffAddrSet = p1MergeSet.intersect(propertyDiffSet);
		AddressSet diffAddrSet2 = DiffUtility.getCompatibleAddressSet(diffAddrSet, program2);
		merger.mergeProperties(diffAddrSet2, monitor);
	}

}
