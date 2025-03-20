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

import java.awt.Color;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import generic.stl.Pair;
import ghidra.app.merge.MergeConstants;
import ghidra.app.merge.tool.ListingMergePanel;
import ghidra.app.merge.util.ConflictUtility;
import ghidra.app.merge.util.MergeUtilities;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Class for merging function changes. This class can merge function changes
 * that were made to the checked out version. It can determine
 * where there are conflicts between the latest checked in version and my
 * checked out version. It can then manually merge the conflicting functions.
 * The FunctionMerger merges entire functions wherever the function bodies are
 * potentially in conflict between Latest and My. It then merges individual
 * parts that make up functions with matching bodies.
 * <br>Note: Function name differences are not resolved by this merger. Instead,
 * they are resolved by the SymbolMerger.
 * <br>Important: This class is intended to be used only for a single program
 * version merge. It should be constructed, followed by an autoMerge(), and lastly
 * each address with a conflict should have mergeConflicts() called on it.
 */
class FunctionMerger extends AbstractFunctionMerger implements ListingMerger {

	//////////////////////////////////////////
	// Begin AbstractListingMerger variables.
	//////////////////////////////////////////

	protected static final Color MERGE_HIGHLIGHT_COLOR = MergeConstants.HIGHLIGHT_COLOR;
	protected int conflictOption = ASK_USER;

	protected Address currentAddress;

	protected ProgramDiff diffOriginalLatest;
	protected ProgramDiff diffOriginalMy;
	protected ProgramDiff diffLatestMy;

	protected int totalChanges = 1; // Total number of changes for this auto-merger.
	protected int changeNum; // Current change number being auto-merged out of totalChanges.
	protected int minPhaseProgressPercentage; // Where to begin filling in the progress bar.
	protected int maxPhaseProgressPercentage; // Where to stop filling in the progress bar.

	protected int numConflictsResolved;

	//////////////////////////////////////////
	// End AbstractListingMerger variables.
	//////////////////////////////////////////

	final static String FUNCTIONS_PHASE = "Functions";
	private final static String CONFLICT_TYPE = "Function";
	private final static String INFO_TITLE = CONFLICT_TYPE + " Merge Information";
	private final static String ERROR_TITLE = CONFLICT_TYPE + " Merge Errors";

	private AddressSetView latestEntireDetailSet;
	private AddressSetView latestDetailSet; // latest function change set
	private AddressSetView myDetailSet; // my function change set

	AddressSet onlyMyChanged;
	AddressSet bothChanged;

	/* the address sets named with "EntireLatest" as a suffix indicate all function differences
	 * between the latest and original programs. These will be needed for checking function overlap.
	 */
	AddressSet addEntireLatest;
	AddressSet changeEntireLatest;
	AddressSet removeEntireLatest;
	AddressSet addLatest;
	AddressSet changeLatest;
	AddressSet removeLatest;
	AddressSet addMy;
	AddressSet changeMy;
	AddressSet removeMy;

	AddressSet autoRemoveSet;

	AddressSet addLatestExternals;
	AddressSet removeLatestExternals;
	AddressSet changeLatestExternals;

	// overlapConflicts: key = Address [entryPoint], value = AddressSet
	Hashtable<Address, AddressSet> overlapConflicts;
	// overlapConflictSet is addresses for conflicts indicating where functions have overlapping
	// bodies between LATEST & MY.
	AddressSet overlapConflictSet;
	// overlapAddressSet is addresses of the overlapping bodies where changed functions created
	// overlapping bodies between LATEST & MY.
	AddressSet overlapAddressSet;
	// bodySet is where both changed function body.
	AddressSet bodySet;
	// thunkConflictSet is where a thunk function conflict exists.
	AddressSet thunkConflictSet;
	// conflictSet is the addresses of functions in conflict.
	AddressSet conflictSet;
	// Hold onto thunks that need to be deferred and auto-merged after all non-thunks are merged.
	AddressSet thunkAutoMergeSet;

	protected static enum FunctionConflictType {
		FUNCTION_OVERLAP_CONFLICT,
		FUNCTION_BODY_CONFLICT,
		FUNCTION_REMOVE_CONFLICT,
		FUNCTION_RETURN_CONFLICT,
		FUNCTION_DETAILS_CONFLICT,
		VARIABLE_STORAGE_CONFLICT,
		PARAMETER_SIGNATURE_CONFLICT,
		PARAMETER_INFO_CONFLICT,
		REMOVED_LOCAL_VARIABLE_CONFLICT,
		LOCAL_VARIABLE_DETAIL_CONFLICT,
		THUNK_CONFLICT,
		TAG_CONFLICT
	}

	FunctionConflictType currentConflictType = null;

	/**
	 * Constructs a function merger.
	 * @param listingMergeMgr the listing merge manager that owns this merger.
	 */
	FunctionMerger(ListingMergeManager listingMergeMgr) {
		super(listingMergeMgr.mergeManager, listingMergeMgr.programs);
		this.listingMergeManager = listingMergeMgr;
		init();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.AbstractListingMerger#init()
	 */
	public void init() {
		initListingMerge();

		latestDetailSet = new AddressSet();
		myDetailSet = new AddressSet();
		onlyMyChanged = new AddressSet();
		bothChanged = new AddressSet();

		/* Remember the next three sets will have all function differences
		 * between the latest and original programs.
		 */
		addEntireLatest = new AddressSet();
		changeEntireLatest = new AddressSet();
		removeEntireLatest = new AddressSet();

		/* Remember the next three sets will only be function differences
		 * between latest and original where it can conflict with my program.
		 */
		addLatest = new AddressSet();
		changeLatest = new AddressSet();
		removeLatest = new AddressSet();

		addMy = new AddressSet();
		changeMy = new AddressSet();
		removeMy = new AddressSet();

		autoRemoveSet = new AddressSet();

		overlapConflicts = new Hashtable<>();
		overlapConflictSet = new AddressSet();
		overlapAddressSet = new AddressSet();
		bodySet = new AddressSet();
		thunkConflictSet = new AddressSet();
		conflictSet = new AddressSet();

		thunkAutoMergeSet = new AddressSet();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#getConflictType()
	 */
	@Override
	public String getConflictType() {
		return CONFLICT_TYPE;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#autoMerge(ghidra.util.task.TaskMonitor)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public void autoMerge(int progressMin, int progressMax, TaskMonitor monitor)
			throws ProgramConflictException, MemoryAccessException, CancelledException {

		latestResolvedDts = (Map<Long, DataType>) mergeManager
				.getResolveInformation(MergeConstants.RESOLVED_LATEST_DTS);
		myResolvedDts = (Map<Long, DataType>) mergeManager
				.getResolveInformation(MergeConstants.RESOLVED_MY_DTS);
		origResolvedDts = (Map<Long, DataType>) mergeManager
				.getResolveInformation(MergeConstants.RESOLVED_ORIGINAL_DTS);

		initializeAutoMerge("Auto-merging Functions and determining conflicts.", progressMin,
			progressMax, monitor);

		clearResolveInfo();

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS);

		updateProgress(0, "Finding Function changes in " + LATEST_TITLE + "...");
		ProgramDiff diffEntireOriginalLatest =
			new ProgramDiff(programs[ORIGINAL], programs[LATEST], listingMergeManager.latestSet);

		latestEntireDetailSet = diffEntireOriginalLatest.getDifferences(filter, monitor);
		latestDetailSet = listingMergeManager.diffOriginalLatest.getDifferences(filter, monitor);

		updateProgress(5, "Finding Function changes in " + MY_TITLE + "...");
		myDetailSet = listingMergeManager.diffOriginalMy.getDifferences(filter, monitor);
		MergeUtilities.adjustSets(latestDetailSet, myDetailSet, onlyMyChanged, bothChanged);

		// Determine removes, adds, and changes.
		updateProgress(10, "Categorizing Function changes in " + LATEST_TITLE + "...");
		getLatestEntireChangeTypes(monitor);
		getLatestChangeTypes(monitor);

		updateProgress(15, "Categorizing Function changes in " + MY_TITLE + "...");
		getMyChangeTypes(monitor);

		// Determine changes resulting in potential function body overlap conflicts.
		updateProgress(20, "Finding function body overlap conflicts.");
		AddressSet changeSet = latestEntireDetailSet.union(myDetailSet);
		determineOverlapConflicts(changeSet, monitor);

		updateProgress(25, "Finding function removal conflicts.");
		AddressSet notOverlapConflicts =
			myDetailSet.subtract(overlapAddressSet.intersect(changeSet));
		determineRemoveConflicts(notOverlapConflicts, monitor);

		updateProgress(30, "Finding function body conflicts.");
		AddressSet notRemoveConflicts = notOverlapConflicts.subtract(removeSet);
		AddressSet notRemoveConflictsAndNotAutoRemove = notRemoveConflicts.subtract(autoRemoveSet);
		determineBodyConflicts(notRemoveConflictsAndNotAutoRemove, monitor);

		// If only MY changed and didn't cause overlap with LATEST changes, then autoMerge MY.
		updateProgressMessage("Auto-merging Functions and determining conflicts.");
		AddressSet functionDetailChanges = notRemoveConflictsAndNotAutoRemove.subtract(bodySet);
		AddressSet autoSet = onlyMyChanged.intersect(functionDetailChanges);
		AddressSet onlyMyChangedThunks = getThunkEntrySet(programs[MY], autoSet);
		thunkAutoMergeSet.add(onlyMyChangedThunks);
		AddressSet nonThunkSet = autoSet.subtract(thunkAutoMergeSet);
		mergeEntireFunctions(nonThunkSet, KEEP_MY, monitor);

		AddressSet possibleDetailConflicts = functionDetailChanges.subtract(autoSet);
		long totalAddresses = possibleDetailConflicts.getNumAddresses();
		int addressCount = 0;
		// Auto-merge parts of functions where possible and determine conflicts.
		AddressIterator iter = possibleDetailConflicts.getAddresses(true);
		while (iter.hasNext()) {
			monitor.checkCancelled();
			updateProgress((int) (DETAILS_CONFLICT_START +
				((addressCount * DETAILS_CONFLICT_SIZE) / totalAddresses)));
			Address entry = iter.next();
			Function[] functions = new Function[4];
			functions[RESULT] = functionManagers[RESULT].getFunctionAt(entry);
			functions[ORIGINAL] = functionManagers[ORIGINAL].getFunctionAt(entry);
			functions[LATEST] = functionManagers[LATEST].getFunctionAt(entry);
			functions[MY] = functionManagers[MY].getFunctionAt(entry);
			boolean latestIsThunk =
				(functions[LATEST] != null) ? functions[LATEST].isThunk() : false;
			boolean myIsThunk = (functions[MY] != null) ? functions[MY].isThunk() : false;

			if (latestIsThunk || myIsThunk) {
				determineThunkConflicts(functions, monitor);
				continue;
			}

			determineFunctionConflicts(functions, false, monitor);
		}

		updateProgress(100, "Done auto-merging Functions and determining conflicts.");
		determineConflictSet();

		showResolveErrors(ERROR_TITLE);
		showResolveInfo(INFO_TITLE);
	}

	private AddressSet getThunkEntrySet(Program program, AddressSet addressSetToCheck) {
		AddressSet thunkSet = new AddressSet();
		FunctionManager functionManager = program.getFunctionManager();
		FunctionIterator functions = functionManager.getFunctions(addressSetToCheck, true);
		for (Function function : functions) {
			if (function.isThunk()) {
				thunkSet.add(function.getEntryPoint());
			}
		}
		return thunkSet;
	}

	private void determineConflictSet() {
		conflictSet.clear();
		conflictSet.add(removeSet);
		conflictSet.add(overlapConflictSet);
		conflictSet.add(bodySet);
		conflictSet.add(funcSet);
		conflictSet.add(thunkConflictSet);
	}

	/* Determines three sets for function differences
	 * between latest and original where it can conflict with my program.
	 */
	private void getLatestChangeTypes(TaskMonitor monitor) throws CancelledException {
		AddressIterator latestIter = latestDetailSet.getAddresses(true);
		long max = latestDetailSet.getNumAddresses();
		monitor.initialize(max);
		int count = 0;
		while (latestIter.hasNext()) {
			monitor.setProgress(count++);
			monitor.checkCancelled();
			Address entry = latestIter.next();
			Function originalFunc = functionManagers[ORIGINAL].getFunctionAt(entry);
			Function latestFunc = functionManagers[LATEST].getFunctionAt(entry);
			if (originalFunc == null) {
				addLatest.addRange(entry, entry);
			}
			else if (latestFunc == null) {
				removeLatest.addRange(entry, entry);
			}
			else {
				changeLatest.addRange(entry, entry);
			}
		}
		monitor.setProgress(max);
	}

	/* Determines three sets for all function differences
	 * between the latest and original programs.
	 */
	private void getLatestEntireChangeTypes(TaskMonitor monitor) throws CancelledException {
		AddressIterator latestIter = latestEntireDetailSet.getAddresses(true);
		long max = latestEntireDetailSet.getNumAddresses();
		monitor.initialize(max);
		int count = 0;
		while (latestIter.hasNext()) {
			monitor.setProgress(count++);
			monitor.checkCancelled();
			Address entry = latestIter.next();
			Function originalFunc = functionManagers[ORIGINAL].getFunctionAt(entry);
			Function latestFunc = functionManagers[LATEST].getFunctionAt(entry);
			if (originalFunc == null) {
				addEntireLatest.addRange(entry, entry);
			}
			else if (latestFunc == null) {
				removeEntireLatest.addRange(entry, entry);
			}
			else {
				changeEntireLatest.addRange(entry, entry);
			}
		}
		monitor.setProgress(max);
	}

	private void getMyChangeTypes(TaskMonitor monitor) throws CancelledException {
		AddressIterator myIter = myDetailSet.getAddresses(true);
		long max = myDetailSet.getNumAddresses();
		int count = 0;
		while (myIter.hasNext()) {
			monitor.setProgress(count++);
			monitor.checkCancelled();
			Address entry = myIter.next();
			Function originalFunc = functionManagers[ORIGINAL].getFunctionAt(entry);
			Function myFunc = functionManagers[MY].getFunctionAt(entry);
			if (originalFunc == null) {
				addMy.addRange(entry, entry);
			}
			else if (myFunc == null) {
				removeMy.addRange(entry, entry);
			}
			else {
				changeMy.addRange(entry, entry);
			}
		}
		monitor.setProgress(max);
	}

	/**
	 *
	 * @param changeSet address set indicating where either Latest or My changed a function.
	 * @param monitor
	 * @throws CancelledException
	 */
	private void determineOverlapConflicts(AddressSet changeSet, TaskMonitor monitor)
			throws CancelledException {
		monitor.checkCancelled();
		AddressSet alreadyChecked = new AddressSet();
		AddressIterator iter = changeSet.getAddresses(true);
		// Look at every address where the Latest or My made a function change.
		while (iter.hasNext()) {
			monitor.checkCancelled();
			Address changeEntry = iter.next(); // Entry Point of function being checked.
			if (overlapAddressSet.contains(changeEntry)) {
				continue;
			}
			if (alreadyChecked.contains(changeEntry)) {
				continue;
			}
			AddressSet entryConflictSet = new AddressSet();
			AddressSet checkEntries = new AddressSet(changeEntry, changeEntry);

			while (!checkEntries.isEmpty()) {
				AddressSet newEntries = new AddressSet();
				AddressIterator entryIter = checkEntries.getAddresses(true);
				while (entryIter.hasNext()) {
					Address entry = entryIter.next();
					Function latestFunc = functionManagers[LATEST].getFunctionAt(entry);
					Function myFunc = functionManagers[MY].getFunctionAt(entry);
					AddressSet latestBody = new AddressSet();
					if (latestFunc != null) {
						latestBody.add(latestFunc.getBody());
					}
					AddressSet myBody = new AddressSet();
					if (myFunc != null) {
						myBody.add(myFunc.getBody());
					}
					AddressSet latestOnly = latestBody.subtract(myBody);
					AddressSet myOnly = myBody.subtract(latestBody);
					// Did Latest program add or change this function?
					if (addEntireLatest.contains(entry) || changeEntireLatest.contains(entry)) {
						AddressSet conflictingMyEntries = new AddressSet();
						// Do body addresses only in Latest function body overlap with My add or change addresses.
						conflictingMyEntries.add(latestOnly.intersect(addMy));
						conflictingMyEntries.add(latestOnly.intersect(changeMy));
						if (!conflictingMyEntries.isEmpty()) {
							entryConflictSet.add(latestBody); // Add Latest function's body.
							entryConflictSet
									.add(getBodies(functionManagers[MY], conflictingMyEntries)); // Add My conflicting function bodies.
						}
						newEntries.add(conflictingMyEntries);
					}
					// Did My program add or change this function?
					if (addMy.contains(entry) || changeMy.contains(entry)) {
						AddressSet conflictingLatestEntries = new AddressSet();
						// Do body addresses only in My function body overlap with Latest add or change addresses.
						conflictingLatestEntries.add(myOnly.intersect(addEntireLatest));
						conflictingLatestEntries.add(myOnly.intersect(changeEntireLatest));
						if (!conflictingLatestEntries.isEmpty()) {
							entryConflictSet.add(myBody); // Add My function's body.
							entryConflictSet.add(
								getBodies(functionManagers[LATEST], conflictingLatestEntries)); // Add Latest conflicting function bodies.
						}
						newEntries.add(conflictingLatestEntries);
					}
					alreadyChecked.addRange(entry, entry);
				}
				// Set up to look at any discovered conflicting function addresses not already examined.
				checkEntries = newEntries.subtract(alreadyChecked);
			}
			// entryConflictSet now has the addresses where the function bodies have an overlap conflict.
			if (!entryConflictSet.isEmpty()) {
				overlapConflicts.put(changeEntry, entryConflictSet);
				overlapConflictSet.addRange(changeEntry, changeEntry);
				overlapAddressSet.add(entryConflictSet);
			}
		}
	}

	private AddressSet getBodies(FunctionManager funcMgr, AddressSet conflictingEntries) {
		AddressSet addrSet = new AddressSet();
		AddressIterator iter = conflictingEntries.getAddresses(true);
		while (iter.hasNext()) {
			Address addr = iter.next();
			Function f = funcMgr.getFunctionAt(addr);
			if (f != null) {
				addrSet.add(f.getBody());
			}
		}
		return addrSet;
	}

	private void determineBodyConflicts(AddressSetView addrs, TaskMonitor monitor)
			throws CancelledException {
		monitor.checkCancelled();
		long totalAddresses = addrs.getNumAddresses();
		monitor.initialize(totalAddresses);
		long granularity = (totalAddresses / 100) + 1;
		int addressCount = 0;
		AddressIterator iter = addrs.getAddresses(true);
		// Look at every address where the Latest or My made a function change.
		while (iter.hasNext()) {
			Address entry = iter.next();
			if (addressCount % granularity == 0) {
				monitor.setProgress(addressCount);
				updateProgress((int) (BODY_CONFLICT_START +
					((addressCount * BODY_CONFLICT_SIZE) / totalAddresses)));
			}
			monitor.setMessage(
				"Checking & Auto-Merging Body Changes for Function " + (++addressCount) + " of " +
					totalAddresses + "." + " Address = " + entry.toString());
			Function originalFunc = functionManagers[ORIGINAL].getFunctionAt(entry);
			Function latestFunc = functionManagers[LATEST].getFunctionAt(entry);
			Function myFunc = functionManagers[MY].getFunctionAt(entry);
			determineBodyConflicts(entry, originalFunc, latestFunc, myFunc, monitor);
		}
	}

	private void determineBodyConflicts(Address entry, Function original, Function latest,
			Function my, TaskMonitor monitor) throws CancelledException {
		monitor.checkCancelled();
		AddressSetView originalAddrs = (original != null) ? original.getBody() : null;
		AddressSetView latestAddrs = (latest != null) ? latest.getBody() : null;
		AddressSetView myAddrs = (my != null) ? my.getBody() : null;
		if (SystemUtilities.isEqual(latestAddrs, myAddrs)) {
			return;
		}
		boolean myBodyChanged = !SystemUtilities.isEqual(myAddrs, originalAddrs);
		boolean latestBodyChanged = !SystemUtilities.isEqual(latestAddrs, originalAddrs);
		if (myBodyChanged) {
			if (isEquivalent(latest, original)) {
				if (my != null && my.isThunk()) {
					// Save the thunk for auto-merging later.
					thunkAutoMergeSet.add(entry);
				}
				else {
					// AutoMerge My function body change
					merge(entry, KEEP_MY, monitor);
				}
			}
			else {
				// Have a my function body vs latest function conflict.
				bodySet.addRange(entry, entry);
			}
		}
		else if ((latestBodyChanged) && (!isEquivalent(my, original))) {
			// Have a latest function body vs my function conflict.
			bodySet.addRange(entry, entry);
		}
	}

	private void determineRemoveConflicts(AddressSet possibleConflicts, TaskMonitor monitor)
			throws CancelledException {
		monitor.checkCancelled();
		AddressSet myRemoveConflicts =
			removeMy.intersect(changeLatest).intersect(possibleConflicts);
		AddressSet latestRemoveConflicts =
			removeLatest.intersect(changeMy).intersect(possibleConflicts);
		autoRemoveSet = removeMy.subtract(myRemoveConflicts);
		// AutoMerge to remove My function
		mergeFunctions(listingMergeManager.mergeMy, autoRemoveSet, monitor);
		removeSet.add(myRemoveConflicts);
		removeSet.add(latestRemoveConflicts);
	}

	private void determineThunkConflicts(Function[] functions, TaskMonitor monitor)
			throws CancelledException {
		monitor.checkCancelled();

		boolean latestIsThunk = functions[LATEST].isThunk();
		boolean myIsThunk = functions[MY].isThunk();
		if (latestIsThunk != myIsThunk) {
			// One is thunk and the other isn't.
			// Save the thunk conflict
			saveThunkConflict(functions[RESULT]);
			return;
		}
		if (latestIsThunk && myIsThunk) {
			determineThunkNameConflicts(functions, monitor);
			determineThunkedFunctionConflicts(functions);
		}
		// If neither is a thunk then other methods will check for those conflicts.
		return;
	}

	private void determineThunkNameConflicts(Function[] functions, TaskMonitor monitor) {
		boolean sameFunctionNames = ProgramDiff.sameFunctionNames(functions[LATEST], functions[MY]);
		if (sameFunctionNames) {
			return; // Already have same names.
		}
		boolean changedLatest =
			!ProgramDiff.sameFunctionNames(functions[ORIGINAL], functions[LATEST]);
		boolean changedMy = !ProgramDiff.sameFunctionNames(functions[ORIGINAL], functions[MY]);
		int latestMyChanges = FUNC_NAME;
		int originalLatestChanges = changedLatest ? FUNC_NAME : 0;
		int originalMyChanges = changedMy ? FUNC_NAME : 0;
		int functionConflictFlags = determineFunctionConflict(functions, FUNC_NAME, latestMyChanges,
			originalLatestChanges, originalMyChanges, monitor);
		if (functionConflictFlags != 0) {
			saveFunctionDetailConflict(functions, functionConflictFlags);
		}
	}

	private void determineThunkedFunctionConflicts(Function[] functions) {
		// Check to see if they point to the equivalent spot.
		Function latestThunkedFunction = functions[LATEST].getThunkedFunction(false);
		Address latestThunkedEntry = latestThunkedFunction.getEntryPoint();
		Function myThunkedFunction = functions[MY].getThunkedFunction(false);
		Address myThunkedEntry = myThunkedFunction.getEntryPoint();
		Address myThunkedEntryAsLatest = SimpleDiffUtility.getCompatibleAddress(
			functions[MY].getProgram(), myThunkedEntry, functions[RESULT].getProgram());
		if (!latestThunkedEntry.equals(myThunkedEntryAsLatest)) {
			// Save the thunk conflict
			saveThunkConflict(functions[RESULT]);
		}
	}

	private void saveThunkConflict(Function result) {
		thunkConflictSet.add(result.getEntryPoint());
	}

	/**
	 *
	 * @param entry
	 * @param type (FUNC_RETURN_TYPE, FUNC_RETURN_ADDRESS_OFFSET,
	 * FUNC_PARAMETER_OFFSET, FUNC_LOCAL_SIZE, FUNC_STACK_PURGE_SIZE, FUNC_NAME, FUNC_INLINE,
	 * FUNC_NO_RETURN, FUNC_CALLING_CONVENTION)
	 */
	@Override
	protected void saveFunctionDetailConflict(Function[] functions, int type) {
		Address entry = (functions[LATEST] != null) ? functions[LATEST].getEntryPoint()
				: ((functions[MY] != null) ? functions[MY].getEntryPoint()
						: functions[ORIGINAL].getEntryPoint());
		// If something else has set bits, we want to retain those, so get them.
		int bits = 0;
		try {
			bits = funcConflicts.get(entry);
		}
		catch (NoValueException e) {
			// It's okay if we don't have bits set yet.
		}
		bits |= type;
		funcConflicts.put(entry, bits);
		funcSet.addRange(entry, entry);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#hasConflict(ghidra.program.model.address.Address)
	 */
	@Override
	public boolean hasConflict(Address addr) {
		return conflictSet.contains(addr);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#getConflictCount(ghidra.program.model.address.Address)
	 */
	@Override
	public int getConflictCount(Address addr) {
		int count = 0;
		if (overlapConflictSet.contains(addr) || bodySet.contains(addr) ||
			removeSet.contains(addr)) {
			return 1;
		}
		if (funcSet.contains(addr)) {
			try {
				int bits = funcConflicts.get(addr);
				count += countSetBits(bits);
			}
			catch (NoValueException e) {
				return 0;
			}
		}
		return count;
	}

	private void merge(Address entryPt, int chosenConflictOption, TaskMonitor monitor)
			throws CancelledException {
		updateProgressMessage("Merging function @ " + entryPt.toString(true));
		ProgramMerge pgmMerge = getProgramListingMerge(chosenConflictOption);
		if (pgmMerge == null) {
			return;
		}
		Program origPgm = pgmMerge.getOriginProgram();
		if (origPgm == null) {
			return;
		}
		Function f = pgmMerge.mergeFunction(entryPt, monitor);
		if (f != null) {
			try {
				Function origF = origPgm.getFunctionManager().getFunctionAt(entryPt);
				if (origF != null) {
					Namespace ns =
						listingMergeManager.resolveNamespace(origPgm, origF.getParentNamespace());
					f.setParentNamespace(ns);
				}
			}
			catch (DuplicateNameException e) {
				Msg.showError(this, mergeManager.getMergeTool().getToolFrame(),
					"Error Setting Function Namespace", e.getMessage());
			}
			catch (InvalidInputException e) {
				Msg.showError(this, mergeManager.getMergeTool().getToolFrame(),
					"Error Setting Function Namespace", e.getMessage());
			}
			catch (CircularDependencyException e) {
				Msg.showError(this, mergeManager.getMergeTool().getToolFrame(),
					"Error Setting Function Namespace", e.getMessage());
			}
		}
	}

	private void mergeOverlap(Address address, int chosenConflictOption, TaskMonitor monitor)
			throws CancelledException {
		AddressSet resolveSet = overlapConflicts.get(currentAddress);
		if (resolveSet != null) {
			mergeEntireFunctions(resolveSet, chosenConflictOption, monitor);
		}
	}

	private void mergeEntireFunctions(final AddressSet addressSet, final int chosenConflictOption,
			final TaskMonitor monitor) throws CancelledException {
		ProgramMerge pgmMerge = getProgramListingMerge(chosenConflictOption);
		if (pgmMerge != null) {
			mergeFunctions(pgmMerge, addressSet, monitor);
		}
	}

	private void mergeFunctions(ProgramMerge pgmMerge, AddressSet addressSet, TaskMonitor monitor)
			throws CancelledException {
		updateProgress(FUNCTION_CONFLICT_START);
		pgmMerge.mergeFunctions(addressSet, monitor);
		FunctionMerge.replaceFunctionsNames(pgmMerge, addressSet, monitor);
		setFunctionsNamespaces(pgmMerge, addressSet, monitor);
		updateProgress(FUNCTION_CONFLICT_START + FUNCTION_CONFLICT_SIZE);
		if (!monitor.isCancelled()) {
			handleProgramMergeMessages(pgmMerge);
		}
	}

	private void setFunctionsNamespaces(ProgramMerge pgmMerge, AddressSet addressSet,
			TaskMonitor monitor) {
		monitor.setMessage("Setting function namespaces...");
		Program resultP = pgmMerge.getResultProgram();
		Program origP = pgmMerge.getOriginProgram();
		FunctionManager resultFM = resultP.getFunctionManager();
		FunctionManager origFM = origP.getFunctionManager();
		FunctionIterator iter = resultFM.getFunctions(addressSet, true);
		while (iter.hasNext()) {
			Function resultF = iter.next();
			Address entryPoint = resultF.getEntryPoint();
			Function origF = origFM.getFunctionAt(entryPoint);
			if (origF != null) {
				monitor.setMessage("Setting namespace for function @ " + entryPoint.toString(true));
				try {
					Namespace ns =
						listingMergeManager.resolveNamespace(origP, origF.getParentNamespace());
					resultF.setParentNamespace(ns);
				}
				catch (DuplicateNameException e) {
					Msg.showError(this, mergeManager.getMergeTool().getToolFrame(),
						"Error Setting Function Namespace", e.getMessage());
				}
				catch (InvalidInputException e) {
					Msg.showError(this, mergeManager.getMergeTool().getToolFrame(),
						"Error Setting Function Namespace", e.getMessage());
				}
				catch (CircularDependencyException e) {
					Msg.showError(this, mergeManager.getMergeTool().getToolFrame(),
						"Error Setting Function Namespace", e.getMessage());
				}
			}
		}
	}

	private void handleProgramMergeMessages(ProgramMerge pm) {

		errorBuf.append(pm.getErrorMessage());
		pm.clearErrorMessage();

		infoBuf.append(pm.getInfoMessage());
		pm.clearInfoMessage();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#mergeConflicts(ghidra.app.merge.tool.ListingMergePanel,
	 * ghidra.program.model.address.Address, int, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void mergeConflicts(ListingMergePanel listingPanel, Address addr,
			int currentConflictOption, TaskMonitor monitor)
			throws CancelledException, MemoryAccessException {
		if (!hasConflict(addr)) {
			return;
		}

		clearResolveInfo();
		monitor.setMessage("Resolving Function conflicts.");
		this.currentAddress = addr;
		this.currentMonitor = monitor;

		Function[] functions = getFunctions(addr);

		// Handle overlap conflict.
		if (overlapConflictSet.contains(addr)) {
			handleOverlappingFunctionsConflict(listingPanel, addr, currentConflictOption, monitor);
		}

		// Handle body difference conflict.
		else if (bodySet.contains(addr)) {
			handleFunctionBodyConflict(listingPanel, addr, currentConflictOption, monitor);
		}

		// Handle remove vs change function conflict.
		else if (removeSet.contains(addr)) {
			handleFunctionRemovalConflict(listingPanel, addr, currentConflictOption, monitor);
		}

		// Handle the various function detail conflicts
		else if (funcConflicts.contains(addr)) {
			handleFunctionDetailConflicts(listingPanel, addr, functions, currentConflictOption,
				monitor);
		}
	}

	private void handleOverlappingFunctionsConflict(ListingMergePanel listingPanel, Address addr,
			int currentConflictOption, TaskMonitor monitor) throws CancelledException {
		currentConflictType = FunctionConflictType.FUNCTION_OVERLAP_CONFLICT;
		boolean askUser =
			(overlapChoice == ASK_USER) && currentConflictOption == ListingMergeConstants.ASK_USER;
		if (askUser && mergeManager != null) {
			VariousChoicesPanel choicesPanel = createOverlapConflictPanel(addr, monitor);

			boolean useForAll = (overlapChoice != ASK_USER);
			choicesPanel.setUseForAll(useForAll);
			choicesPanel.setConflictType("Function Overlap");

			setupAddressSetConflictPanel(listingPanel, choicesPanel, addr,
				overlapConflicts.get(addr), monitor);
			monitor.checkCancelled();
		}
		else {
			// If we have a function overlap choice then a "Use For All" has already occurred.
			int optionToUse = (overlapChoice == ASK_USER) ? currentConflictOption : overlapChoice;
			mergeOverlap(addr, optionToUse, monitor);
		}
	}

	private void handleFunctionBodyConflict(ListingMergePanel listingPanel, Address addr,
			int currentConflictOption, TaskMonitor monitor) throws CancelledException {
		currentConflictType = FunctionConflictType.FUNCTION_BODY_CONFLICT;
		boolean askUser =
			(bodyChoice == ASK_USER) && currentConflictOption == ListingMergeConstants.ASK_USER;
		if (askUser && mergeManager != null) {
			VerticalChoicesPanel choicesPanel = createBodyConflictPanel(addr, monitor);

			boolean useForAll = (bodyChoice != ASK_USER);
			choicesPanel.setUseForAll(useForAll);
			choicesPanel.setConflictType("Function Body");

			setupAddressSetConflictPanel(listingPanel, choicesPanel, addr, getBodySet(addr),
				monitor);
			monitor.checkCancelled();
		}
		else {
			// If we have a function body choice then a "Use For All" has already occurred.
			int optionToUse = (bodyChoice == ASK_USER) ? currentConflictOption : bodyChoice;
			merge(addr, optionToUse, monitor);
		}
	}

	private void handleFunctionRemovalConflict(ListingMergePanel listingPanel, Address addr,
			int currentConflictOption, TaskMonitor monitor) throws CancelledException {
		currentConflictType = FunctionConflictType.FUNCTION_REMOVE_CONFLICT;
		boolean askUser =
			(removeChoice == ASK_USER) && currentConflictOption == ListingMergeConstants.ASK_USER;
		if (askUser && mergeManager != null) {
			VerticalChoicesPanel choicesPanel =
				createRemoveConflictPanel(getFunctions(addr), monitor);

			boolean useForAll = (removeChoice != ASK_USER);
			choicesPanel.setUseForAll(useForAll);
			choicesPanel.setConflictType("Function Removal");

			setupConflictPanel(listingPanel, choicesPanel, addr, monitor);
			monitor.checkCancelled();
		}
		else {
			// If we have a function remove choice then a "Use For All" has already occurred.
			int optionToUse = (removeChoice == ASK_USER) ? currentConflictOption : removeChoice;
			merge(addr, optionToUse, monitor);
		}
	}

	private void handleFunctionDetailConflicts(ListingMergePanel listingPanel, Address addr,
			Function[] functions, int currentConflictOption, TaskMonitor monitor)
			throws CancelledException {
		currentConflictType = FunctionConflictType.FUNCTION_DETAILS_CONFLICT;
		boolean askUser = currentConflictOption == ListingMergeConstants.ASK_USER;
		int conflicts;
		try {
			conflicts = funcConflicts.get(addr);
		}
		catch (NoValueException e) {
			throw new RuntimeException("Unexpected Exception", e);
		}

		// Merge function signature source conflicts based on priority.
		if ((conflicts & FUNC_SIGNATURE_SOURCE) != 0) {
			mergeHigherPrioritySignatureSource(functions, monitor);
		}

		// Handle merge of non-variable function detail.
		if ((conflicts & FUNC_DETAIL_MASK) != 0) {
			// If we have a function details choice then a "Use For All" has already occurred.
			if (detailsChoice != ASK_USER) {
				mergeFunctionDetails(functions, detailsChoice, monitor);
			}
			else if (askUser && mergeManager != null) {
				VariousChoicesPanel choicesPanel =
					createFunctionConflictPanel(getFunctions(addr), monitor);

				boolean useForAll = (detailsChoice != ASK_USER);
				choicesPanel.setUseForAll(useForAll);
				choicesPanel.setConflictType("Function Detail");

				setupConflictPanel(listingPanel, choicesPanel, addr, monitor);
				monitor.checkCancelled();
			}
			else {
				mergeFunctionDetails(functions, currentConflictOption, monitor);
			}
		}

		// If Calling Convention was addressed
		// we must determine deferred parameter/variable storage/detail checks.
		// Must be done after signature resolution since this could introduce
		// storage conflicts.
		FunctionVariableStorageConflicts variableStorageConflicts = null;
		List<ParamInfoConflict> paramInfoConflicts = null;
		List<LocalVariableConflict> localVarConflicts = null;
		if ((conflicts & FUNC_CALLING_CONVENTION) != 0) {

			variableStorageConflicts = determineStorageConflict(functions, monitor);
			boolean skipParamChecks =
				variableStorageConflicts != null && variableStorageConflicts.hasParameterConflict();

			if (!skipParamChecks && determineSignatureConflicts(functions, monitor)) {
				paramInfoConflicts = determineParameterInfoConflicts(functions, true, monitor);
			}

			determineReturnConflict(functions, true, monitor);

			localVarConflicts = determineLocalVariableInfoConflicts(functions, true,
				variableStorageConflicts, monitor);

			// update function conflicts
			try {
				conflicts = funcConflicts.get(addr);
			}
			catch (NoValueException e) {
				throw new RuntimeException("Unexpected Exception", e);
			}
		}

		if ((conflicts & FUNC_RETURN) != 0) {
			currentConflictType = FunctionConflictType.FUNCTION_RETURN_CONFLICT;
			// If we have a function return choice then a "Use For All" has already occurred.
			if (functionReturnChoice != ASK_USER) {
				mergeFunctionReturn(functions, functionReturnChoice, monitor);
			}
			else if (askUser && mergeManager != null) {
				VerticalChoicesPanel choicesPanel =
					createFunctionReturnConflictPanel(getFunctions(addr), monitor);

				boolean useForAll = (functionReturnChoice != ASK_USER);
				choicesPanel.setUseForAll(useForAll);
				choicesPanel.setConflictType("Function Return");

				setupConflictPanel(listingPanel, choicesPanel, addr, monitor);
				monitor.checkCancelled();
			}
			else {
				mergeFunctionReturn(functions, currentConflictOption, monitor);
			}
		}

		// Handle merge of overlapping function variables.
		if ((conflicts & FUNC_VAR_STORAGE) != 0) {
			currentConflictType = FunctionConflictType.VARIABLE_STORAGE_CONFLICT;
			if (variableStorageConflicts == null) {
				variableStorageConflicts = determineStorageConflict(functions, monitor);
			}
			// If we have a function variable storage choice then a "Use For All" has already occurred.
			if (variableStorageChoice != ASK_USER) {
				for (Pair<List<Variable>, List<Variable>> pair : variableStorageConflicts
						.getOverlappingVariables()) {
					monitor.checkCancelled();
					mergeVariableStorage(addr, pair, variableStorageChoice, monitor);
				}
			}
			else if (askUser && mergeManager != null) {
				for (Pair<List<Variable>, List<Variable>> pair : variableStorageConflicts
						.getOverlappingVariables()) {
					monitor.checkCancelled();
					boolean useForAll = (variableStorageChoice != ASK_USER);
					if (useForAll) {
						mergeVariableStorage(addr, pair, variableStorageChoice, monitor);
						continue;
					}
					ScrollingListChoicesPanel choicesPanel =
						createStorageConflictPanel(addr, pair, monitor);

					choicesPanel.setUseForAll(useForAll);
					choicesPanel.setConflictType("Function Variable Storage");

					setupConflictPanel(listingPanel, choicesPanel, addr, monitor);
				}
			}
			else {
				for (Pair<List<Variable>, List<Variable>> pair : variableStorageConflicts
						.getOverlappingVariables()) {
					monitor.checkCancelled();
					mergeVariableStorage(addr, pair, currentConflictOption, monitor);
				}
			}
		}

		// Handle merge of function parameter signature.
		if ((conflicts & FUNC_SIGNATURE) != 0) {
			currentConflictType = FunctionConflictType.PARAMETER_SIGNATURE_CONFLICT;
			// If we have a function parameter signature choice then a "Use For All" has already occurred.
			if (parameterSignatureChoice != ASK_USER) {
				mergeParameters(addr, parameterSignatureChoice, monitor);
			}
			else if (askUser && mergeManager != null) {
				VerticalChoicesPanel choicesPanel =
					createParameterSigConflictPanel(getFunctions(addr), monitor);

				boolean useForAll = (parameterSignatureChoice != ASK_USER);
				choicesPanel.setUseForAll(useForAll);
				choicesPanel.setConflictType("Function Parameter Signature");

				setupConflictPanel(listingPanel, choicesPanel, addr, monitor);
				monitor.checkCancelled();
			}
			else {
				mergeParameters(addr, currentConflictOption, monitor);
			}
		}

		// Handle merge of function parameter Info details.
		if ((conflicts & FUNC_PARAM_DETAILS) != 0) {
			currentConflictType = FunctionConflictType.PARAMETER_INFO_CONFLICT;
			if (paramInfoConflicts == null) {
				paramInfoConflicts = determineParameterInfoConflicts(functions, false, monitor);
			}
			// If we have a function parameter information choice then a "Use For All" has already occurred.
			if (parameterInfoChoice != ASK_USER) {
				mergeParamInfo(addr, paramInfoConflicts, parameterInfoChoice, monitor);
			}
			else if (askUser && mergeManager != null) {
				for (ParamInfoConflict pc : paramInfoConflicts) {
					monitor.checkCancelled();
					boolean useForAll = (parameterInfoChoice != ASK_USER);
					if (useForAll) {
						mergeParamInfo(addr, pc, parameterInfoChoice, monitor);
						continue;
					}
					VariousChoicesPanel choicesPanel = createParamInfoConflictPanel(pc, monitor);

					choicesPanel.setUseForAll(useForAll);
					choicesPanel.setConflictType("Function Parameter Info");

					setupConflictPanel(listingPanel, choicesPanel, pc.entry, monitor);
					monitor.checkCancelled();
				}

			}
			else {
				mergeParamInfo(addr, paramInfoConflicts, currentConflictOption, monitor);
			}
		}

		// Handle merge of function local variable details.
		if ((conflicts & FUNC_LOCAL_DETAILS) != 0) {
			currentConflictType = FunctionConflictType.LOCAL_VARIABLE_DETAIL_CONFLICT;
			if (localVarConflicts == null) {
				localVarConflicts = determineLocalVariableInfoConflicts(functions, false,
					variableStorageConflicts, monitor);
			}
			if (askUser && mergeManager != null) {
				for (LocalVariableConflict localVariableConflict : localVarConflicts) {
					monitor.checkCancelled();
					ConflictPanel choicesPanel = null;
					if ((localVariableConflict.varConflicts & VAR_REMOVED) != 0) {
						currentConflictType = FunctionConflictType.REMOVED_LOCAL_VARIABLE_CONFLICT;
						// If we have a remove local variable choice then a "Use For All" has already occurred.
						if (removedLocalVariableChoice != ASK_USER) {
							mergeLocalVariable(VAR_REMOVED, addr, localVariableConflict.vars,
								removedLocalVariableChoice, monitor);
							continue;
						}
						choicesPanel =
							createRemovedVarConflictPanel(localVariableConflict, monitor);

						boolean useForAll = (removedLocalVariableChoice != ASK_USER);
						choicesPanel.setUseForAll(useForAll);
						choicesPanel.setConflictType("Local Variable Removal");
					}
					else {
						currentConflictType = FunctionConflictType.LOCAL_VARIABLE_DETAIL_CONFLICT;
						// If we have a local variable detail choice then a "Use For All" has already occurred.
						if (localVariableDetailChoice != ASK_USER) {
							mergeLocal(addr, localVariableConflict, localVariableDetailChoice,
								monitor);
							continue;
						}
						choicesPanel =
							createLocalVariableConflictPanel(localVariableConflict, monitor);

						boolean useForAll = (localVariableDetailChoice != ASK_USER);
						choicesPanel.setUseForAll(useForAll);
						choicesPanel.setConflictType("Local Variable Detail");
					}
					setupConflictPanel(listingPanel, choicesPanel, localVariableConflict.entry,
						monitor);
				}
			}
			else {
				mergeLocals(addr, localVarConflicts, currentConflictOption, monitor);
			}
		}
	}

	public void mergeThunks(ListingMergePanel listingPanel, int currentConflictOption,
			TaskMonitor monitor) throws CancelledException {

		currentConflictType = FunctionConflictType.THUNK_CONFLICT;
		boolean askUser = currentConflictOption == ListingMergeConstants.ASK_USER;
		this.currentMonitor = monitor;

		mergeEntireFunctions(thunkAutoMergeSet, KEEP_MY, monitor);

		AddressIterator conflictIter = thunkConflictSet.getAddresses(true);
		while (conflictIter.hasNext()) {
			Address thunkConflictAddress = conflictIter.next();
			this.currentAddress = thunkConflictAddress;
			Function latestFunction = functionManagers[LATEST].getFunctionAt(thunkConflictAddress);
			Function myFunction = functionManagers[MY].getFunctionAt(thunkConflictAddress);
			boolean latestIsInvalidThunk = (latestFunction != null) && latestFunction.isThunk() &&
				(latestFunction.getThunkedFunction(false) == null);
			boolean myIsInvalidThunk = (myFunction != null) && myFunction.isThunk() &&
				(myFunction.getThunkedFunction(false) == null);
			if (latestIsInvalidThunk && myIsInvalidThunk) {
				continue;
			}
			else if (myIsInvalidThunk) {
				// The my thunked function is no longer there so can't pick the thunk. Instead keep LATEST function.
				// We already have the LATEST so do nothing.
				continue;
			}
			else if (latestIsInvalidThunk) {
				// The latest thunked function is no longer there so can't pick the thunk. Instead keep MY function.
				ProgramMerge programListingMerge = getProgramListingMerge(KEEP_MY);
				programListingMerge.mergeFunction(thunkConflictAddress, monitor);
				continue;
			}
			// If we have a thunk function choice then a "Use For All" has already occurred.
			if (thunkChoice != ASK_USER) {
				merge(thunkConflictAddress, thunkChoice, monitor);
			}
			// Handle thunk function conflict.
			else if (askUser && mergeManager != null) {
				VerticalChoicesPanel choicesPanel =
					createThunkConflictPanel(thunkConflictAddress, monitor);

				boolean useForAll = (thunkChoice != ASK_USER);
				choicesPanel.setUseForAll(useForAll);
				choicesPanel.setConflictType("Thunk Function");

				setupConflictPanel(listingPanel, choicesPanel, thunkConflictAddress, monitor);
				monitor.checkCancelled();
			}
			else {
				merge(thunkConflictAddress, currentConflictOption, monitor);
			}
			monitor.checkCancelled();
		}

		showResolveErrors(ERROR_TITLE);
		showResolveInfo(INFO_TITLE);
//		clearResolveErrors();
//		clearResolveInfo();
	}

	private Function[] getFunctions(Address entryPoint) {
		Function[] functions = new Function[4];
		functions[RESULT] = functionManagers[RESULT].getFunctionAt(entryPoint);
		functions[LATEST] = functionManagers[LATEST].getFunctionAt(entryPoint);
		functions[MY] = functionManagers[MY].getFunctionAt(entryPoint);
		functions[ORIGINAL] = functionManagers[ORIGINAL].getFunctionAt(entryPoint);
		return functions;
	}

	private AddressSetView getBodySet(Address addr) {
		AddressSet set = new AddressSet(addr);
		Function latest = functionManagers[LATEST].getFunctionAt(addr);
		Function my = functionManagers[MY].getFunctionAt(addr);
		Function original = functionManagers[ORIGINAL].getFunctionAt(addr);
		if (latest != null) {
			set.add(latest.getBody());
		}
		if (my != null) {
			set.add(my.getBody());
		}
		if (original != null) {
			set.add(original.getBody());
		}
		return set;
	}

	class FunctionOverlapConflictChangeListener implements ChangeListener {
		int type;
		Address entryPt;
		TaskMonitor monitor;
		VariousChoicesPanel vPanel;

		FunctionOverlapConflictChangeListener(final int type, final Address entryPt,
				final VariousChoicesPanel vPanel, final TaskMonitor monitor) {
			this.type = type;
			this.entryPt = entryPt;
			this.monitor = monitor;
			this.vPanel = vPanel;
		}

		@Override
		public void stateChanged(ChangeEvent e) {
			ResolveConflictChangeEvent re = (ResolveConflictChangeEvent) e;
			int choice = re.getChoice();
			try {
				mergeOverlap(entryPt, getOptionForChoice(choice), currentMonitor);
			}
			catch (CancelledException e1) {
				Msg.error(this, "Unexpected Exception: " + e1.getMessage(), e1);
			}
			adjustUseForAll();
			adjustApply();
		}

		void adjustUseForAll() {
			if (mergeManager != null) {
				vPanel.adjustUseForAllEnablement();
			}
		}

		void adjustApply() {
			if (mergeManager != null) {
				mergeManager.setApplyEnabled(vPanel.allChoicesAreResolved());
			}
		}
	}

	private VariousChoicesPanel createOverlapConflictPanel(final Address addr,
			final TaskMonitor monitor) {
		final AddressSet resolveSet = overlapConflicts.get(addr);
		VariousChoicesPanel panel = getEmptyVariousPanel();

		runSwing(() -> {
			panel.setTitle("Function Overlap");
			StringBuffer buf = new StringBuffer();
			buf.append("Function @ ");
			ConflictUtility.addAddress(buf, addr);
			buf.append(" overlaps with different function(s) in other program.");
			buf.append("<br>");
			buf.append("The overlap address set is " +
				ConflictUtility.getEmphasizeString(resolveSet.toString()) + ".");
			panel.setHeader(buf.toString());
			ChangeListener changeListener =
				new FunctionOverlapConflictChangeListener(FUNC_OVERLAP, addr, panel, monitor);
			panel.addSingleChoice("Choose the version of functions to keep: ",
				new String[] { LATEST_TITLE, MY_TITLE }, changeListener);
		});
		return panel;
	}

	private VerticalChoicesPanel createBodyConflictPanel(final Address addr,
			final TaskMonitor monitor) {
		Function latestFunction = functionManagers[LATEST].getFunctionAt(addr);
		Function myFunction = functionManagers[MY].getFunctionAt(addr);
		String latest = "'" + LATEST_TITLE + "' version";
		String my = "'" + MY_TITLE + "' version";
		String latestBody = latestFunction.getBody().toString();
		String myBody = myFunction.getBody().toString();

		VerticalChoicesPanel panel = getEmptyVerticalPanel();

		runSwing(() -> {
			panel.setTitle("Function Body");
			StringBuffer buf = new StringBuffer();
			buf.append("Functions @ ");
			ConflictUtility.addAddress(buf, addr);
			buf.append(" have different bodies defined.");
			panel.setHeader(buf.toString());
			ChangeListener changeListener =
				new FunctionConflictChangeListener(FUNC_BODY, addr, panel, monitor);
			panel.setRowHeader(new String[] { "Option", "Body" });
			panel.addRadioButtonRow(new String[] { latest, latestBody }, LATEST_BUTTON_NAME,
				KEEP_LATEST, changeListener);
			panel.addRadioButtonRow(new String[] { my, myBody }, CHECKED_OUT_BUTTON_NAME, KEEP_MY,
				changeListener);
		});
		return panel;
	}

	private VerticalChoicesPanel createThunkConflictPanel(final Address addr,
			final TaskMonitor monitor) {
		Function latestFunction = functionManagers[LATEST].getFunctionAt(addr);
		Function myFunction = functionManagers[MY].getFunctionAt(addr);
		boolean bothThunks = latestFunction.isThunk() && myFunction.isThunk();
		String latest = "Keep" + (latestFunction.isThunk() ? " thunk " : " ") + "function '" +
			latestFunction.getName() + "' as in '" + LATEST_TITLE + "' version.";
		String my = "Keep" + (myFunction.isThunk() ? " thunk " : " ") + "function '" +
			myFunction.getName() + "' as in '" + MY_TITLE + "' version.";

		VerticalChoicesPanel panel = getEmptyVerticalPanel();

		runSwing(() -> {
			panel.setTitle("Thunk Function");
			StringBuffer buf = new StringBuffer();
			if (bothThunks) {
				buf.append("Thunks are to different functions @ ");
			}
			else {
				buf.append("One function is a thunk and the other is not @ ");
			}
			ConflictUtility.addAddress(buf, addr);
			buf.append(".");
			panel.setHeader(buf.toString());
			ChangeListener changeListener =
				new FunctionConflictChangeListener(FUNC_THUNK, addr, panel, monitor);
			panel.addRadioButtonRow(new String[] { latest }, LATEST_BUTTON_NAME, KEEP_LATEST,
				changeListener);
			panel.addRadioButtonRow(new String[] { my }, CHECKED_OUT_BUTTON_NAME, KEEP_MY,
				changeListener);
		});
		return panel;
	}

	protected void mergeParameters(Address entryPtAddress, int chosenConflictOption,
			TaskMonitor monitor) {
		Function resultFunction = listingMergeManager.mergeLatest.getResultProgram()
				.getFunctionManager()
				.getFunctionAt(entryPtAddress);
		if (resultFunction == null) {
			return;
		}
		ProgramMerge pgmMerge = null;
		if ((chosenConflictOption & KEEP_LATEST) != 0) {
			pgmMerge = listingMergeManager.mergeLatest;
		}
		else if ((chosenConflictOption & KEEP_MY) != 0) {
			pgmMerge = listingMergeManager.mergeMy;
		}
		else {
			return;
		}
		if (pgmMerge != null) {
			pgmMerge.replaceFunctionParameters(currentAddress, monitor);
			Function f =
				pgmMerge.getOriginProgram().getFunctionManager().getFunctionAt(entryPtAddress);
			if (f == null) {
				return;
			}
		}
	}

	class ParameterChangeListener implements ChangeListener {
		int type;
		Address entryPt;
		int ordinal;
		TaskMonitor monitor;
		VariousChoicesPanel vPanel;

		ParameterChangeListener(final int type, final Address entryPt, final int ordinal,
				final VariousChoicesPanel vPanel, final TaskMonitor monitor) {
			this.type = type;
			this.entryPt = entryPt;
			this.ordinal = ordinal;
			this.monitor = monitor;
			this.vPanel = vPanel;
		}

		@Override
		public void stateChanged(ChangeEvent e) {
			ResolveConflictChangeEvent re = (ResolveConflictChangeEvent) e;
			int choice = re.getChoice();
			mergeParameter(type, entryPt, ordinal, getOptionForChoice(choice), monitor);
			adjustUseForAll();
			adjustApply();
		}

		void adjustUseForAll() {
			if (mergeManager != null) {
				vPanel.adjustUseForAllEnablement();
			}
		}

		void adjustApply() {
			if (mergeManager != null) {
				mergeManager.setApplyEnabled(vPanel.allChoicesAreResolved());
			}
		}
	}

	private void setupAddressSetConflictPanel(final ListingMergePanel listingPanel,
			final JPanel conflictPanel, final Address entryPt, final AddressSetView addrSet,
			final TaskMonitor monitor) {
		this.currentAddress = entryPt;
		this.currentMonitor = monitor;

		try {
			SwingUtilities.invokeAndWait(() -> listingPanel.setBottomComponent(conflictPanel));
			SwingUtilities.invokeLater(() -> {
				// Set background color of function entry point code unit
				listingPanel.clearAllBackgrounds();
				listingPanel.paintAllBackgrounds(addrSet);
			});
		}
		catch (InterruptedException e) {
			showOverlapException(entryPt, e);
			return;
		}
		catch (InvocationTargetException e) {
			showOverlapException(entryPt, e);
			return;
		}
		if (mergeManager != null) {
			mergeManager.setApplyEnabled(false);
			mergeManager.showListingMergePanel(currentAddress);
		}
		// block until the user either cancels or hits the "Apply" button
		// on the merge dialog...
		// when the "Apply" button is hit, get the user's selection
		// and continue.
	}

	private void showOverlapException(final Address entryPt, Exception e) {
		String message = "Couldn't display body address set conflict for function at " +
			entryPt.toString(true) + ".\n " + e.getMessage();
		Msg.showError(this, mergeManager.getMergeTool().getToolFrame(), "Function Merge Error",
			message, e);
		// Should this just put a message on errorBuf instead?
	}

	/**
	 *
	 * @param entryPt
	 * @return
	 */
	private VariousChoicesPanel createParamInfoConflictPanel(final ParamInfoConflict pc,
			final TaskMonitor monitor) {
		Address entryPt = pc.entry;
		int ordinal = pc.ordinal;
		int conflicts = pc.paramConflicts;
		Function latestFunc = functionManagers[LATEST].getFunctionAt(entryPt);
		Function myFunc = functionManagers[MY].getFunctionAt(entryPt);
		Parameter latestParam = latestFunc.getParameter(ordinal);
		Parameter myParam = myFunc.getParameter(ordinal);

		VariousChoicesPanel panel = getEmptyVariousPanel();

		runSwing(() -> {
			panel.setTitle("Function Parameter");
			Parameter param = (latestParam != null) ? latestParam : myParam;
			String varInfo = "Storage: " +
				ConflictUtility.getEmphasizeString(param.getVariableStorage().toString());
			String text = "Function: " +
				ConflictUtility.getEmphasizeString(
					functionManagers[RESULT].getFunctionAt(entryPt).getName()) +
				ConflictUtility.spaces(4) + "EntryPoint: " +
				ConflictUtility.getAddressString(entryPt) + ConflictUtility.spaces(4) +
				"Parameter #" + ConflictUtility.getNumberString(param.getOrdinal() + 1) +
				ConflictUtility.spaces(4) + varInfo;
			panel.setHeader(text);
			panel.addInfoRow("Conflict", new String[] { LATEST_TITLE, MY_TITLE }, true);

//		if ((conflicts & VAR_TYPE) != 0) {
//			String latest = (latestParam instanceof RegisterParameter) ? "Register" : "Stack";
//			String my = (myParam instanceof RegisterParameter) ? "Register" : "Stack";
//			panel.addSingleChoice("Parameter Type", new String[] { latest, my },
//				new ParameterChangeListener(VAR_TYPE, entryPt, ordinal, panel, monitor));
//		}
			if ((conflicts & VAR_NAME) != 0) {
				String latest = latestParam.getName();
				String my = myParam.getName();
				panel.addSingleChoice("Parameter Name", new String[] { latest, my },
					new ParameterChangeListener(VAR_NAME, entryPt, ordinal, panel, monitor));
			}
			if ((conflicts & VAR_DATATYPE) != 0) {
				String latest = latestParam.getDataType().getName();
				String my = myParam.getDataType().getName();
				panel.addSingleChoice("Parameter Data Type", new String[] { latest, my },
					new ParameterChangeListener(VAR_DATATYPE, entryPt, ordinal, panel, monitor));
			}
//		if ((conflicts & VAR_LENGTH) != 0) {
//			String latest = latestParam.getLength();
//			String my = myParam.getLength();
//			panel.addSingleChoice("Parameter Length", new String[] {latest, my},
//					new ParameterChangeListener(VAR_LENGTH, entryPt, ordinal, panel, monitor));
//		}
			if ((conflicts & VAR_COMMENT) != 0) {
				String latest = latestParam.getComment();
				String my = myParam.getComment();
				panel.addSingleChoice("Parameter Comment", new String[] { latest, my },
					new ParameterChangeListener(VAR_COMMENT, entryPt, ordinal, panel, monitor));
			}
		});
		return panel;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#getConflicts()
	 */
	@Override
	public AddressSetView getConflicts() {
		return conflictSet;
	}

	@Override
	ProgramMerge getMergeLatest() {
		return listingMergeManager.mergeLatest;
	}

	@Override
	ProgramMerge getMergeMy() {
		return listingMergeManager.mergeMy;
	}

	@Override
	ProgramMerge getMergeOriginal() {
		return listingMergeManager.mergeOriginal;
	}

	//////////////////////////////////////////
	// Begin AbstractListingMerger methods.
	//////////////////////////////////////////

	/**
	 * Initializes the four programs and each of the ProgramDiffs
	 * typically needed to perform the merge.
	 * <br>Note: If you override this method, it should be the first method you call
	 * as "super.init()" to setup the common listing merge information.
	 *
	 */
	protected void initListingMerge() {
		mergeManager = listingMergeManager.mergeManager;
		errorBuf = new StringBuffer();
		infoBuf = new StringBuffer();

		programs[RESULT] = listingMergeManager.programs[RESULT];
		programs[ORIGINAL] = listingMergeManager.programs[ORIGINAL];
		programs[LATEST] = listingMergeManager.programs[LATEST];
		programs[MY] = listingMergeManager.programs[MY];

		functionManagers[LATEST] = programs[LATEST].getFunctionManager();
		functionManagers[MY] = programs[MY].getFunctionManager();
		functionManagers[ORIGINAL] = programs[ORIGINAL].getFunctionManager();
		functionManagers[RESULT] = programs[RESULT].getFunctionManager();

		resultAddressFactory = programs[RESULT].getAddressFactory();

		diffOriginalLatest = listingMergeManager.diffOriginalLatest;
		diffOriginalMy = listingMergeManager.diffOriginalMy;
		diffLatestMy = listingMergeManager.diffLatestMy;
	}

	protected void initializeAutoMerge(String progressMessage, int progressMin, int progressMax,
			TaskMonitor monitor) {
		this.minPhaseProgressPercentage = progressMin;
		this.maxPhaseProgressPercentage = progressMax;
		this.totalChanges = 0; // Actual merger will still need to set this value.
		this.changeNum = 0;
		mergeManager.updateProgress(progressMin, progressMessage);
		monitor.setMessage(progressMessage);
	}

	/**
	 * Gets the merge constant associated with the indicated program.
	 * @param pgm the program
	 * @return RESULT, LATEST, MY, ORIGINAL, or -1.
	 * A value of -1 indicates the program is not one of the four versioned programs.
	 * @see MergeConstants
	 */
	int getProgramIndex(Program pgm) {
		if (pgm == programs[RESULT]) {
			return RESULT;
		}
		else if (pgm == programs[LATEST]) {
			return LATEST;
		}
		else if (pgm == programs[MY]) {
			return MY;
		}
		else if (pgm == programs[ORIGINAL]) {
			return ORIGINAL;
		}
		return -1;
	}

	/**
	 * Gets the program associated with the indicated conflictOption
	 * @param chosenConflictOption PICK_LATEST, PICK_MY or PICK_ORIGINAL
	 * @return the program for the option or null
	 */
	Program getProgramForConflictOption(int chosenConflictOption) {
		switch (chosenConflictOption) {
			case KEEP_LATEST:
				return programs[LATEST];
			case KEEP_MY:
				return programs[MY];
			case KEEP_ORIGINAL:
				return programs[ORIGINAL];
			default:
				return null;
		}
	}

	/**
	 * Gets an address set indicating all addresses in the initial set that are the
	 * minimum address of a code unit in the specified program's listing.
	 * @param program the program to check for the start of each code unit.
	 * @param initialSet the initial address set to be checked for the starts of code units.
	 * @return the address set of all code unit min addresses in the initial set.
	 */
	AddressSet limitToStartofCodeUnits(Program program, AddressSetView initialSet) {
		Listing listing = program.getListing();
		AddressSet returnSet = new AddressSet();
		AddressIterator iter = initialSet.getAddresses(true);
		while (iter.hasNext()) {
			Address address = iter.next();
			CodeUnit cu = listing.getCodeUnitAt(address);
			if (cu != null) {
				// Only automerge functions that are still at a code unit after code unit merge.
				returnSet.addRange(address, address);
			}
		}
		return returnSet;
	}

	/** Return an address set that contains all addresses that make up the code
	 * units containing the indicated address in the LATEST, MY, and ORIGINAL programs.
	 * @param addr the address
	 * @return the code unit address set
	 */
	protected AddressSetView getCodeUnitAddressSet(Address addr) {
		return getCodeUnitAddressSet(new AddressSet(addr, addr));
	}

	/** Return an address set that contains all addresses that make up the code
	 * units containing the indicated addresses in the LATEST, MY, and ORIGINAL programs.
	 * @param addrs the addresses
	 * @return the code unit address set
	 */
	protected AddressSetView getCodeUnitAddressSet(AddressSet addrs) {
		AddressSet codeSet = new AddressSet();
		codeSet.add(DiffUtility.getCodeUnitSet(addrs, programs[LATEST]));
		codeSet.add(DiffUtility.getCodeUnitSet(addrs, programs[MY]));
		codeSet.add(DiffUtility.getCodeUnitSet(addrs, programs[ORIGINAL]));
		return codeSet;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#apply()
	 */
	@Override
	public boolean apply() {
		numConflictsResolved = 0;
		if (currentConflictPanel != null) {
			numConflictsResolved = currentConflictPanel.getNumConflictsResolved();
			if (currentConflictPanel.allChoicesAreResolved()) {
				currentConflictPanel.removeAllListeners();

				int useForAllChoice = currentConflictPanel.getUseForAllChoice();

				// If the "Use For All" check box is selected
				// then save the option chosen for this conflict type.
				if (currentConflictPanel.getUseForAll()) {
					setChoiceForFunctionConflictType(currentConflictType, useForAllChoice);
				}

				return true;
			}
			return false;
		}
		return true;
	}

	private void setChoiceForFunctionConflictType(FunctionConflictType functionConflictType,
			int choiceForFunctionConflict) {
		switch (functionConflictType) {
			case FUNCTION_OVERLAP_CONFLICT:
				overlapChoice = getOptionForChoice(choiceForFunctionConflict);
				break;
			case FUNCTION_BODY_CONFLICT:
				bodyChoice = choiceForFunctionConflict;
				break;
			case FUNCTION_REMOVE_CONFLICT:
				removeChoice = choiceForFunctionConflict;
				break;
			case FUNCTION_RETURN_CONFLICT:
				functionReturnChoice = choiceForFunctionConflict;
				break;
			case FUNCTION_DETAILS_CONFLICT:
				detailsChoice = getOptionForChoice(choiceForFunctionConflict);
				break;
			case VARIABLE_STORAGE_CONFLICT:
				variableStorageChoice = getOptionForChoice(choiceForFunctionConflict);
				break;
			case PARAMETER_SIGNATURE_CONFLICT:
				parameterSignatureChoice = choiceForFunctionConflict;
				break;
			case PARAMETER_INFO_CONFLICT:
				parameterInfoChoice = getOptionForChoice(choiceForFunctionConflict);
				break;
			case REMOVED_LOCAL_VARIABLE_CONFLICT:
				removedLocalVariableChoice = choiceForFunctionConflict;
				break;
			case LOCAL_VARIABLE_DETAIL_CONFLICT:
				localVariableDetailChoice = getOptionForChoice(choiceForFunctionConflict);
				break;
			case THUNK_CONFLICT:
				thunkChoice = choiceForFunctionConflict;
				break;
			default:
				Msg.showError(this, listingMergePanel, "Unrecognized Function Conflict Type",
					"Unrecognized indicator (" + functionConflictType +
						") for function conflict type to merge.");
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#cancel()
	 */
	@Override
	public void cancel() {
		// Do nothing
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#getNumConflictsResolved()
	 */
	@Override
	public int getNumConflictsResolved() {
		return numConflictsResolved;
	}

	/**
	 * Updates the progress bar associated with this phase of the merge.
	 * Before beginning to auto-merge the <code>totalChanges</code> and <code>changeNum</code> must be set.
	 * This method should then be called as changes are made to update the change bar.
	 * This assumes that each change is equivalent in terms of shown progress.
	 * @param increment the number of changes completed relative to the total
	 * number of changes for this auto-merger.
	 */
	protected void incrementProgress(int increment) {
		int progressRange = maxPhaseProgressPercentage - minPhaseProgressPercentage;
		changeNum += increment;
		int granularity = (totalChanges / progressRange) + 1;
		if (changeNum % granularity == 0) {
			if (totalChanges <= 0) {
				totalChanges = 1;
			}
			mergeManager.updateProgress(
				minPhaseProgressPercentage + ((changeNum * progressRange) / totalChanges));
		}
	}

	/**
	 * Updates the progress bar associated with this phase of the merge.
	 * @param myPercentComplete the progress percentage completed for this merger.
	 * This should be a value from 0 to 100.
	 */
	protected void updateProgress(int myPercentComplete) {
		int progressRange = maxPhaseProgressPercentage - minPhaseProgressPercentage;
		int myProgress = (myPercentComplete * progressRange) / 100;
		mergeManager.updateProgress(minPhaseProgressPercentage + myProgress);
	}

	/**
	 * Updates the progress bar and the progress message details associated with this
	 * phase of the merge.
	 * @param myPercentComplete the progress percentage completed for this merger.
	 * This should be a value from 0 to 100.
	 * @param message a message indicating what is currently occurring in this phase.
	 * Null indicates to use the default message.
	 */
	protected void updateProgress(int myPercentComplete, String message) {
		int progressRange = maxPhaseProgressPercentage - minPhaseProgressPercentage;
		int myProgress = (myPercentComplete * progressRange) / 100;
		mergeManager.updateProgress(minPhaseProgressPercentage + myProgress);
		mergeManager.updateProgress(message);
	}

	//////////////////////////////////////////
	// End AbstractListingMerger methods.
	//////////////////////////////////////////

	@Override
	protected String getInfoTitle() {
		return INFO_TITLE;
	}

	@Override
	protected String getErrorTitle() {
		return ERROR_TITLE;
	}

	private boolean isEquivalent(Function function1, Function function2) {
		if (function1 == function2) {
			return true;
		}
		if (function1 == null || function2 == null) {
			return false;
		}

		if (!function1.getName().equals(function2.getName())) {
			return false;
		}
		if (function1.isExternal()) {
			if (!SystemUtilities.isEqual(function1.getExternalLocation(),
				function2.getExternalLocation())) {
				return false;
			}
		}
		else if (function2.isExternal()) {
			return false;
		}
		if (!function1.getEntryPoint().equals(function2.getEntryPoint())) {
			return false;
		}

		if (!SystemUtilities.isEqual(function1.getBody(), function2.getBody())) {
			return false;
		}

		Function thunkedFunction1 = function1.getThunkedFunction(false);
		Function thunkedFunction2 = function2.getThunkedFunction(false);
		if (thunkedFunction1 != null) {
			if (thunkedFunction2 == null) {
				return false;
			}
			if (thunkedFunction1.isExternal() != thunkedFunction2.isExternal()) {
				return false;
			}
			if (!thunkedFunction1.isExternal()) {
				return thunkedFunction1.getEntryPoint().equals(thunkedFunction2.getEntryPoint());
			}
			return isEquivalent(thunkedFunction1, thunkedFunction2);
		}
		else if (thunkedFunction2 != null) {
			return false;
		}

		// TODO: using isEquivelent seems bad

		Parameter returnParam1 = function1.getReturn();
		Parameter returnParam2 = function2.getReturn();
		if (!returnParam1.equals(returnParam2)) {
			return false;
		}

		if (function1.getStackPurgeSize() != function2.getStackPurgeSize()) {
			return false;
		}
		if (function1.getStackFrame().getReturnAddressOffset() != function2.getStackFrame()
				.getReturnAddressOffset()) {
			return false;
		}
		if (!function1.getCallingConventionName().equals(function2.getCallingConventionName())) {
			return false;
		}
		if (function1.hasVarArgs() != function2.hasVarArgs()) {
			return false;
		}
		if (function1.isInline() != function2.isInline()) {
			return false;
		}
		if (function1.hasNoReturn() != function2.hasNoReturn()) {
			return false;
		}
		if (function1.hasCustomVariableStorage() != function2.hasCustomVariableStorage()) {
			return false;
		}
		if (function1.getSignatureSource() != function2.getSignatureSource()) {
			return false;
		}

		if (!VariableUtilities.equivalentVariableArrays(function1.getParameters(),
			function2.getParameters())) {
			return false;
		}
		if (!VariableUtilities.equivalentVariableArrays(function1.getLocalVariables(),
			function2.getLocalVariables())) {
			return false;
		}
		return true;

	}
}
