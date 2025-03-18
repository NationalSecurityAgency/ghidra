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
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.*;
import ghidra.util.datastruct.LongLongHashtable;
import ghidra.util.datastruct.ObjectIntHashtable;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Class for merging external function and label changes. This class can merge external function
 * and label changes that were made to the checked out version. It can determine
 * where there are conflicts between the latest checked in version and my
 * checked out version. It can then allow the user to manually merge the conflicting
 * functions and labels. External functions do not have bodies.
 * However their signatures, stacks and variables do get merged.
 * This class extends the AbstractFunctionMerger to handle merging of function changes when both
 * My and Latest have changed functions.
 * <br>Note: Externals are uniquely identified by symbol ID and the name (including namespace is
 * also used to match externals when the external is transitioned from a label to a function
 * and vice versa.
 * <br>Important: This class is intended to be used only for a single program
 * version merge. It should be constructed, followed by an autoMerge(), and lastly
 * each external with a conflict should have mergeConflicts() called on it.
 */
public class ExternalFunctionMerger extends AbstractFunctionMerger implements ListingMerger {

	final static String EXTERNALS_PHASE = "Externals";
	private final static String CONFLICT_TYPE = "Externals";
	private final static String INFO_TITLE = CONFLICT_TYPE + " Merge Information";
	private final static String ERROR_TITLE = CONFLICT_TYPE + " Merge Errors";

	static protected final int EXTERNAL_NAMESPACE = 0x001;
	static protected final int EXTERNAL_LABEL = 0x002;
	static protected final int EXTERNAL_ADDRESS = 0x004;
// Source Type differences have been commented out.
// Instead source type will be replaced whenever the label name is replaced.
//	static protected final int EXTERNAL_SOURCE_TYPE = 0x008;
	static protected final int EXTERNAL_SYMBOL_TYPE = 0x010;
	static protected final int EXTERNAL_DATA_TYPE = 0x020;
	static protected final int EXTERNAL_FUNCTION = 0x040;
	static protected final int HIGHEST_DETAIL_BIT_SHIFT = 6; // 0 based
	static protected final int ALL_EXTERNAL_DIFFERENCES = EXTERNAL_NAMESPACE | EXTERNAL_LABEL |
		EXTERNAL_ADDRESS | EXTERNAL_SYMBOL_TYPE | EXTERNAL_DATA_TYPE | EXTERNAL_FUNCTION;
//	static protected final int ALL_EXTERNAL_DIFFERENCES = EXTERNAL_NAMESPACE | EXTERNAL_LABEL |
//			EXTERNAL_ADDRESS | EXTERNAL_SOURCE_TYPE | EXTERNAL_SYMBOL_TYPE | EXTERNAL_DATA_TYPE |
//			EXTERNAL_FUNCTION;

	/** Keep the external location added in LATEST to resolve a conflict. */
	public static final int KEEP_LATEST_ADD = 1;
	/** Keep the external location added in MY to resolve a conflict. */
	public static final int KEEP_MY_ADD = 2;
	/** Keep both of the external locations added in the LATEST and in MY when in conflict. */
	public static final int KEEP_BOTH_ADDS = 4;
	/** Merge both of the external locations added in the LATEST and in MY when in conflict. */
	public static final int MERGE_BOTH_ADDS = 8;

	public static final String KEEP_BOTH_BUTTON_NAME = "KeepBothVersionsRB";
	public static final String MERGE_BOTH_BUTTON_NAME = "MergeBothVersionsRB";

	private ExternalAddConflictPanel addConflictPanel;

	private ExternalConflictInfoPanel conflictInfoPanel; // This goes above the listing merge panels

	private int totalConflicts = 0;
	private int conflictIndex = 0;

	private ProgramChangeSet latestChanges;
	private ProgramChangeSet myChanges;

	private LongLongHashtable originalToLatestHash;
	private LongLongHashtable latestToOriginalHash;
	private LongLongHashtable originalToMyHash;
	private LongLongHashtable myToOriginalHash;

	LongLongHashtable originalResolvedSymbols; // Maps original symbolID to result symbolID
	LongLongHashtable latestResolvedSymbols; // Maps latest symbolID to result symbolID
	LongLongHashtable myResolvedSymbols; // Maps my symbolID to result symbolID

	/** Used to merge from Checked Out version to Result version. */
	private ProgramMerge mergeMy;
	/** Used to merge from Latest version to Result version. */
	private ProgramMerge mergeLatest;
	/** Used to merge from Original version to Result version. */
	private ProgramMerge mergeOriginal;

	HashSet<Long> latestAddIDs = new HashSet<>(); // Added Latest IDs only (initially adds and changes)
	HashSet<Long> latestRemovedOriginalIDs = new HashSet<>(); // Latest Removed Original IDs only (initially adds and changes)
	HashSet<Long> latestModifiedIDs = new HashSet<>(); // Changed Latest IDs only
	HashSet<Long> myAddIDs = new HashSet<>(); // Added My IDs only (initially adds and changes)
	HashSet<Long> myRemovedOriginalIDs = new HashSet<>(); // My Removed Original IDs only (initially adds and changes)
	HashSet<Long> myModifiedIDs = new HashSet<>(); // Changed My IDs only

	HashSet<Long> removeConflictIDs = new HashSet<>(); // IDs from ORIGINAL where there are external removal conflicts.
	HashSet<Long> removeFunctionConflictIDs = new HashSet<>(); // IDs from ORIGINAL where there are function removal conflicts.

	HashSet<Long> renamedConflictIDs = new HashSet<>(); // result ID for symbol that was renamed to avoid a conflict.

	private SymbolTable[] symbolTables = new SymbolTable[4];
	private ExternalManager[] externalManagers = new ExternalManager[4];
	private ConflictListener conflictListener = null;

	/** addresses of changes to externals between the original and latest versioned program. */
	AddressSetView latestExternalSet;
	/** addresses of changes to externals between the original and my modified program. */
	AddressSetView myExternalSet;

	// externalDetailConflicts: key = Address [MyEntryPoint], value = int (bits for each basic external detail type)
	protected ObjectIntHashtable<Address> externalDetailConflicts = new ObjectIntHashtable<>();

	protected AddressSet externalDataTypeConflicts;
	protected AddressSet externalFunctionVersusDataTypeConflicts;

	// externalAddConflicts will need to ask user KEEP_LATEST, KEEP_MY, KEEP_BOTH, or MERGE_BOTH
	// externalAddConflicts (key=MyExternalSymbolID, value=LatestExternalSymbolID)
	protected LongLongHashtable externalAddConflicts = new LongLongHashtable();

	// The translators that get used by the ProgramMerge instances.
	ExternalsAddressTranslator myAddressTranslator;
	ExternalsAddressTranslator latestAddressTranslator;
	ExternalsAddressTranslator originalAddressTranslator;

	protected int totalChanges = 0; // Total number of changes for this auto-merger.
	protected int changeNum; // Current change number being auto-merged out of totalChanges.
	private boolean showListingPanel;

	protected int externalFunctionRemovalChoice = ASK_USER;
	protected int externalFunctionChoice = ASK_USER;
	protected int externalDetailsChoice = ASK_USER;
	protected int externalDataTypeChoice = ASK_USER;
	protected int externalFunctionVsDataTypeChoice = ASK_USER;
	protected int externalAddChoice = ASK_USER;
	protected int externalRemoveChoice = ASK_USER;

	protected static enum ExternalConflictType {
		EXTERNAL_FUNCTION_REMOVE_CONFLICT,
		EXTERNAL_FUNCTION_CONFLICT,
		EXTERNAL_DETAILS_CONFLICT,
		EXTERNAL_DATA_TYPE_CONFLICT,
		EXTERNAL_FUNCTION_VS_DATA_TYPE_CONFLICT,
		EXTERNAL_ADD_CONFLICT,
		EXTERNAL_REMOVE_CONFLICT,
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
		THUNK_CONFLICT
	}

	ExternalConflictType currentExternalConflictType = null;

	/**
	 * Manages changes and conflicts for externals between the latest versioned
	 * program and the modified program being checked into version control.
	 * @param listingMergeManager the top level merge manager for merging a program version.
	 * @param showListingPanel true to show the listing panel.
	 */
	public ExternalFunctionMerger(ListingMergeManager listingMergeManager,
			boolean showListingPanel) {
		super(listingMergeManager.mergeManager, listingMergeManager.programs);
		this.listingMergeManager = listingMergeManager;
		this.showListingPanel = showListingPanel;
		this.listingMergePanel = listingMergeManager.getListingMergePanel();
		this.latestChanges = listingMergeManager.latestChanges;
		this.myChanges = listingMergeManager.myChanges;
		init();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.AbstractListingMerger#init()
	 */
	public void init() {
		initializeSymbolTables();
		initializeExternalManagers();
		initializeMessages();
		initializeChangeSets();
		initializeProgramMerges();
		initializeConflictSets();

		originalToLatestHash = new LongLongHashtable();
		latestToOriginalHash = new LongLongHashtable();
		originalToMyHash = new LongLongHashtable();
		myToOriginalHash = new LongLongHashtable();
	}

	/**
	 * Determine the type of changes to the symbols in the LATEST and MY (CheckedOut) program.
	 * Changes can be symbol removed, added, changed, renamed, and set to primary.
	 * @param monitor task monitor for displaying progress to the user
	 * @throws CancelledException if the user cancels the merge.
	 */
	private void setupSymbolChanges(TaskMonitor monitor) throws CancelledException {

		fillExternalAddSymbolSet(symbolTables[MY], myChanges.getSymbolAdditions(), myAddIDs);
		fillExternalChangeSymbolSets(symbolTables[MY], myChanges.getSymbolChanges(),
			myRemovedOriginalIDs, myModifiedIDs);
		fillExternalAddSymbolSet(symbolTables[LATEST], latestChanges.getSymbolAdditions(),
			latestAddIDs);
		fillExternalChangeSymbolSets(symbolTables[LATEST], latestChanges.getSymbolChanges(),
			latestRemovedOriginalIDs, latestModifiedIDs);
	}

	private void fillExternalAddSymbolSet(SymbolTable symbolTable, long[] symbolIDs,
			HashSet<Long> externalAddSet) {

		for (long symbolID : symbolIDs) {
			Symbol symbol = symbolTable.getSymbol(symbolID);
			if (symbol == null) {
				continue;
			}
			SymbolType symbolType = symbol.getSymbolType();
			if (symbol.isExternal() &&
				(symbolType == SymbolType.FUNCTION || symbolType == SymbolType.LABEL)) {

				externalAddSet.add(symbolID);
			}
		}
	}

	private void fillExternalChangeSymbolSets(SymbolTable symbolTable, long[] symbolIDs,
			HashSet<Long> externalRemoveSet, HashSet<Long> externalModifySet) {

		for (long symbolID : symbolIDs) {
			Symbol symbol = symbolTable.getSymbol(symbolID);
			if (symbol == null) {
				Symbol originalSymbol = symbolTables[ORIGINAL].getSymbol(symbolID);
				if (originalSymbol == null) {
					continue;
				}
				SymbolType symbolType = originalSymbol.getSymbolType();
				if (originalSymbol.isExternal() &&
					(symbolType == SymbolType.FUNCTION || symbolType == SymbolType.LABEL)) {
					externalRemoveSet.add(symbolID);
				}
				continue;
			}
			SymbolType symbolType = symbol.getSymbolType();
			if (symbol.isExternal() &&
				(symbolType == SymbolType.FUNCTION || symbolType == SymbolType.LABEL)) {
				externalModifySet.add(symbolID);
			}
		}
	}

	private void initializeSymbolTables() {
		symbolTables[LATEST] = programs[LATEST].getSymbolTable();
		symbolTables[MY] = programs[MY].getSymbolTable();
		symbolTables[ORIGINAL] = programs[ORIGINAL].getSymbolTable();
		symbolTables[RESULT] = programs[RESULT].getSymbolTable();
	}

	private void initializeExternalManagers() {
		externalManagers[RESULT] = programs[RESULT].getExternalManager();
		externalManagers[LATEST] = programs[LATEST].getExternalManager();
		externalManagers[MY] = programs[MY].getExternalManager();
		externalManagers[ORIGINAL] = programs[ORIGINAL].getExternalManager();
	}

	private void initializeMessages() {
		errorBuf = new StringBuffer();
		infoBuf = new StringBuffer();
	}

	private void initializeChangeSets() {
		Address minExternalAddress = AddressSpace.EXTERNAL_SPACE.getMinAddress();
		Address maxExternalAddress = AddressSpace.EXTERNAL_SPACE.getMaxAddress();
		AddressSetView resultExternalSet = new AddressSet(minExternalAddress, maxExternalAddress);
		this.latestExternalSet = latestChanges.getAddressSet().intersect(resultExternalSet);
		this.myExternalSet = myChanges.getAddressSet().intersect(resultExternalSet);
	}

	private void initializeProgramMerges() {
		myAddressTranslator = new ExternalsAddressTranslator(programs[RESULT], programs[MY]);
		latestAddressTranslator =
			new ExternalsAddressTranslator(programs[RESULT], programs[LATEST]);
		originalAddressTranslator =
			new ExternalsAddressTranslator(programs[RESULT], programs[ORIGINAL]);

		// Set up for the different types of merges that are needed to merge changes.
		mergeMy = new ProgramMerge(myAddressTranslator);
		mergeLatest = new ProgramMerge(latestAddressTranslator);
		mergeOriginal = new ProgramMerge(originalAddressTranslator);
	}

	private void initializeConflictSets() {
		AddressFactory myAddressFactory = programs[MY].getAddressFactory();
//		AddressFactory originalAddressFactory = programs[ORIGINAL].getAddressFactory();

		externalDataTypeConflicts = new AddressSet();
		externalFunctionVersusDataTypeConflicts = new AddressSet();
		removeSet = new AddressSet();
		funcConflicts = new ObjectIntHashtable<>();
		funcSet = new AddressSet();
	}

	public String getName() {
		return "Externals Merger";
	}

	public String getDescription() {
		return "Merge Externals";
	}

	public boolean allChoicesAreResolved() {
		if (currentConflictPanel != null) {
			if (currentConflictPanel.allChoicesAreResolved()) {
				currentConflictPanel.removeAllListeners();
				return true;
			}
			return false;
		}
		return true;
	}

	@Override
	public boolean apply() {
		if (mergeManager == null) {
			return false;
		}
		boolean resolvedAll = allChoicesAreResolved();
		if (resolvedAll) {
			if (conflictListener != null) {
				conflictListener.resolveConflict();
				conflictListener = null;
			}

			int useForAllChoice = currentConflictPanel.getUseForAllChoice();
			// If the "Use For All" check box is selected
			// then save the option chosen for this conflict type.
			if (currentConflictPanel.getUseForAll()) {
				setChoiceForExternalConflictType(currentExternalConflictType, useForAllChoice);
			}

			mergeManager.setApplyEnabled(false);
			return true;
		}
		mergeManager.setStatusText("Please select an option to resolve each conflict.");
		return false;
	}

	private void setChoiceForExternalConflictType(ExternalConflictType externalConflictType,
			int choiceForFunctionConflict) {
		switch (externalConflictType) {
			case EXTERNAL_FUNCTION_REMOVE_CONFLICT:
				externalFunctionRemovalChoice = choiceForFunctionConflict;
				break;
			case EXTERNAL_FUNCTION_CONFLICT:
				externalFunctionChoice = choiceForFunctionConflict;
				break;
			case EXTERNAL_DETAILS_CONFLICT:
				externalDetailsChoice = getOptionForChoice(choiceForFunctionConflict);
				break;
			case EXTERNAL_DATA_TYPE_CONFLICT:
				externalDataTypeChoice = choiceForFunctionConflict;
				break;
			case EXTERNAL_FUNCTION_VS_DATA_TYPE_CONFLICT:
				externalFunctionVsDataTypeChoice = choiceForFunctionConflict;
				break;
			case EXTERNAL_ADD_CONFLICT:
				externalAddChoice = choiceForFunctionConflict;
				break;
			case EXTERNAL_REMOVE_CONFLICT:
				externalRemoveChoice = choiceForFunctionConflict;
				break;
			case FUNCTION_OVERLAP_CONFLICT:
				overlapChoice = choiceForFunctionConflict;
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
				Msg.showError(this, listingMergePanel, "Unrecognized External Conflict Type",
					"Unrecognized indicator (" + externalConflictType +
						") for external conflict type to merge.");
		}
	}

	@Override
	public void cancel() {
		// Do nothing.

		// Should this call dispose()?
	}

	@SuppressWarnings("unchecked")
	@Override
	public void autoMerge(int progressMin, int progressMax, TaskMonitor monitor)
			throws ProgramConflictException, MemoryAccessException, CancelledException {

		if (mergeManager != null) {
			latestResolvedDts = (Map<Long, DataType>) mergeManager
					.getResolveInformation(MergeConstants.RESOLVED_LATEST_DTS);
			myResolvedDts = (Map<Long, DataType>) mergeManager
					.getResolveInformation(MergeConstants.RESOLVED_MY_DTS);
			origResolvedDts = (Map<Long, DataType>) mergeManager
					.getResolveInformation(MergeConstants.RESOLVED_ORIGINAL_DTS);

			latestResolvedSymbols = (LongLongHashtable) mergeManager
					.getResolveInformation(MergeConstants.RESOLVED_LATEST_SYMBOLS);
			myResolvedSymbols = (LongLongHashtable) mergeManager
					.getResolveInformation(MergeConstants.RESOLVED_MY_SYMBOLS);
			originalResolvedSymbols = (LongLongHashtable) mergeManager
					.getResolveInformation(MergeConstants.RESOLVED_ORIGINAL_SYMBOLS);
		}

		initializeAutoMerge("Auto-merging External Labels and Functions and determining conflicts.",
			progressMin, progressMax, monitor);

		monitor.checkCancelled();
		clearResolveInfo();

		setupSymbolChanges(monitor); // Creates ID arrays used by processing methods.

		monitor.setMessage("Auto-merging Externals and determining conflicts.");

		getAddsRemovesChangesForExternals(monitor);

		saveInitialIDHashInfo();

//		mergeManager.updateProgress(25, "Finding conflicts for removed externals.");
		determineExternalRemoveConflicts(monitor);

//		mergeManager.updateProgress(35, "Finding conflicts for changed externals.");
		determineExternalChangeConflicts(monitor);

//		mergeManager.updateProgress(85, "Finding conflicts for added externals.");
		determineExternalAddConflicts(monitor);

		mergeManager.updateProgress(100, "Done auto-merging Externals and determining conflicts.");

		showResolveErrors(ERROR_TITLE);
		showResolveInfo(INFO_TITLE);
	}

	protected void initializeAutoMerge(String progressMessage, int progressMin, int progressMax,
			TaskMonitor monitor) {
		// For now, ignore the min and max values passed in and assume them to be 0 and 100 respectively.
		this.totalChanges = 0; // Actual merger will still need to set this value.
		this.changeNum = 0;
		mergeManager.updateProgress(0, progressMessage);
		monitor.setMessage(progressMessage);
	}

	private void saveInitialIDHashInfo() {
		// -1 is used to indicate removal of the symbol.
		for (Long originalID : latestRemovedOriginalIDs) { // Removed
			long resultID = -1;
			originalResolvedSymbols.put(originalID, resultID);
			long myID = resolveMyIDFromOriginalID(originalID);
			if (myID != -1) {
				myResolvedSymbols.put(myID, resultID);
			}
		}
		for (Long latestID : latestAddIDs) { // Added
			Long resultID = latestID;
			latestResolvedSymbols.put(latestID, resultID);
		}
		for (Long latestID : latestModifiedIDs) { // Changed
			Long resultID = latestID;
			latestResolvedSymbols.put(latestID, resultID);
			long originalID = resolveOriginalIDFromLatestID(latestID);
			originalResolvedSymbols.put(originalID, resultID);
		}
	}

	private void getAddsRemovesChangesForExternals(TaskMonitor monitor) throws CancelledException {

		mergeManager.updateProgress(0, "Finding changes to Externals in " + LATEST_TITLE + "...");
		fixupLatestChangeIDsMarkedAsRemovesAndAdds(monitor);
		getNonSymbolChangesForLatestExternals(monitor);

		mergeManager.updateProgress(5, "Finding changes to Externals in " + MY_TITLE + "...");
		fixupMyChangeIDsMarkedAsRemovesAndAdds(monitor);
		getNonSymbolChangesForMyExternals(monitor);

		totalChanges =
			latestAddIDs.size() + latestModifiedIDs.size() + latestRemovedOriginalIDs.size() +
				myAddIDs.size() + myModifiedIDs.size() + myRemovedOriginalIDs.size();
	}

	private void fixupLatestChangeIDsMarkedAsRemovesAndAdds(TaskMonitor monitor) {
		// NOTE: Things get rather complicated when an external location transitions to
		// a function since it is conveyed as a symbol removal and an add even though it
		// is really the same external location.
		@SuppressWarnings("unchecked")
		HashSet<Long> latestRemovedIDs = (HashSet<Long>) latestRemovedOriginalIDs.clone();
		for (Long id : latestRemovedIDs) {
			long originalID = id.longValue();
			Symbol originalSymbol = symbolTables[ORIGINAL].getSymbol(originalID);
			Address originalAddress = originalSymbol.getAddress();
			Symbol latestSymbol = SimpleDiffUtility.getMatchingExternalSymbol(programs[ORIGINAL],
				originalSymbol, programs[LATEST], false, latestAddIDs);
			if (latestSymbol != null) {
				Address latestAddress = latestSymbol.getAddress();
				// Check the external space addresses to ensure they are the same.
				if (originalAddress.equals(latestAddress)) {
					// This remove/add appears to be a change
					long latestID = latestSymbol.getID();
					fixupLatestExternalTypeChanges(originalID, latestID);
				}
			}
		}
	}

	private void fixupMyChangeIDsMarkedAsRemovesAndAdds(TaskMonitor monitor) {
		@SuppressWarnings("unchecked")
		HashSet<Long> myRemovedIDs = (HashSet<Long>) myRemovedOriginalIDs.clone();
		for (Long id : myRemovedIDs) {
			long originalID = id.longValue();
			Symbol originalSymbol = symbolTables[ORIGINAL].getSymbol(originalID);
			Address originalAddress = originalSymbol.getAddress();
			Symbol mySymbol = SimpleDiffUtility.getMatchingExternalSymbol(programs[ORIGINAL],
				originalSymbol, programs[MY], false, myAddIDs);
			if (mySymbol != null) {
				Address myAddress = mySymbol.getAddress();
				// Check the external space addresses to ensure they are the same.
				if (originalAddress.equals(myAddress)) {
					// This remove/add appears to be a change
					long myID = mySymbol.getID();
					fixupMyExternalTypeChanges(originalID, myID);
				}
			}
		}
	}

	private void getNonSymbolChangesForLatestExternals(TaskMonitor monitor)
			throws CancelledException {
		AddressIterator latestModifiedAddressIterator = latestExternalSet.getAddresses(true);
		while (latestModifiedAddressIterator.hasNext()) {
			monitor.checkCancelled();
			Address externalAddress = latestModifiedAddressIterator.next();
			Symbol latestSymbol = symbolTables[LATEST].getPrimarySymbol(externalAddress);
			if (latestSymbol == null) {
				continue; // External was removed. (Should be handled via removed symbol ID.)
			}
			long latestID = latestSymbol.getID();
			if (latestModifiedIDs.contains(latestID) || latestAddIDs.contains(latestID)) {
				continue; // External is already in ID set for changes or adds.
			}

			long originalID = resolveOriginalIDFromLatestID(latestID);
			Symbol originalSymbol = symbolTables[ORIGINAL].getSymbol(originalID);
			if (originalSymbol != null) {
				ExternalLocation latestExternalLocation =
					externalManagers[LATEST].getExternalLocation(latestSymbol);
				ExternalLocation originalExternalLocation =
					externalManagers[ORIGINAL].getExternalLocation(originalSymbol);
				if (!equivalentExternals(latestExternalLocation, originalExternalLocation)) {
					// Otherwise, something was changed about this External.
					latestModifiedIDs.add(latestID);
				}
				continue;
			}
			// Otherwise we have a change without an original. Huh?
			Msg.error(this, "Why is there a change to LATEST external without an ORIGINAL at " +
				externalAddress.toString(true) + "?");
		}
	}

	private void getNonSymbolChangesForMyExternals(TaskMonitor monitor) throws CancelledException {
		AddressIterator myModifiedAddressIterator = myExternalSet.getAddresses(true);
		while (myModifiedAddressIterator.hasNext()) {
			monitor.checkCancelled();
			Address externalAddress = myModifiedAddressIterator.next();
			Symbol mySymbol = symbolTables[MY].getPrimarySymbol(externalAddress);
			if (mySymbol == null) {
				continue; // External was removed. (Should be handled via removed symbol ID.)
			}
			long myID = mySymbol.getID();
			if (myModifiedIDs.contains(myID) || myAddIDs.contains(myID)) {
				continue; // External is already in ID set for changes or adds.
			}

			long originalID = resolveOriginalIDFromMyID(myID);
			Symbol originalSymbol = symbolTables[ORIGINAL].getSymbol(originalID);
			if (originalSymbol != null) {
				ExternalLocation myExternalLocation =
					externalManagers[MY].getExternalLocation(mySymbol);
				ExternalLocation originalExternalLocation =
					externalManagers[ORIGINAL].getExternalLocation(originalSymbol);
				if (!equivalentExternals(myExternalLocation, originalExternalLocation)) {
					// Otherwise, something was changed about this External.
					myModifiedIDs.add(myID);
				}
				continue;
			}
			// Otherwise we have a change without an original. Huh?
			Msg.error(this, "Why is there a change to MY external without an ORIGINAL at " +
				externalAddress.toString(true) + "?");
		}
	}

	private void fixupLatestExternalTypeChanges(long originalID, long latestID) {
		// The type was changed. Convert this from a "Remove/Add" to a "Change".
		latestModifiedIDs.add(latestID);
		latestRemovedOriginalIDs.remove(originalID);
		latestAddIDs.remove(latestID);
		originalToLatestHash.put(originalID, latestID);
		latestToOriginalHash.put(latestID, originalID);
	}

	private void fixupMyExternalTypeChanges(long originalID, long myID) {
		// The type was changed. Convert this from a "Remove/Add" to a "Change".
		myModifiedIDs.add(myID);
		myRemovedOriginalIDs.remove(originalID);
		myAddIDs.remove(myID);
		originalToMyHash.put(originalID, myID);
		myToOriginalHash.put(myID, originalID);
	}

	private void saveExternalDetailConflict(ExternalLocation[] locations,
			int externalConflictFlags) {

		Address myEntry = locations[MY].getExternalSpaceAddress();
		externalDetailConflicts.put(myEntry, externalConflictFlags);
	}

	/**
	 *
	 * @param entry
	 * @param type (FUNC_RETURN_TYPE, FUNC_RETURN_ADDRESS_OFFSET,
	 * FUNC_PARAMETER_OFFSET, FUNC_LOCAL_SIZE, FUNC_STACK_PURGE_SIZE, FUNC_NAME, FUNC_INLINE,
	 * FUNC_NO_RETURN, FUNC_CALLING_CONVENTION)
	 * @param latestMyChanges
	 * @param originalLatestChanges
	 * @param originalMyChanges
	 * @param monitor
	 * @return
	 * @throws CancelledException
	 */
	private int determineBasicExternalConflict(ExternalLocation[] locations, int type,
			int latestMyChanges, int originalLatestChanges, int originalMyChanges,
			TaskMonitor monitor) throws CancelledException {
		if (((latestMyChanges & type) != 0) && ((originalMyChanges & type) != 0)) {
			// Latest and My differ, and My changed the Original.
			// My changed this basic type part of the external.
			if ((originalLatestChanges & type) != 0) {
				// Latest Changed this type of detail too.
				return type;
			}
			// AutoMerge
			mergeExternalDetail(type, locations[RESULT], locations[MY], monitor);
		}
		return 0; // No conflict
	}

	private void mergeExternalDetail(int type, ExternalLocation resultExternalLocation,
			ExternalLocation fromExternalLocation, TaskMonitor monitor) throws CancelledException {

		monitor.checkCancelled();

		// See if both changed to same value.
		switch (type) {
			case EXTERNAL_NAMESPACE:
				replaceNamespace(resultExternalLocation, fromExternalLocation, monitor);
				return;
			case EXTERNAL_LABEL:
				// TODO: The order of detail merge could be problematic since we can't set 
				// default label if EXTERNAL_ADDRESS is currently null.  
				String fromLabel = fromExternalLocation.getLabel();
				SourceType resultSource = resultExternalLocation.getSource();
				SourceType fromSource = fromExternalLocation.getSource();
				// If both are DEFAULT then no name to merge.
				if (resultSource == SourceType.DEFAULT && fromSource == SourceType.DEFAULT) {
					return; // Just return since default names may not match each other by their text.
				}
				try {
					resultExternalLocation.getSymbol().setName(fromLabel, fromSource);
				}
				catch (DuplicateNameException e) {
					throw new AssertException("Can't happen now that duplicates are allowed");
				}
				catch (InvalidInputException e) {
					Msg.error(this,
						"Couldn't merge external location name '" + fromLabel + "'. " + e);
					return;
				}
				return;
			case EXTERNAL_ADDRESS:
				// TODO: The order of detail merge could be problematic since we can't set 
				// null address if EXTERNAL_LABEL is currently null/default.
				Address address = fromExternalLocation.getAddress();
				try {
					resultExternalLocation.setAddress(address);
				}
				catch (InvalidInputException e) {
					String message = "Couldn't set memory address " +
						(address != null ? address.toString(true) : "(null)") + " for external '" +
						resultExternalLocation.getLabel() + "'.";
					errorBuf.append(message);
					Msg.error(this, message, e);
				}
				return;
			case EXTERNAL_DATA_TYPE:
				replaceExternalDataType(resultExternalLocation, fromExternalLocation, monitor);
				return;
//				// Source Type is handled by the Label.
//			case EXTERNAL_SOURCE_TYPE:
//				SourceType source = fromExternalLocation.getSource();
//				try {
//					toExternalLocation.setLocation(toExternalLocation.getLabel(),
//						toExternalLocation.getAddress(), source);
//				}
//				catch (DuplicateNameException e) {
//					e.printStackTrace();
//				}
//				catch (InvalidInputException e) {
//					e.printStackTrace();
//				}
//				return;
		}
	}

	private DataType getResultDataType(ExternalLocation fromExternalLocation) {
		if (fromExternalLocation == null) {
			return null;
		}
		DataType fromDataType = fromExternalLocation.getDataType();
		if (fromDataType == null || fromDataType == DataType.DEFAULT) {
			return fromDataType;
		}
		DataTypeManager latestDTM = programs[LATEST].getDataTypeManager();
		DataTypeManager myDTM = programs[MY].getDataTypeManager();
		DataTypeManager originalDTM = programs[ORIGINAL].getDataTypeManager();
		DataTypeManager fromDataTypeManager = fromDataType.getDataTypeManager();
		if (fromDataTypeManager == latestDTM) {
			long latestID = latestDTM.getID(fromDataType);
			DataType latestResultDT = getResultDataType(latestID, programs[LATEST]);
			if (latestResultDT != null) {
				return latestResultDT;
			}
		}
		if (fromDataTypeManager == myDTM) {
			long myID = myDTM.getID(fromDataType);
			DataType myResultDT = getResultDataType(myID, programs[MY]);
			if (myResultDT != null) {
				return myResultDT;
			}
		}
		if (fromDataTypeManager == originalDTM) {
			long originalID = originalDTM.getID(fromDataType);
			DataType originalResultDT = getResultDataType(originalID, programs[ORIGINAL]);
			if (originalResultDT != null) {
				return originalResultDT;
			}
		}
		return fromDataType;
	}

	private DataType getResultDataType(DataType fromDataType) {
		if (fromDataType == null) {
			return null;
		}
		if (fromDataType == DataType.DEFAULT) {
			return fromDataType;
		}
		DataTypeManager latestDTM = programs[LATEST].getDataTypeManager();
		DataTypeManager myDTM = programs[MY].getDataTypeManager();
		DataTypeManager originalDTM = programs[ORIGINAL].getDataTypeManager();
		DataTypeManager fromDataTypeManager = fromDataType.getDataTypeManager();
		if (fromDataTypeManager == latestDTM) {
			long latestID = latestDTM.getID(fromDataType);
			DataType latestResultDT = getResultDataType(latestID, programs[LATEST]);
			if (latestResultDT != null) {
				return latestResultDT;
			}
		}
		if (fromDataTypeManager == myDTM) {
			long myID = myDTM.getID(fromDataType);
			DataType myResultDT = getResultDataType(myID, programs[MY]);
			if (myResultDT != null) {
				return myResultDT;
			}
		}
		if (fromDataTypeManager == originalDTM) {
			long originalID = originalDTM.getID(fromDataType);
			DataType originalResultDT = getResultDataType(originalID, programs[ORIGINAL]);
			if (originalResultDT != null) {
				return originalResultDT;
			}
		}
		return fromDataType;
	}

	private int getBasicExternalDiffs(ExternalLocation externalLocation1,
			ExternalLocation externalLocation2) {

		int conflicts = 0; // No conflict
		if ((externalLocation1 == null) || (externalLocation2 == null)) {
			throw new IllegalArgumentException("External location can't be null.");
		}

		// Neither is null so lets compare them.

		Namespace namespace1 = externalLocation1.getParentNameSpace();
		String label1 = externalLocation1.getLabel();
		DataType dataType1 = getResultDataType(externalLocation1);
		Address address1 = externalLocation1.getAddress();
		SourceType sourceType1 = externalLocation1.getSource();
		Symbol symbol1 = externalLocation1.getSymbol();
		SymbolType symbolType1 = symbol1.getSymbolType();
		Function function1 = externalLocation1.getFunction();

		Namespace namespace2 = externalLocation2.getParentNameSpace();
		String label2 = externalLocation2.getLabel();
		DataType dataType2 = getResultDataType(externalLocation2);
		Address address2 = externalLocation2.getAddress();
		SourceType sourceType2 = externalLocation2.getSource();
		Symbol symbol2 = externalLocation2.getSymbol();
		SymbolType symbolType2 = symbol2.getSymbolType();
		Function function2 = externalLocation2.getFunction();

		// TODO: Does not consider original imported name

		if (!equivalentNamespaces(namespace1, namespace2)) {
			conflicts |= EXTERNAL_NAMESPACE;
		}
		if (!isSameLabel(label1, label2, sourceType1, sourceType2)) {
			conflicts |= EXTERNAL_LABEL;
		}
		if (!SystemUtilities.isEqual(address1, address2)) {
			conflicts |= EXTERNAL_ADDRESS;
		}
//		if (!sourceType1.equals(sourceType2)) {
//			conflicts |= EXTERNAL_SOURCE_TYPE;
//		}
		if (!isSameDataType(dataType1, dataType2)) {
			conflicts |= EXTERNAL_DATA_TYPE;
		}
		if (symbolType1 != symbolType2) {
			conflicts |= EXTERNAL_SYMBOL_TYPE;
		}
		if (!ProgramDiff.equivalentFunctions(function1, function2)) {
			conflicts |= EXTERNAL_FUNCTION;
		}

		return conflicts;
	}

	private boolean isSameDataType(DataType dt1, DataType dt2) {
		if (dt1 == dt2) {
			return true;
		}
		if (dt1 == null) {
			return (dt2 == null);
		}
		if (dt2 == null) {
			return false;
		}
		return dt1.isEquivalent(dt2); // Should this use isEquivalent() or equals()?
	}

	private boolean isSameLabel(String label1, String label2, SourceType sourceType1,
			SourceType sourceType2) {
		if (sourceType1 == SourceType.DEFAULT && sourceType2 == SourceType.DEFAULT) {
			return true;
		}
		return SystemUtilities.isEqual(label1, label2);
	}

	private boolean hasExternalAddConflicts(ExternalLocation externalLocation1,
			ExternalLocation externalLocation2) {

		if ((externalLocation1 == null) || (externalLocation2 == null)) {
			throw new IllegalArgumentException("External location can't be null.");
		}

		// Neither is null so lets compare them.

		Namespace namespace1 = externalLocation1.getParentNameSpace();
		String label1 = externalLocation1.getLabel();
		boolean label1IsDefault = hasDefaultExternalName(externalLocation1);
		DataType dataType1 = getResultDataType(externalLocation1);
		boolean dataType1IsDefined = hasDefinedDataType(externalLocation1);
		Address address1 = externalLocation1.getAddress();
//		SourceType sourceType1 = externalLocation1.getSource();
//		Symbol symbol1 = externalLocation1.getSymbol();
//		SymbolType symbolType1 = symbol1.getSymbolType();
		Function function1 = externalLocation1.getFunction();
		String originalName1 = externalLocation1.getOriginalImportedName();
		boolean external1IsFunction = function1 != null;

		Namespace namespace2 = externalLocation2.getParentNameSpace();
		String label2 = externalLocation2.getLabel();
		boolean label2IsDefault = hasDefaultExternalName(externalLocation2);
		DataType dataType2 = getResultDataType(externalLocation2);
		boolean dataType2IsDefined = hasDefinedDataType(externalLocation2);
		Address address2 = externalLocation2.getAddress();
//		SourceType sourceType2 = externalLocation2.getSource();
//		Symbol symbol2 = externalLocation2.getSymbol();
//		SymbolType symbolType2 = symbol2.getSymbolType();
		String originalName2 = externalLocation2.getOriginalImportedName();
		Function function2 = externalLocation2.getFunction();
		boolean external2IsFunction = function2 != null;

		if (!equivalentNamespaces(namespace1, namespace2)) {
			return true;
		}
		if (!label1IsDefault && !label2IsDefault &&
			isNameConflict(label1, label2, originalName1, originalName2)) {
			return true;
		}
//		if (!SystemUtilities.isEqual(sourceType1, sourceType2)) {
//			return true;
//		}
		if ((address1 != null) && (address2 != null) &&
			!SystemUtilities.isEqual(address1, address2)) {
			return true;
		}
		if (dataType1IsDefined && dataType2IsDefined && !isSameDataType(dataType1, dataType2)) {
			return true;
		}
		if ((dataType1IsDefined && external2IsFunction) ||
			(dataType2IsDefined && external1IsFunction)) {
			return true;
		}
		if (external1IsFunction && external2IsFunction &&
			hasExternalFunctionAddConflicts(function1, function2)) {
			return true;
		}

		return false;
	}

	private boolean isNameConflict(String name1, String name2, String originalName1,
			String originalName2) {
		boolean hasOriginalName1 = originalName1 != null;
		boolean hasOriginalName2 = originalName2 != null;

		if (hasOriginalName1 && hasOriginalName2) {
			if (!originalName1.equals(originalName2)) {
				return true;
			}
			if (!name1.equals(name2)) {
				return true;
			}
		}
		else if (hasOriginalName1) {
			if (!name2.equals(name1) && !name2.equals(originalName1)) {
				return true;
			}
		}
		else if (hasOriginalName2) {
			if (!name1.equals(name2) && !name1.equals(originalName2)) {
				return true;
			}
		}
		else if (!name1.equals(name2)) {
			return true;
		}
		return false;
	}

	private boolean hasExternalFunctionAddConflicts(Function function1, Function function2) {
		return !ProgramDiff.equivalentFunctions(function1, function2, true);
	}

	private boolean hasDefaultExternalName(ExternalLocation externalLocation) {
		Symbol symbol = externalLocation.getSymbol();
		SourceType source = symbol.getSource();
		return source == SourceType.DEFAULT;
	}

	private boolean hasDefinedDataType(ExternalLocation externalLocation) {
		DataType dataType = externalLocation.getDataType();
		return (dataType != null && dataType != DataType.DEFAULT);
	}

	private boolean equivalentNamespaces(Namespace namespace1, Namespace namespace2) {
		if (namespace1 == null) {
			return (namespace2 == null);
		}
		if (namespace1.getID() == Namespace.GLOBAL_NAMESPACE_ID) {
			return (namespace2.getID() == Namespace.GLOBAL_NAMESPACE_ID);
		}
		String name1 = namespace1.getName();
		String name2 = namespace2.getName();
		if (!SystemUtilities.isEqual(name1, name2)) {
			return false;
		}
		SymbolType symbolType1 = namespace1.getSymbol().getSymbolType();
		SymbolType symbolType2 = namespace2.getSymbol().getSymbolType();
		if (!SystemUtilities.isEqual(symbolType1, symbolType2)) {
			return false;
		}
		Namespace parent1 = namespace1.getParentNamespace();
		Namespace parent2 = namespace2.getParentNamespace();
		return equivalentNamespaces(parent1, parent2);
	}

	private boolean equivalentExternals(ExternalLocation externalLocation1,
			ExternalLocation externalLocation2) {
		if (externalLocation1 == null) {
			return (externalLocation2 == null);
		}
		else if (externalLocation2 == null) {
			return false;
		}

		// Neither is null so lets compare them.

		Namespace namespace1 = externalLocation1.getParentNameSpace();
		String label1 = externalLocation1.getLabel();
		DataType dataType1 = getResultDataType(externalLocation1);
		Address address1 = externalLocation1.getAddress();
//		SourceType sourceType1 = externalLocation1.getSource();
		Symbol symbol1 = externalLocation1.getSymbol();
		SymbolType symbolType1 = symbol1.getSymbolType();
		Function function1 = externalLocation1.getFunction();

		Namespace namespace2 = externalLocation2.getParentNameSpace();
		String label2 = externalLocation2.getLabel();
		DataType dataType2 = getResultDataType(externalLocation2);
		Address address2 = externalLocation2.getAddress();
//		SourceType sourceType2 = externalLocation2.getSource();
		Symbol symbol2 = externalLocation2.getSymbol();
		SymbolType symbolType2 = symbol2.getSymbolType();
		Function function2 = externalLocation2.getFunction();

		if (!equivalentNamespaces(namespace1, namespace2)) {
			return false;
		}
		if (!label1.equals(label2)) {
			return false;
		}
		if (!isSameDataType(dataType1, dataType2)) {
			return false;
		}
		if (!SystemUtilities.isEqual(address1, address2)) {
			return false;
		}
//		if (!sourceType1.equals(sourceType2)) {
//			return false;
//		}
		if (symbolType1 != symbolType2) {
			return false;
		}
		if ((symbolType1 == SymbolType.FUNCTION) &&
			!ProgramDiff.equivalentFunctions(function1, function2)) {
			return false;
		}

		return true;
	}

	private void determineExternalRemoveConflicts(TaskMonitor monitor) throws CancelledException {
		monitor.checkCancelled();
		if (totalChanges <= 0) {
			return;
		}
		mergeManager.updateProgress((changeNum / totalChanges) * 100,
			"Finding conflicts for removed externals.");

		// Process Externals that were removed in LATEST
		Iterator<Long> latestIterator = latestRemovedOriginalIDs.iterator();
		while (latestIterator.hasNext()) {
			long originalID = latestIterator.next();
			long myID = resolveMyIDFromOriginalID(originalID);
			if (myRemovedOriginalIDs.contains(originalID)) {
				// MY removed it too.
				continue;
			}
			if (myModifiedIDs.contains(myID)) {
				// Conflict: MY changed it, but LATEST has removed it.
				removeConflictIDs.add(originalID);
			}

			mergeManager.updateProgress((++changeNum / totalChanges) * 100);
		}

		// Process Externals that were removed in MY
		Iterator<Long> myIterator = myRemovedOriginalIDs.iterator();
		while (myIterator.hasNext()) {
			long originalID = myIterator.next();
			long latestID = resolveLatestIDFromOriginalID(originalID);
			if (latestRemovedOriginalIDs.contains(originalID)) {
				// LATEST removed it too.
				continue;
			}
			if (latestModifiedIDs.contains(latestID)) {
				// Conflict: LATEST changed it, but MY has removed it.
				removeConflictIDs.add(originalID);
			}
			else {
				long resultID = getResultIDfromOriginalID(originalID);
				if (resultID != -1) {
					removeExternal(resultID);
				}
				originalResolvedSymbols.put(originalID, -1);
				latestResolvedSymbols.put(latestID, -1);
			}

			mergeManager.updateProgress((++changeNum / totalChanges) * 100);
		}
	}

	private void determineExternalChangeConflicts(TaskMonitor monitor) throws CancelledException {
		monitor.checkCancelled();
		if (totalChanges <= 0) {
			return;
		}
		mergeManager.updateProgress((changeNum / totalChanges) * 100,
			"Finding conflicts for changed externals.");

		// Process Externals that were changed in LATEST.
		processExternalsChangedInLatest(monitor);

		// Process Externals that were changed in MY.
		processExternalsChangedInMy(monitor);
	}

	private void processExternalsChangedInLatest(TaskMonitor monitor) throws CancelledException {
		Iterator<Long> latestIterator = latestModifiedIDs.iterator();
		while (latestIterator.hasNext()) {
			monitor.checkCancelled();
			long latestID = latestIterator.next();
			long originalID = resolveOriginalIDFromLatestID(latestID);
			long myID = resolveMyIDFromOriginalID(originalID);
			if (removeConflictIDs.contains(originalID)) {
				continue; // Already have a remove conflict on this.
			}
			if (myModifiedIDs.contains(myID)) {
				// Both modified it so need to autoMerge and determine Conflicts.
				Symbol latestSymbol = symbolTables[LATEST].getSymbol(latestID);
				Symbol mySymbol = symbolTables[MY].getSymbol(myID);
				Symbol originalSymbol = symbolTables[ORIGINAL].getSymbol(originalID);
				long resultID = getResultIDfromLatestID(latestID);
				Symbol resultSymbol = symbolTables[RESULT].getSymbol(resultID);

				ExternalLocation[] externalLocations = new ExternalLocation[4];
				externalLocations[LATEST] =
					externalManagers[LATEST].getExternalLocation(latestSymbol);
				externalLocations[MY] = externalManagers[MY].getExternalLocation(mySymbol);
				externalLocations[ORIGINAL] =
					externalManagers[ORIGINAL].getExternalLocation(originalSymbol);
				externalLocations[RESULT] =
					externalManagers[RESULT].getExternalLocation(resultSymbol);

				myResolvedSymbols.put(myID, resultID);

				mergeChangesAndDetermineConflicts(externalLocations, monitor);
			}
			// Otherwise, MY didn't change it and RESULT should already have the change from LATEST.

			mergeManager.updateProgress((++changeNum / totalChanges) * 100);
		} // Done checking LATEST changes.
	}

	private void processExternalsChangedInMy(TaskMonitor monitor) throws CancelledException {
		Iterator<Long> myIterator = myModifiedIDs.iterator();
		while (myIterator.hasNext()) {
			monitor.checkCancelled();
			long myID = myIterator.next();
			long originalID = resolveOriginalIDFromMyID(myID);
			long latestID = resolveLatestIDFromOriginalID(originalID);
			long resultID = getResultIDfromLatestID(latestID);

			if (latestModifiedIDs.contains(latestID)) {
				continue; // Already processed this above in the LATEST changes loop.
			}
			if (removeConflictIDs.contains(originalID)) {
				continue; // Already have a remove conflict on this.
			}
			// Only MY modified it so need to autoMerge it.
			Symbol myExternalSymbol = symbolTables[MY].getSymbol(myID);
			ExternalLocation myExternalLocation =
				externalManagers[MY].getExternalLocation(myExternalSymbol);
			Symbol resultExternalSymbol = symbolTables[RESULT].getSymbol(resultID);
			ExternalLocation resultExternalLocation =
				externalManagers[RESULT].getExternalLocation(resultExternalSymbol);

			myAddressTranslator.setPair(resultExternalSymbol.getAddress(),
				myExternalSymbol.getAddress());

			try {
				resultExternalLocation = replaceExternalLocation(resultExternalLocation,
					myExternalLocation, getMergeMy(), monitor);
				myResolvedSymbols.put(myID, resultID);
				originalResolvedSymbols.put(originalID, resultID);
			}
			catch (DuplicateNameException e) {
				Msg.showError(this, mergeManager.getMergeTool().getToolFrame(),
					"Error Merging External Location", e.getMessage());
			}
			catch (InvalidInputException e) {
				Msg.showError(this, mergeManager.getMergeTool().getToolFrame(),
					"Error Merging External Location", e.getMessage());
			}

			mergeManager.updateProgress((++changeNum / totalChanges) * 100);
		} // Done checking MY changes.
	}

	private long getResultIDfromLatestID(long latestID) {
		long resultID;
		try {
			resultID = latestResolvedSymbols.get(latestID);
		}
		catch (NoValueException e) {
			resultID = latestID;
		}
		return resultID;
	}

	private long getResultIDfromOriginalID(long originalID) {
		long resultID;
		try {
			resultID = originalResolvedSymbols.get(originalID);
		}
		catch (NoValueException e) {
			resultID = originalID;
		}
		return resultID;
	}

	private void mergeChangesAndDetermineConflicts(ExternalLocation[] externalLocations,
			TaskMonitor monitor) throws CancelledException {

		if (!equivalentExternals(externalLocations[LATEST], externalLocations[MY])) {
			// Both Latest and My changed it but they don't match.
			// See what pieces can be auto-merged and which are conflicts.

			// Set up address translator information for any ProgramMerge method calls.
			updateAddressTranslators(externalLocations);

			int latestMyChanges =
				getBasicExternalDiffs(externalLocations[LATEST], externalLocations[MY]);
			if (latestMyChanges == 0) {
				return; // Already the same.
			}
			int originalLatestChanges =
				getBasicExternalDiffs(externalLocations[ORIGINAL], externalLocations[LATEST]);
			int originalMyChanges =
				getBasicExternalDiffs(externalLocations[ORIGINAL], externalLocations[MY]);

			int detailConflictFlags = 0;
			// Check and auto-merge the namespace.
			detailConflictFlags |=
				determineBasicExternalConflict(externalLocations, EXTERNAL_NAMESPACE,
					latestMyChanges, originalLatestChanges, originalMyChanges, monitor);

			// Check and auto-merge the name and source type.
			detailConflictFlags |= determineBasicExternalConflict(externalLocations, EXTERNAL_LABEL,
				latestMyChanges, originalLatestChanges, originalMyChanges, monitor);

			// Source Type is handled along with Label.
//			detailConflictFlags |=
//				determineBasicExternalConflict(externalLocations, EXTERNAL_SOURCE_TYPE,
//					latestMyChanges, originalLatestChanges, originalMyChanges, monitor);

			// Check and auto-merge memory address.
			detailConflictFlags |=
				determineBasicExternalConflict(externalLocations, EXTERNAL_ADDRESS, latestMyChanges,
					originalLatestChanges, originalMyChanges, monitor);

			if (detailConflictFlags != 0) {
				saveExternalDetailConflict(externalLocations, detailConflictFlags);
			}

			// Check Data Type vs Function
			determineExternalDataTypeConflict(externalLocations, latestMyChanges,
				originalLatestChanges, originalMyChanges, monitor);

			// Check Function Changes
			determineExternalFunctionConflict(externalLocations, latestMyChanges,
				originalLatestChanges, originalMyChanges, monitor);

		}
		// Otherwise Latest and My are equivalent.
	}

	private void determineExternalDataTypeConflict(ExternalLocation[] externalLocations,
			int latestMyChanges, int originalLatestChanges, int originalMyChanges,
			TaskMonitor monitor) throws CancelledException {

		Address myExternalAddress = externalLocations[MY].getExternalSpaceAddress();

		DataType latestDataType = getResultDataType(externalLocations[LATEST]);
		DataType myDataType = getResultDataType(externalLocations[MY]);
		boolean latestHasDataType =
			(latestDataType != null) && (latestDataType != DataType.DEFAULT);
		boolean myHasDataType = (myDataType != null) && (myDataType != DataType.DEFAULT);
		boolean differentDataTypes = (latestMyChanges & EXTERNAL_DATA_TYPE) != 0;
		boolean latestChangedDataType = (originalLatestChanges & EXTERNAL_DATA_TYPE) != 0;
		boolean myChangedDataType = (originalMyChanges & EXTERNAL_DATA_TYPE) != 0;
		boolean latestIsFunction = externalLocations[LATEST].isFunction();
		boolean myIsFunction = externalLocations[MY].isFunction();
		boolean latestChangedFunction = (originalLatestChanges & EXTERNAL_FUNCTION) != 0;
		boolean myChangedFunction = (originalMyChanges & EXTERNAL_FUNCTION) != 0;
		// If the data types are different, then did a change to one conflict with a
		// data type or function change to the other?
		if (differentDataTypes) {
			if (myChangedDataType) {
				if (latestChangedDataType) {
					// Both changed the data type differently.
					saveExternalDataTypeConflict(myExternalAddress);
				}
				else if (myHasDataType && latestChangedFunction && latestIsFunction) {
					// MY Data Type conflicts with LATEST function.
					saveExternalFunctionVersusDataTypeConflict(myExternalAddress);
				}
				else {
					// Auto Merge My data type change.
					replaceExternalDataType(externalLocations[RESULT], externalLocations[MY],
						monitor);
				}
			}
			else if (latestChangedDataType) {
				if (myChangedDataType) {
					// Can't get here. This CONFLICT is handled by "if (myChangedDataType)" above.
					throw new AssertException("Shouldn't be here!");
				}
				else if (latestHasDataType && myChangedFunction && myIsFunction) {
					// LATEST data type conflicts with MY function.
					saveExternalFunctionVersusDataTypeConflict(myExternalAddress);
				}
				// Otherwise, RESULT should already have the LATEST data type.
			}
		}
	}

	private void mergeExternalDataType(ExternalLocation[] externalLocations,
			int chosenConflictOption, TaskMonitor monitor) throws CancelledException {

		ExternalLocation chosenExternalLocation;
		if ((chosenConflictOption & KEEP_ORIGINAL) != 0) {
//			chosenExternalLocation = externalLocations[ORIGINAL];
			Msg.showError(this, mergeManager.getMergeTool().getToolFrame(),
				"Error Merging External Location",
				"Can't currently merge external data type from ORIGINAL program." +
					((externalLocations[ORIGINAL] != null)
							? (" ORIGINAL external was " + externalLocations[ORIGINAL].getLabel() +
								".")
							: ""));
			return;
		}
		else if ((chosenConflictOption & KEEP_LATEST) != 0) {
			chosenExternalLocation = externalLocations[LATEST];
		}
		else if ((chosenConflictOption & KEEP_MY) != 0) {
			chosenExternalLocation = externalLocations[MY];
		}
		else {
//			chosenExternalLocation = null;
			Msg.showError(this, mergeManager.getMergeTool().getToolFrame(),
				"Error Merging External Location",
				"Can only merge external data type from LATEST or MY program." +
					((externalLocations[RESULT] != null)
							? (" RESULT external was " + externalLocations[RESULT].getLabel() + ".")
							: ""));
			return;
		}
		replaceExternalDataType(externalLocations[RESULT], chosenExternalLocation, monitor);
	}

	/**
	 * <CODE>replaceExternalDataType</CODE> replaces the data type of the
	 * external label in program1 with the data type of the external label in program2
	 * at the specified external space address.
	 * @param resultExternalLocation
	 * @param fromExternalLocation
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 * @throws CancelledException
	 */
	public void replaceExternalDataType(ExternalLocation resultExternalLocation,
			ExternalLocation fromExternalLocation, TaskMonitor monitor) throws CancelledException {
		monitor.checkCancelled();
		if (fromExternalLocation != null && resultExternalLocation != null) {
			DataType fromDataTypeForResult = getResultDataType(fromExternalLocation);
			DataType resultDataType = resultExternalLocation.getDataType();
			if (isSameDataType(fromDataTypeForResult, resultDataType)) {
				return; // Already the same.
			}
			resultExternalLocation.setDataType(fromDataTypeForResult);
		}
	}

	private void saveExternalDataTypeConflict(Address myExternalAddress) {
		externalDataTypeConflicts.add(myExternalAddress);
	}

	private void saveExternalFunctionVersusDataTypeConflict(Address myExternalAddress) {
		externalFunctionVersusDataTypeConflicts.add(myExternalAddress);
	}

	private void saveExternalRemoveFunctionConflict(long originalID) {
		removeFunctionConflictIDs.add(originalID);
	}

	private void determineExternalFunctionConflict(ExternalLocation[] externalLocations,
			int latestMyChanges, int originalLatestChanges, int originalMyChanges,
			TaskMonitor monitor) throws CancelledException {

		// Don't look for function diffs if there is a function vs data type conflict?
		Address myExternalAddress = externalLocations[MY].getExternalSpaceAddress();
		if (externalFunctionVersusDataTypeConflicts.contains(myExternalAddress)) {
			return; // Function Vs Data Type conflict is already handling this.
		}

		boolean latestIsFunction = externalLocations[LATEST].isFunction();
		boolean myIsFunction = externalLocations[MY].isFunction();

		boolean latestChangedFunction = (originalLatestChanges & EXTERNAL_FUNCTION) != 0;
		boolean myChangedFunction = (originalMyChanges & EXTERNAL_FUNCTION) != 0;

		if (!latestIsFunction && !myIsFunction) {
			return;
		}

		// Check for function change conflict or auto-merge function change.
		boolean differentFunctions = (latestMyChanges & EXTERNAL_FUNCTION) != 0;
		// If the data types are different, then did a change to one conflict with a
		// data type or function change to the other?
		if (differentFunctions) {
			if (myChangedFunction) {
				if (latestChangedFunction) {
					determineDetailedFunctionConflicts(externalLocations, monitor);
				}
				else {
					// Auto Merge MY external function changes.
					replaceFunction(externalLocations[RESULT], externalLocations[MY], getMergeMy(),
						monitor);
				}
			}
			// Otherwise only LATEST changed the function and it is already in the RESULT.
		}
		// Otherwise functions are already the same so do nothing.
	}

	private void determineDetailedFunctionConflicts(ExternalLocation[] externalLocations,
			TaskMonitor monitor) throws CancelledException {

		Function[] functions = new Function[4];
		functions[RESULT] = externalLocations[RESULT].getFunction();
		functions[LATEST] = externalLocations[LATEST].getFunction();
		functions[MY] = externalLocations[MY].getFunction();
		functions[ORIGINAL] =
			(externalLocations[ORIGINAL] != null) ? externalLocations[ORIGINAL].getFunction()
					: null;
		boolean noLatestFunction = (functions[LATEST] == null);
		boolean noMyFunction = (functions[MY] == null);
		boolean noOriginalFunction = (functions[ORIGINAL] == null);

		// If both removed it then the function should already be auto-merged.
		if (noLatestFunction && noMyFunction) {
			throw new AssertException("Shouldn't be here! Something is wrong.");
		}

		// If one removed it and one changed it, then save a remove function conflict.
		if (!noOriginalFunction && (noLatestFunction != noMyFunction)) {
			long originalID = externalLocations[ORIGINAL].getSymbol().getID();
			saveExternalRemoveFunctionConflict(originalID);
			return;
		}

		// Determine function conflicts and auto-merge changes that aren't in conflict.
		determineFunctionConflicts(functions, true, monitor);

		// If only one added then the function should already be auto-merged.
		if (noOriginalFunction && (noLatestFunction || noMyFunction)) {
			throw new AssertException(
				"Shouldn't be here! It looks like only Latest or My added the function.");
		}
	}

	private void determineExternalAddConflicts(TaskMonitor monitor) throws CancelledException {
		monitor.checkCancelled();
		if (totalChanges <= 0) {
			return;
		}
		mergeManager.updateProgress((changeNum / totalChanges) * 100,
			"Finding conflicts for added externals.");

		// LATEST adds are already in RESULT.
		changeNum += latestAddIDs.size();
		mergeManager.updateProgress((changeNum / totalChanges) * 100);

		// MY adds may conflict with LATEST adds that are already in RESULT.
		Iterator<Long> myIterator = myAddIDs.iterator();
		while (myIterator.hasNext()) {
			monitor.checkCancelled();
			long myID = myIterator.next();
			Symbol mySymbol = symbolTables[MY].getSymbol(myID);
			// Non-primary symbols are "original" symbols and we don't need to match these.
			if (!mySymbol.isPrimary()) {
				continue;
			}
			ExternalLocation myExternalLocation =
				externalManagers[MY].getExternalLocation(mySymbol);
			if (myExternalLocation == null) {
				throw new AssertException("Why don't we have an external location?");
			}
			// Get the external symbol in LATEST that we think most likely matches MY external.
			// Only try to match it with externals that were also added in LATEST.
			Symbol latestSymbol = SimpleDiffUtility.getMatchingExternalSymbol(programs[MY],
				mySymbol, programs[LATEST], false, latestAddIDs);
			ExternalLocation latestExternalLocation = null;
			if (latestSymbol != null) {
				// We have a possible matching external from LATEST.
				SymbolType symbolType = latestSymbol.getSymbolType();
				if (symbolType == SymbolType.LABEL || symbolType == SymbolType.FUNCTION) {
					latestExternalLocation =
						externalManagers[LATEST].getExternalLocation(latestSymbol);
				}
			}
			if (latestExternalLocation == null) {
				// Couldn't find an external in LATEST that we think matches this one in MY.
				// So just add this one and give it a conflict name if necessary.
				try {
					ExternalLocation resultExternalLocation =
						addExternal(myExternalLocation, monitor);

					ExternalLocation[] externalLocations = new ExternalLocation[] {
						resultExternalLocation, latestExternalLocation, myExternalLocation, null };
					adjustIDMapsForAdd(externalLocations, resultExternalLocation, MY);
				}
				catch (DuplicateNameException e) {
					Msg.error(this, "Couldn't add external '" +
						myExternalLocation.getSymbol().getName(true) + ",. " + e.getMessage());
				}
				catch (InvalidInputException e) {
					Msg.error(this, "Couldn't add external '" +
						myExternalLocation.getSymbol().getName(true) + ",. " + e.getMessage());
				}
				continue;
			}

			// Check the externals for add conflicts. If there are any then present them with a
			// choice between Keep Latest, Keep My, Keep Both, or Merge Together.
			boolean hasExternalAddConflicts =
				hasExternalAddConflicts(latestExternalLocation, myExternalLocation);
			if (hasExternalAddConflicts) {
				// Check to see if this is a new external function versus a new external data label.
				if (isAddConflictSpecialFunctionVsData(latestExternalLocation, myExternalLocation,
					monitor)) {
					// Only give the latest vs my choices. Don't allow KeepBoth or MergeBoth.
					saveExternalFunctionVersusDataTypeConflict(
						myExternalLocation.getExternalSpaceAddress());
					continue;
				}
				saveExternalAddConflict(latestExternalLocation, myExternalLocation, monitor);
				continue;
			}

			// Otherwise, merge MY and RESULT (originally matched LATEST).
			mergeAddsAndDetermineConflicts(latestExternalLocation, myExternalLocation, monitor);

			mergeManager.updateProgress((++changeNum / totalChanges) * 100);
		}
	}

	/**
	 * If there is an external add conflict, but it is between a new external function versus a
	 * new external data label, we don't want to give the user the KeepBoth or MergeBoth options.
	 * @param latestExternalLocation the external location in the Latest program
	 * @param myExternalLocation the external location in the My program
	 * @param monitor a status monitor for feedback and cancelling.
	 * @return true if this is an external function versus external data label.
	 */
	private boolean isAddConflictSpecialFunctionVsData(ExternalLocation latestExternalLocation,
			ExternalLocation myExternalLocation, TaskMonitor monitor) {

		long myExternalID = myExternalLocation.getSymbol().getID();
		long latestExternalID = latestExternalLocation.getSymbol().getID();
		long resultExternalID = getResultIDfromLatestID(latestExternalID);

		Symbol latestSymbol = symbolTables[LATEST].getSymbol(latestExternalID);
		Symbol mySymbol = symbolTables[MY].getSymbol(myExternalID);
		Symbol resultSymbol = symbolTables[RESULT].getSymbol(resultExternalID);
		ExternalLocation[] externalLocations = new ExternalLocation[4];
		externalLocations[LATEST] = externalManagers[LATEST].getExternalLocation(latestSymbol);
		externalLocations[MY] = externalManagers[MY].getExternalLocation(mySymbol);
		externalLocations[ORIGINAL] = null;
		externalLocations[RESULT] = externalManagers[RESULT].getExternalLocation(resultSymbol);

		String latestName = getExternalName(externalLocations, LATEST, true);
		String myName = getExternalName(externalLocations, MY, true);
		boolean latestIsFunction = externalLocations[LATEST].isFunction();
		boolean myIsFunction = externalLocations[MY].isFunction();
		Address latestAddress = externalLocations[LATEST].getAddress();
		Address myAddress = externalLocations[MY].getAddress();
		boolean hasAddresses = latestAddress != null && myAddress != null;
		boolean namesMatch = SystemUtilities.isEqual(latestName, myName);
		boolean addressesMatch = SystemUtilities.isEqual(latestAddress, myAddress);
		boolean typesDiffer = latestIsFunction != myIsFunction;

		return namesMatch && typesDiffer && hasAddresses && addressesMatch;
	}

	private void saveExternalAddConflict(ExternalLocation latestExternalLocation,
			ExternalLocation myExternalLocation, TaskMonitor monitor) {
		// save my added external ID and matching latest external ID in a hash map.
		long myID = myExternalLocation.getSymbol().getID();
		long latestID = latestExternalLocation.getSymbol().getID();
		externalAddConflicts.put(myID, latestID);
	}

	private void mergeAddsAndDetermineConflicts(ExternalLocation latestExternalLocation,
			ExternalLocation myExternalLocation, TaskMonitor monitor) throws CancelledException {

		if (!equivalentExternals(latestExternalLocation, myExternalLocation)) {
			// Latest and My don't match.
			// See what pieces can be auto-merged and which are conflicts.

			Namespace latestNamespace = latestExternalLocation.getParentNameSpace();
			String latestLabel = latestExternalLocation.getLabel();
			DataType latestDataType = getResultDataType(latestExternalLocation);
			Address latestAddress = latestExternalLocation.getAddress();
			String latestOriginalName = latestExternalLocation.getOriginalImportedName();
//			SourceType latestSourceType = latestExternalLocation.getSource();
			Function latestFunction = latestExternalLocation.getFunction();
			boolean latestExternalIsFunction = (latestFunction != null);

			Namespace myNamespace = myExternalLocation.getParentNameSpace();
			boolean myNamespaceIsDefault =
				(myNamespace.getSymbol().getSymbolType() == SymbolType.LIBRARY) &&
					(myNamespace.getName() == Library.UNKNOWN);
			String myLabel = myExternalLocation.getLabel();
			boolean myLabelIsDefault = hasDefaultExternalName(myExternalLocation);
			DataType myDataType = getResultDataType(myExternalLocation);
			boolean myDataTypeIsDefined = hasDefinedDataType(myExternalLocation);
			Address myAddress = myExternalLocation.getAddress();
			String myOriginalName = myExternalLocation.getOriginalImportedName();
//			SourceType mySourceType = myExternalLocation.getSource();
			Function myFunction = myExternalLocation.getFunction();
			boolean myExternalIsFunction = (myFunction != null);

			// Get the external in RESULT that is the same as in LATEST.
			Address resultExternalAddress =
				getResultSpaceAddressForLatestLocation(latestExternalLocation);
			Symbol resultSymbol = symbolTables[RESULT].getPrimarySymbol(resultExternalAddress);
			ExternalLocation resultExternalLocation =
				externalManagers[RESULT].getExternalLocation(resultSymbol);

			ExternalLocation originalLocation = null; // no original location. This is an add.
			ExternalLocation[] locations = new ExternalLocation[] { resultExternalLocation,
				latestExternalLocation, myExternalLocation, originalLocation };
			updateAddressTranslators(locations);

//			if (myOriginalName != null && latestOriginalName == null &&
//				myOriginalName.equals(latestLabel)) {
//				mergeExternalDetail(EXTERNAL_LABEL, resultExternalLocation, myExternalLocation,
//					monitor);
//			}

			if (!myNamespaceIsDefault && !equivalentNamespaces(latestNamespace, myNamespace)) {
				// Auto-merge MY namespace.
				mergeExternalDetail(EXTERNAL_NAMESPACE, resultExternalLocation, myExternalLocation,
					monitor);
			}

			if (!myLabelIsDefault && !SystemUtilities.isEqual(latestLabel, myLabel) &&
				!SystemUtilities.isEqual(latestOriginalName, myLabel)) {
				// Auto-merge MY label.
				mergeExternalDetail(EXTERNAL_LABEL, resultExternalLocation, myExternalLocation,
					monitor);
			}

			if ((myAddress != null) && !SystemUtilities.isEqual(latestAddress, myAddress)) {
				// Auto-merge MY memory address.
				mergeExternalDetail(EXTERNAL_ADDRESS, resultExternalLocation, myExternalLocation,
					monitor);
			}

			// Data Type vs Data type
			if (myDataTypeIsDefined && !isSameDataType(latestDataType, myDataType)) {
				// Auto-merge MY data type.
				replaceExternalDataType(resultExternalLocation, myExternalLocation, monitor);
			}
			// Function vs Function
			if (myExternalIsFunction && !latestExternalIsFunction) {
				// Auto-merge MY function.
				// Add the function to the external location.
				// Change the external Label into a function.
				Function resultFunction = resultExternalLocation.createFunction();
				getMergeMy().replaceExternalFunction(resultFunction, myFunction, monitor);
			}
		}
		// Otherwise Latest and My are equivalent.
	}

	private Address getResultSpaceAddressForLatestLocation(
			ExternalLocation latestExternalLocation) {
		long latestID = latestExternalLocation.getSymbol().getID();
		long resultID = getResultIDfromLatestID(latestID);
		Symbol resultSymbol = symbolTables[RESULT].getSymbol(resultID);
		ExternalLocation resultExternalLocation =
			externalManagers[RESULT].getExternalLocation(resultSymbol);
		if (resultExternalLocation != null) {
			return resultExternalLocation.getExternalSpaceAddress();
		}
		Address latestSpaceAddress = latestExternalLocation.getExternalSpaceAddress();
		return SimpleDiffUtility.getCompatibleAddress(programs[LATEST], latestSpaceAddress,
			programs[RESULT]);
	}

	private ExternalLocation addExternal(ExternalLocation myExternalLocation, TaskMonitor monitor)
			throws DuplicateNameException, InvalidInputException, CancelledException {

		ExternalLocation resultExternalLocation =
			addExternal(myExternalLocation, getMergeMy(), monitor);
		if ((resultExternalLocation != null) &&
			!resultExternalLocation.getLabel().equals(myExternalLocation.getLabel())) {
			renamedConflictIDs.add(resultExternalLocation.getSymbol().getID());
		}
		return resultExternalLocation;
	}

	private ExternalLocation addExternal(ExternalLocation externalLocation,
			ProgramMerge programMerge, TaskMonitor monitor) throws DuplicateNameException,
			InvalidInputException, CancelledException, UnsupportedOperationException {

		Address address = externalLocation.getAddress();

		Namespace resolvedNamespace = listingMergeManager.resolveNamespace(
			programMerge.getOriginProgram(), externalLocation.getParentNameSpace());

		Namespace namespace = resolvedNamespace;
		String name = externalLocation.getLabel();
		SourceType sourceType = externalLocation.getSource();

		String originalImportedName = externalLocation.getOriginalImportedName();
		if (originalImportedName != null) {
			namespace = NamespaceUtils.getLibrary(namespace);
			name = originalImportedName;
			sourceType = SourceType.IMPORTED;
		}

		ExternalLocation resultExternalLocation = null;
		// Add External Function

		if (externalLocation.isFunction()) {
			Function function = externalLocation.getFunction();
			if (function == null) {
				throw new AssertException("Uh Oh! Function symbol, but no function.");
			}

			// Add the function by creating a simple function.
			resultExternalLocation = externalManagers[RESULT].addExtFunction(namespace, name,
				address, sourceType, false);
			Function resultFunction = resultExternalLocation.getFunction();
			// Now change the simple function to become the one we actually want.
			programMerge.replaceExternalFunction(resultFunction, function, monitor);
		}
		// Add External Label
		else {
			resultExternalLocation = externalManagers[RESULT].addExtLocation(namespace, name,
				address, sourceType, false);

			// Set the data type to match MY.
			DataType dataType = getResultDataType(externalLocation);
			if (dataType != null && resultExternalLocation != null) {
				resultExternalLocation.setDataType(dataType);
			}
		}
		if (originalImportedName != null) {
			try {
				resultExternalLocation.getSymbol()
						.setNameAndNamespace(externalLocation.getLabel(), resolvedNamespace,
							externalLocation.getSource());
			}
			catch (CircularDependencyException e) {
				throw new AssertException(e);
			}
		}
		return resultExternalLocation;
	}

	/**
	 * Performs a manual merge of external program conflicts.
	 * @param chosenConflictOption ASK_USER means interactively resolve conflicts.
	 * JUnit testing also allows setting this to LATEST, MY, or ORIGINAL to force
	 * selection of a particular version change.
	 * @param monitor task monitor for informing the user of progress.
	 * @throws CancelledException if the user cancels the merge.
	 */
	public void mergeConflicts(final int chosenConflictOption,
			final ConflictInfoPanel listingConflictInfoPanel, final TaskMonitor monitor)
			throws CancelledException {

		// Create our own conflict info panel for the top of the conflict panel.
		conflictInfoPanel = new ExternalConflictInfoPanel();
		listingMergePanel.setTopComponent(conflictInfoPanel);

		monitor.setMessage("Resolving Externals conflicts");
		totalConflicts = removeConflictIDs.size() + externalDetailConflicts.size() +
			(int) externalDataTypeConflicts.getNumAddresses() +
			(int) externalFunctionVersusDataTypeConflicts.getNumAddresses() +
			removeFunctionConflictIDs.size() + (int) funcSet.getNumAddresses() +
			externalAddConflicts.size();
		monitor.initialize(totalConflicts);
		conflictIndex = 1;
		conflictInfoPanel.setConflictInfo(conflictIndex, totalConflicts);

		processExternalRemoveConflicts(chosenConflictOption, monitor);
		processExternalDetailConflicts(chosenConflictOption, monitor);
		processExternalDataTypeConflicts(chosenConflictOption, monitor);
		processExternalFunctionVsDataTypeConflicts(chosenConflictOption, monitor);
		processExternalFunctionRemoveConflicts(chosenConflictOption, monitor);
		processExternalFunctionDetailConflicts(chosenConflictOption, monitor);
		processExternalAddConflicts(chosenConflictOption, monitor);

		listingMergePanel.setTopComponent(listingConflictInfoPanel); // Restore the listing's own top component.

		// Remove any conflict panel from the screen.
		mergeManager.showComponent(null, null, null);

		infoBuf.append(getRenamedConflictsInfo());

		showResolveErrors(ERROR_TITLE);
		showResolveInfo(INFO_TITLE);

		// Write the resolve info back to the merger so Symbol and Reference mergers can use it.
		setResolveInformation();

		clearResolveInfo();
		cleanupConflictPanels();
		monitor.setMessage("Done resolving Externals conflicts.");
	}

	private void processExternalRemoveConflicts(final int chosenConflictOption,
			final TaskMonitor monitor) throws CancelledException {
		// Handle Remove Conflicts
		for (long originalExternalID : removeConflictIDs) {
			handleRemoveConflict(originalExternalID, chosenConflictOption, monitor);
			monitor.setProgress(conflictIndex++);
			conflictInfoPanel.setConflictInfo(conflictIndex, totalConflicts);
		}
	}

	private void processExternalDetailConflicts(final int chosenConflictOption,
			final TaskMonitor monitor) throws CancelledException {
		// Handle External Detail Conflicts
		Address[] keys =
			externalDetailConflicts.getKeys(new Address[externalDetailConflicts.size()]);
		for (Address myAddress : keys) {
			ExternalLocation[] externalLocations = getExternalLocationsForMyAddress(myAddress);
			handleExternalDetailsConflict(externalLocations, chosenConflictOption, monitor);
			monitor.setProgress(conflictIndex++);
			conflictInfoPanel.setConflictInfo(conflictIndex, totalConflicts);
		}
	}

	private void processExternalDataTypeConflicts(final int chosenConflictOption,
			final TaskMonitor monitor) throws CancelledException {
		// Handle External Data Type Conflicts
		AddressIterator dataTypeAddresses = externalDataTypeConflicts.getAddresses(true);
		while (dataTypeAddresses.hasNext()) {
			Address myAddress = dataTypeAddresses.next();
			ExternalLocation[] externalLocations = getExternalLocationsForMyAddress(myAddress);
			handleExternalDataTypeConflict(externalLocations, chosenConflictOption, monitor);
			monitor.setProgress(conflictIndex++);
			conflictInfoPanel.setConflictInfo(conflictIndex, totalConflicts);
		}
	}

	private void processExternalFunctionVsDataTypeConflicts(final int chosenConflictOption,
			final TaskMonitor monitor) throws CancelledException {
		// Handle External Function versus Data Type Conflicts
		AddressIterator functionVsDataTypeAddresses =
			externalFunctionVersusDataTypeConflicts.getAddresses(true);
		while (functionVsDataTypeAddresses.hasNext()) {
			Address myAddress = functionVsDataTypeAddresses.next();
			ExternalLocation[] externalLocations = getExternalLocationsForMyAddress(myAddress);
			handleExternalFunctionVersusDataTypeConflict(externalLocations, chosenConflictOption,
				monitor);
			monitor.setProgress(conflictIndex++);
			conflictInfoPanel.setConflictInfo(conflictIndex, totalConflicts);
		}
	}

	private void processExternalFunctionRemoveConflicts(final int chosenConflictOption,
			final TaskMonitor monitor) throws CancelledException {
		// Handle External Remove Function Conflicts
		for (Long originalID : removeFunctionConflictIDs) {
			ExternalLocation[] externalLocations = getExternalLocationsForOriginalID(originalID);
			handleExternalRemoveFunctionConflict(externalLocations, chosenConflictOption, monitor);
			monitor.setProgress(conflictIndex++);
			conflictInfoPanel.setConflictInfo(conflictIndex, totalConflicts);
		}
	}

	private void processExternalFunctionDetailConflicts(final int chosenConflictOption,
			final TaskMonitor monitor) throws CancelledException {
		// Handle Detailed Function Conflicts
		AddressIterator detailFunctionConflictAddresses = funcSet.getAddresses(true);
		while (detailFunctionConflictAddresses.hasNext()) {
			Address myEntryPoint = detailFunctionConflictAddresses.next();
			ExternalLocation[] externalLocations = getExternalLocationsForMyAddress(myEntryPoint);
			Function[] functions = getFunctions(externalLocations);
			handleExternalFunctionConflict(functions, myEntryPoint, chosenConflictOption,
				listingMergePanel, monitor);
			monitor.setProgress(conflictIndex++);
			conflictInfoPanel.setConflictInfo(conflictIndex, totalConflicts);
		}
	}

	private void processExternalAddConflicts(final int chosenConflictOption,
			final TaskMonitor monitor) throws CancelledException {
		// Handle Add Conflicts
		// These will ask the user KEEP_LATEST, KEEP_MY, KEEP_BOTH, or MERGE_BOTH.
		long[] addConflictIDs = externalAddConflicts.getKeys();
		for (long myExternalSymbolID : addConflictIDs) {
			try {
				long latestExternalSymbolID = externalAddConflicts.get(myExternalSymbolID);
				handleExternalAddConflict(latestExternalSymbolID, myExternalSymbolID,
					chosenConflictOption, monitor);
				monitor.setProgress(conflictIndex++);
				conflictInfoPanel.setConflictInfo(conflictIndex, totalConflicts);
			}
			catch (NoValueException e) {
				Msg.error(this,
					"Couldn't get merge conflict for external that was added. " + e.getMessage());
			}
		}
	}

	/**
	 * Puts the LongLongHashtables, that map the symbol IDs from LATEST, MY, and
	 * ORIGINAL programs to the RESULT program symbol IDs, into the Merge Manager.
	 */
	private void setResolveInformation() {
		if (mergeManager != null) {
			mergeManager.setResolveInformation(MergeConstants.RESOLVED_LATEST_SYMBOLS,
				latestResolvedSymbols);
			mergeManager.setResolveInformation(MergeConstants.RESOLVED_MY_SYMBOLS,
				myResolvedSymbols);
			mergeManager.setResolveInformation(MergeConstants.RESOLVED_ORIGINAL_SYMBOLS,
				originalResolvedSymbols);
		}
	}

	private void cleanupConflictPanels() {
		if (addConflictPanel != null) {
			mergeManager.removeComponent(addConflictPanel);
		}
	}

	private void handleExternalRemoveFunctionConflict(ExternalLocation[] externalLocations,
			int chosenConflictOption, TaskMonitor monitor) throws CancelledException {

		currentExternalConflictType = ExternalConflictType.EXTERNAL_FUNCTION_REMOVE_CONFLICT;
		updateExternalNameInfo(externalLocations, MY);
		boolean askUser =
			(externalFunctionRemovalChoice == ASK_USER) && (chosenConflictOption == ASK_USER);
		updateAddressTranslators(externalLocations);

		if (askUser && mergeManager != null) {
			VerticalChoicesPanel choicesPanel =
				createExternalRemoveFunctionConflictPanel(externalLocations, monitor);

			boolean useForAll = (removeChoice != ASK_USER);
			choicesPanel.setUseForAll(useForAll);
			choicesPanel.setConflictType("External Function Removal");

			setupConflictPanel(listingMergePanel, choicesPanel, externalLocations, monitor);
			monitor.checkCancelled();
		}
		else {
			// If we have a external function removal choice then a "Use For All" has already occurred.
			int optionToUse = (externalFunctionRemovalChoice == ASK_USER) ? chosenConflictOption
					: externalFunctionRemovalChoice;
			merge(externalLocations, optionToUse, monitor);
		}
	}

	private void handleExternalFunctionConflict(Function[] functions, Address myEntryPoint,
			int currentConflictOption, ListingMergePanel listingPanel, TaskMonitor monitor)
			throws CancelledException {

		boolean askUser = currentConflictOption == ListingMergeConstants.ASK_USER;
		updateAddressTranslators(functions);
		ExternalLocation[] externalLocations = getExternalLocationsForFunctions(functions);

		currentExternalConflictType = ExternalConflictType.FUNCTION_DETAILS_CONFLICT;
		if (funcConflicts.contains(myEntryPoint)) {

			int conflicts;
			try {
				conflicts = funcConflicts.get(myEntryPoint);
			}
			catch (NoValueException e) {
				String message = "Couldn't process function conflict for external '" +
					functions[MY].getName() + "'.";
				errorBuf.append(message);
				Msg.error(this, message, e);
				return;
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
						createFunctionConflictPanel(functions, monitor);

					boolean useForAll = (detailsChoice != ASK_USER);
					choicesPanel.setUseForAll(useForAll);
					choicesPanel.setConflictType("Function Detail");

					setupConflictPanel(listingPanel, choicesPanel, externalLocations, monitor);
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
				boolean skipParamChecks = variableStorageConflicts != null &&
					variableStorageConflicts.hasParameterConflict();

				if (skipParamChecks) {
					determineReturnConflict(functions, true, monitor);
				}
				else if (determineSignatureConflicts(functions, monitor)) {
					paramInfoConflicts = determineParameterInfoConflicts(functions, true, monitor);
					determineReturnConflict(functions, true, monitor);
				}

				localVarConflicts = determineLocalVariableInfoConflicts(functions, true,
					variableStorageConflicts, monitor);

				// update function conflicts. funcConflicts may have been populated by the "determine" method call above.
				try {
					conflicts = funcConflicts.get(myEntryPoint);
				}
				catch (NoValueException e) {
					String message = "Couldn't process function conflict for external '" +
						functions[MY].getName() + "'.";
					errorBuf.append(message);
					Msg.error(this, message, e);
					return;
				}
			}

			if ((conflicts & FUNC_RETURN) != 0) {
				currentExternalConflictType = ExternalConflictType.FUNCTION_RETURN_CONFLICT;
				// If we have a function return choice then a "Use For All" has already occurred.
				if (functionReturnChoice != ASK_USER) {
					mergeFunctionReturn(functions, functionReturnChoice, monitor);
				}
				else if (askUser && mergeManager != null) {
					VerticalChoicesPanel choicesPanel =
						createFunctionReturnConflictPanel(functions, monitor);

					boolean useForAll = (functionReturnChoice != ASK_USER);
					choicesPanel.setUseForAll(useForAll);
					choicesPanel.setConflictType("Function Return");

					setupConflictPanel(listingPanel, choicesPanel, externalLocations, monitor);
					monitor.checkCancelled();
				}
				else {
					mergeFunctionReturn(functions, currentConflictOption, monitor);
				}
			}

			// Handle merge of overlapping function variables.
			if ((conflicts & FUNC_VAR_STORAGE) != 0) {
				currentExternalConflictType = ExternalConflictType.VARIABLE_STORAGE_CONFLICT;
				if (variableStorageConflicts == null) {
					variableStorageConflicts = determineStorageConflict(functions, monitor);
				}
				// If we have a function variable storage choice then a "Use For All" has already occurred.
				if (variableStorageChoice != ASK_USER) {
					for (Pair<List<Variable>, List<Variable>> pair : variableStorageConflicts
							.getOverlappingVariables()) {
						monitor.checkCancelled();
						mergeVariableStorage(functions, pair, variableStorageChoice, monitor);
					}
				}
				else if (askUser && mergeManager != null) {
					for (Pair<List<Variable>, List<Variable>> pair : variableStorageConflicts
							.getOverlappingVariables()) {
						monitor.checkCancelled();
						boolean useForAll = (variableStorageChoice != ASK_USER);
						if (useForAll) {
							mergeVariableStorage(functions, pair, variableStorageChoice, monitor);
							continue;
						}
						ScrollingListChoicesPanel choicesPanel =
							createStorageConflictPanel(functions, pair, monitor);

						choicesPanel.setUseForAll(useForAll);
						choicesPanel.setConflictType("Function Variable Storage");

						setupConflictPanel(listingPanel, choicesPanel, externalLocations, monitor);
					}
				}
				else {
					for (Pair<List<Variable>, List<Variable>> pair : variableStorageConflicts
							.getOverlappingVariables()) {
						monitor.checkCancelled();
						mergeVariableStorage(functions, pair, currentConflictOption, monitor);
					}
				}
			}

			// Handle merge of function parameter signature.
			if ((conflicts & FUNC_SIGNATURE) != 0) {
				currentExternalConflictType = ExternalConflictType.PARAMETER_SIGNATURE_CONFLICT;
				// If we have a function parameter signature choice then a "Use For All" has already occurred.
				if (parameterSignatureChoice != ASK_USER) {
					mergeParameters(functions, parameterSignatureChoice, monitor);
				}
				else if (askUser && mergeManager != null) {
					VerticalChoicesPanel choicesPanel =
						createParameterSigConflictPanel(functions, monitor);

					boolean useForAll = (parameterSignatureChoice != ASK_USER);
					choicesPanel.setUseForAll(useForAll);
					choicesPanel.setConflictType("Function Parameter Signature");

					setupConflictPanel(listingPanel, choicesPanel, externalLocations, monitor);
					monitor.checkCancelled();
				}
				else {
					mergeParameters(functions, currentConflictOption, monitor);
				}
			}

			// Handle merge of function parameter Info details.
			if ((conflicts & FUNC_PARAM_DETAILS) != 0) {
				currentExternalConflictType = ExternalConflictType.PARAMETER_INFO_CONFLICT;
				if (paramInfoConflicts == null) {
					paramInfoConflicts = determineParameterInfoConflicts(functions, false, monitor);
				}
				// If we have a function parameter information choice then a "Use For All" has already occurred.
				if (parameterInfoChoice != ASK_USER) {
					mergeParamInfo(functions, paramInfoConflicts, parameterInfoChoice, monitor);
				}
				else if (askUser && mergeManager != null) {
					for (ParamInfoConflict pc : paramInfoConflicts) {
						monitor.checkCancelled();
						boolean useForAll = (parameterInfoChoice != ASK_USER);
						if (useForAll) {
							mergeParamInfo(functions, pc, parameterInfoChoice, monitor);
							continue;
						}
						VariousChoicesPanel choicesPanel =
							createParamInfoConflictPanel(functions, pc, monitor);

						choicesPanel.setUseForAll(useForAll);
						choicesPanel.setConflictType("Function Parameter Info");

						setupConflictPanel(listingPanel, choicesPanel, externalLocations, monitor);
						monitor.checkCancelled();
					}

				}
				else {
					mergeParamInfo(functions, paramInfoConflicts, currentConflictOption, monitor);
				}
			}

			// Handle merge of function local variable details.
			if ((conflicts & FUNC_LOCAL_DETAILS) != 0) {
				currentExternalConflictType = ExternalConflictType.LOCAL_VARIABLE_DETAIL_CONFLICT;
				if (localVarConflicts == null) {
					localVarConflicts = determineLocalVariableInfoConflicts(functions, false,
						variableStorageConflicts, monitor);
				}
				if (askUser && mergeManager != null) {
					for (LocalVariableConflict localVariableConflict : localVarConflicts) {
						monitor.checkCancelled();
						ConflictPanel choicesPanel;
						if ((localVariableConflict.varConflicts & VAR_REMOVED) != 0) {
							currentExternalConflictType =
								ExternalConflictType.REMOVED_LOCAL_VARIABLE_CONFLICT;
							// If we have a remove local variable choice then a "Use For All" has already occurred.
							if (removedLocalVariableChoice != ASK_USER) {
								mergeLocalVariable(VAR_REMOVED, myEntryPoint,
									localVariableConflict.vars, removedLocalVariableChoice,
									monitor);
								continue;
							}
							choicesPanel =
								createRemovedVarConflictPanel(localVariableConflict, monitor);

							boolean useForAll = (removedLocalVariableChoice != ASK_USER);
							choicesPanel.setUseForAll(useForAll);
							choicesPanel.setConflictType("Local Variable Removal");
						}
						else {
							currentExternalConflictType =
								ExternalConflictType.LOCAL_VARIABLE_DETAIL_CONFLICT;
							// If we have a local variable detail choice then a "Use For All" has already occurred.
							if (localVariableDetailChoice != ASK_USER) {
								mergeLocal(myEntryPoint, localVariableConflict,
									localVariableDetailChoice, monitor);
								continue;
							}
							choicesPanel =
								createLocalVariableConflictPanel(localVariableConflict, monitor);

							boolean useForAll = (localVariableDetailChoice != ASK_USER);
							choicesPanel.setUseForAll(useForAll);
							choicesPanel.setConflictType("Local Variable Detail");
						}
						setupConflictPanel(listingPanel, choicesPanel, externalLocations, monitor);
					}
				}
				else {
					mergeLocals(myEntryPoint, localVarConflicts, currentConflictOption, monitor);
				}
			}

		}
	}

	private ScrollingListChoicesPanel createStorageConflictPanel(final Function[] functions,
			final Pair<List<Variable>, List<Variable>> pair, final TaskMonitor monitor) {

		getEmptyScrollingListChoicesPanel();

		final ChangeListener changeListener = new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				int choice =
					ExternalFunctionMerger.this.scrollingListConflictPanel.getUseForAllChoice();
				if (choice == 0) {
					if (mergeManager != null) {
						mergeManager.setApplyEnabled(false);
					}
					return;
				}
				if (mergeManager != null) {
					mergeManager.clearStatusText();
				}
				try {
					mergeVariableStorage(functions, pair, choice == 1 ? KEEP_LATEST : KEEP_MY,
						monitor);
					if (mergeManager != null) {
						mergeManager.setApplyEnabled(true);
					}
				}
				catch (Exception e1) {
					Msg.error(this, "Unexpected Exception: " + e1.getMessage(), e1);
				}
			}
		};

		runSwing(() -> {
			scrollingListConflictPanel.setTitle("Parameter/Variable Storage");
			String text = LATEST_TITLE + " function '" + functions[LATEST].getName(true) +
				"' and " + MY_TITLE + " function '" + functions[MY].getName(true) +
				"' have conflicting parameter/variable storage resulting from changes.<br>Choose the desired set of parameters/variables to keep.<br>";
			scrollingListConflictPanel.setHeader(text);
			scrollingListConflictPanel.setChoiceNames(LATEST_TITLE, LATEST_LIST_BUTTON_NAME,
				MY_TITLE, CHECKED_OUT_LIST_BUTTON_NAME);
			scrollingListConflictPanel.setListChoice(changeListener, STORAGE_CONFLICT_CHOICES,
				STORAGE_CONFLICT_HEADINGS, getVariableDetails(pair.first),
				getVariableDetails(pair.second));
		});
		return scrollingListConflictPanel;
	}

	private void mergeVariableStorage(Function[] functions,
			Pair<List<Variable>, List<Variable>> pair, int currentConflictOption,
			TaskMonitor monitor) throws CancelledException {

		ProgramMerge pgmMerge = getProgramListingMerge(currentConflictOption);
		List<Variable> list;
		Address entryPt;
		if (currentConflictOption == KEEP_LATEST) {
			list = pair.first;
			entryPt = functions[LATEST].getEntryPoint();
		}
		else {
			list = pair.second;
			entryPt = functions[MY].getEntryPoint();
		}
		pgmMerge.replaceVariables(entryPt, list, monitor);
	}

	private ExternalLocation[] getExternalLocationsForFunctions(Function[] functions) {
		ExternalLocation[] externalLocations = new ExternalLocation[4];

		if (functions[RESULT] != null) {
			externalLocations[RESULT] = functions[RESULT].getExternalLocation();
		}
		if (functions[LATEST] != null) {
			externalLocations[LATEST] = functions[LATEST].getExternalLocation();
		}
		if (functions[MY] != null) {
			externalLocations[MY] = functions[MY].getExternalLocation();
		}
		if (functions[ORIGINAL] != null) {
			externalLocations[ORIGINAL] = functions[ORIGINAL].getExternalLocation();
		}
		return externalLocations;
	}

	private void updateAddressTranslators(ExternalLocation[] locations) {
		Address resultExternalAddress =
			(locations[RESULT] != null) ? locations[RESULT].getExternalSpaceAddress() : null;
		Address latestExternalAddress =
			(locations[LATEST] != null) ? locations[LATEST].getExternalSpaceAddress() : null;
		Address myExternalAddress =
			(locations[MY] != null) ? locations[MY].getExternalSpaceAddress() : null;
		Address originalExternalAddress =
			(locations[ORIGINAL] != null) ? locations[ORIGINAL].getExternalSpaceAddress() : null;

		// Set up address translator information for any ProgramMerge method calls.
		myAddressTranslator.setPair(resultExternalAddress, myExternalAddress);
		latestAddressTranslator.setPair(resultExternalAddress, latestExternalAddress);
		originalAddressTranslator.setPair(resultExternalAddress, originalExternalAddress);
	}

	private void updateAddressTranslators(Function[] functions) {
		Address resultExternalAddress =
			(functions[RESULT] != null) ? functions[RESULT].getEntryPoint() : null;
		Address latestExternalAddress =
			(functions[LATEST] != null) ? functions[LATEST].getEntryPoint() : null;
		Address myExternalAddress = (functions[MY] != null) ? functions[MY].getEntryPoint() : null;
		Address originalExternalAddress =
			(functions[ORIGINAL] != null) ? functions[ORIGINAL].getEntryPoint() : null;

		// Set up address translator information for any ProgramMerge method calls.
		myAddressTranslator.setPair(resultExternalAddress, myExternalAddress);
		latestAddressTranslator.setPair(resultExternalAddress, latestExternalAddress);
		originalAddressTranslator.setPair(resultExternalAddress, originalExternalAddress);
	}

	public void mergeConflictsForAdd(final ExternalLocation[] externalLocations,
			final int chosenConflictOption, final TaskMonitor monitor) throws CancelledException {

		Address myAddress = externalLocations[MY].getExternalSpaceAddress();

		// Handle External Detail Conflicts
		if (externalDetailConflicts.contains(myAddress)) {
			monitor.checkCancelled();
			handleExternalDetailsConflict(externalLocations, chosenConflictOption, monitor);
		}

		// Handle External Data Type Conflicts
		if (externalDataTypeConflicts.contains(myAddress)) {
			monitor.checkCancelled();
			handleExternalDataTypeConflict(externalLocations, chosenConflictOption, monitor);
		}

		// Handle External Function versus Data Type Conflicts
		if (externalFunctionVersusDataTypeConflicts.contains(myAddress)) {
			monitor.checkCancelled();
			handleExternalFunctionVersusDataTypeConflict(externalLocations, chosenConflictOption,
				monitor);
		}

		// Handle Detailed Function Conflicts
		if (funcSet.contains(myAddress)) {
			monitor.checkCancelled();
			Address myEntryPoint = myAddress;
			Function[] functions = getFunctions(externalLocations);
			updateExternalNameInfo(externalLocations, MY);
			handleExternalFunctionConflict(functions, myEntryPoint, chosenConflictOption,
				listingMergePanel, monitor);

			// The following removes myAddress from funcSet since we just handled it here.
			funcSet.deleteRange(myAddress, myAddress);
		}
	}

	private long resolveOriginalIDFromLatestID(long latestID) {
		try {
			return latestToOriginalHash.get(latestID);
		}
		catch (NoValueException e) {
			return latestID;
		}
	}

	private long resolveOriginalIDFromMyID(long myID) {
		try {
			return myToOriginalHash.get(myID);
		}
		catch (NoValueException e) {
			return myID;
		}
	}

	private long resolveLatestIDFromOriginalID(long originalID) {
		try {
			return originalToLatestHash.get(originalID);
		}
		catch (NoValueException e) {
			return originalID;
		}
	}

	private long resolveMyIDFromOriginalID(long originalID) {
		try {
			return originalToMyHash.get(originalID);
		}
		catch (NoValueException e) {
			return originalID;
		}
	}

	/**
	 * Gets the external locations (result, latest, my, original) for the specified MY program
	 * external space address.<br>
	 * NOTE: Be careful where you call this method from. It is intended to be used for external
	 * location changes only (not for Adds). It gets the ORIGINAL based on MY and then LATEST and
	 * RESULT based on the ORIGINAL.
	 * @param myAddress the MY program external space address for MY external location
	 * @return all four program's external locations.
	 */
	private ExternalLocation[] getExternalLocationsForMyAddress(Address myAddress) {
		ExternalLocation[] externalLocations = new ExternalLocation[4];

		Symbol mySymbol = symbolTables[MY].getPrimarySymbol(myAddress);
		long myID = mySymbol.getID();
		long originalID = resolveOriginalIDFromMyID(myID);
		long latestID = resolveLatestIDFromOriginalID(originalID);

		Symbol latestSymbol = symbolTables[LATEST].getSymbol(latestID);
		Symbol originalSymbol = symbolTables[ORIGINAL].getSymbol(originalID);
		if (latestSymbol != null) {
			externalLocations[LATEST] = externalManagers[LATEST].getExternalLocation(latestSymbol);
		}
		externalLocations[MY] = externalManagers[MY].getExternalLocation(mySymbol);
		if (originalSymbol != null) {
			externalLocations[ORIGINAL] =
				externalManagers[ORIGINAL].getExternalLocation(originalSymbol);
		}
		// Get the RESULT external location.
		long resultID;
		try {
			resultID = myResolvedSymbols.get(myID);
		}
		catch (NoValueException e) {
			resultID = getResultIDfromLatestID(latestID);
		}
		Symbol resultSymbol = symbolTables[RESULT].getSymbol(resultID);
		if (resultSymbol != null) {
			externalLocations[RESULT] = externalManagers[RESULT].getExternalLocation(resultSymbol);
		}
		return externalLocations;
	}

	private ExternalLocation[] getExternalLocationsForOriginalID(long originalID) {
		ExternalLocation[] externalLocations = new ExternalLocation[4];

		Symbol originalSymbol = symbolTables[ORIGINAL].getSymbol(originalID);
		long latestID = resolveLatestIDFromOriginalID(originalID);
		long myID = resolveMyIDFromOriginalID(originalID);

		Symbol latestSymbol = symbolTables[LATEST].getSymbol(latestID);
		Symbol mySymbol = symbolTables[MY].getSymbol(myID);
		if (latestSymbol != null) {
			externalLocations[LATEST] = externalManagers[LATEST].getExternalLocation(latestSymbol);
		}
		if (mySymbol != null) {
			externalLocations[MY] = externalManagers[MY].getExternalLocation(mySymbol);
		}
		if (originalSymbol != null) {
			externalLocations[ORIGINAL] =
				externalManagers[ORIGINAL].getExternalLocation(originalSymbol);
		}
		// Get the RESULT external location.
		long resultID;
		try {
			resultID = originalResolvedSymbols.get(originalID);
		}
		catch (NoValueException e) {
			resultID = latestID;
		}
		Symbol resultSymbol = symbolTables[RESULT].getSymbol(resultID);
		if (resultSymbol != null) {
			externalLocations[RESULT] = externalManagers[RESULT].getExternalLocation(resultSymbol);
		}
		return externalLocations;
	}

	private void handleExternalDetailsConflict(ExternalLocation[] externalLocations,
			int chosenConflictOption, TaskMonitor monitor) throws CancelledException {

		currentExternalConflictType = ExternalConflictType.EXTERNAL_DETAILS_CONFLICT;
		updateExternalNameInfo(externalLocations, MY);
		boolean askUser = (externalDetailsChoice == ASK_USER) && (chosenConflictOption == ASK_USER);
		updateAddressTranslators(externalLocations);

		Address myExternalAddress = externalLocations[MY].getExternalSpaceAddress();
		if (askUser && mergeManager != null) {
			VariousChoicesPanel choicesPanel =
				createExternalDetailConflictPanel(externalLocations, myExternalAddress, monitor);

			boolean useForAll = (externalDetailsChoice != ASK_USER);
			choicesPanel.setUseForAll(useForAll);
			choicesPanel.setConflictType("External Details");

			setupConflictPanel(listingMergePanel, choicesPanel, externalLocations, monitor);
			monitor.checkCancelled();
		}
		else {
			// If we have a external details choice then a "Use For All" has already occurred.
			int optionToUse =
				(externalDetailsChoice == ASK_USER) ? chosenConflictOption : externalDetailsChoice;
			// Merge each detail type that is in conflict.
			try {
				int conflicts = externalDetailConflicts.get(myExternalAddress);
				for (int shift = 0; shift <= HIGHEST_DETAIL_BIT_SHIFT; shift++) {
					int type = 1 << shift;
					if ((conflicts & type) != 0) {
						mergeBasicExternalDetail(type, externalLocations, optionToUse, monitor);
					}
				}
			}
			catch (NoValueException e) {
				Msg.error(this, "Couldn't merge external details conflict at address " +
					myExternalAddress + ".");
			}
		}
	}

	private void handleExternalDataTypeConflict(ExternalLocation[] externalLocations,
			int chosenConflictOption, TaskMonitor monitor) throws CancelledException {

		currentExternalConflictType = ExternalConflictType.EXTERNAL_DATA_TYPE_CONFLICT;
		updateExternalNameInfo(externalLocations, MY);
		boolean askUser =
			(externalDataTypeChoice == ASK_USER) && (chosenConflictOption == ASK_USER);
		updateAddressTranslators(externalLocations);

		if (askUser && mergeManager != null) {
			VerticalChoicesPanel choicesPanel =
				createExternalDataTypeConflictPanel(externalLocations, monitor);

			boolean useForAll = (externalDataTypeChoice != ASK_USER);
			choicesPanel.setUseForAll(useForAll);
			choicesPanel.setConflictType("External Data Type");

			setupConflictPanel(listingMergePanel, choicesPanel, externalLocations, monitor);
			monitor.checkCancelled();
		}
		else {
			// If we have a external data type choice then a "Use For All" has already occurred.
			int optionToUse = (externalDataTypeChoice == ASK_USER) ? chosenConflictOption
					: externalDataTypeChoice;
			mergeExternalDataType(externalLocations, optionToUse, monitor);
		}
	}

	private void handleExternalFunctionVersusDataTypeConflict(ExternalLocation[] externalLocations,
			int chosenConflictOption, TaskMonitor monitor) throws CancelledException {

		currentExternalConflictType = ExternalConflictType.EXTERNAL_FUNCTION_VS_DATA_TYPE_CONFLICT;
		updateExternalNameInfo(externalLocations, MY);
		boolean askUser =
			(externalFunctionVsDataTypeChoice == ASK_USER) && (chosenConflictOption == ASK_USER);
		updateAddressTranslators(externalLocations);

		if (askUser && mergeManager != null) {
			VerticalChoicesPanel choicesPanel =
				createExternalFunctionVsDataTypeConflictPanel(externalLocations, monitor);

			boolean useForAll = (externalFunctionVsDataTypeChoice != ASK_USER);
			choicesPanel.setUseForAll(useForAll);
			choicesPanel.setConflictType("External Function Versus Data Type");

			setupConflictPanel(listingMergePanel, choicesPanel, externalLocations, monitor);
			monitor.checkCancelled();
		}
		else {
			// If we have a external function vs. data type choice then a "Use For All" has already occurred.
			int optionToUse = (externalFunctionVsDataTypeChoice == ASK_USER) ? chosenConflictOption
					: externalFunctionVsDataTypeChoice;
			merge(externalLocations, optionToUse, monitor);
		}
	}

	private void handleExternalAddConflict(long latestExternalID, long myExternalID,
			final int chosenConflictOption, TaskMonitor monitor) throws CancelledException {

		currentExternalConflictType = ExternalConflictType.EXTERNAL_ADD_CONFLICT;
		long resultExternalID = getResultIDfromLatestID(latestExternalID);
		Symbol latestSymbol = symbolTables[LATEST].getSymbol(latestExternalID);
		Symbol mySymbol = symbolTables[MY].getSymbol(myExternalID);
		Symbol resultSymbol = symbolTables[RESULT].getSymbol(resultExternalID);
		ExternalLocation[] externalLocations = new ExternalLocation[4];
		externalLocations[LATEST] = externalManagers[LATEST].getExternalLocation(latestSymbol);
		externalLocations[MY] = externalManagers[MY].getExternalLocation(mySymbol);
		externalLocations[ORIGINAL] = null;
		externalLocations[RESULT] = externalManagers[RESULT].getExternalLocation(resultSymbol);

		updateExternalNameInfo(externalLocations, MY);
		boolean askUser = (externalAddChoice == ASK_USER) && (chosenConflictOption == ASK_USER);
		updateAddressTranslators(externalLocations);

		if (askUser && mergeManager != null) {
			if (addConflictPanel == null) {
				addConflictPanel = new ExternalAddConflictPanel(mergeManager, totalConflicts,
					programs[LATEST], programs[MY], showListingPanel);
			}

			VerticalChoicesPanel choicesPanel = createAddConflictPanel(externalLocations, monitor);

			boolean useForAll = (externalAddChoice != ASK_USER);
			choicesPanel.setUseForAll(useForAll);
			choicesPanel.setConflictType("External Add");

			setupAddConflictPanel(addConflictPanel, choicesPanel, externalLocations[LATEST],
				externalLocations[MY], monitor);
			monitor.checkCancelled();
		}
		else {
			// If we have a external add choice then a "Use For All" has already occurred.
			int optionToUse =
				(externalAddChoice == ASK_USER) ? chosenConflictOption : externalAddChoice;
			resolveAddConflict(externalLocations, optionToUse, monitor);
		}
		// Now process any conflicts that were created by picking merge both.
		mergeConflictsForAdd(externalLocations, chosenConflictOption, monitor);
	}

	private Function[] getFunctions(ExternalLocation[] externalLocations) {
		Function[] functions = new Function[4];
		functions[RESULT] =
			(externalLocations[RESULT] != null) ? externalLocations[RESULT].getFunction() : null;
		functions[LATEST] =
			(externalLocations[LATEST] != null) ? externalLocations[LATEST].getFunction() : null;
		functions[MY] =
			(externalLocations[MY] != null) ? externalLocations[MY].getFunction() : null;
		functions[ORIGINAL] =
			(externalLocations[ORIGINAL] != null) ? externalLocations[ORIGINAL].getFunction()
					: null;
		return functions;
	}

	private void handleRemoveConflict(long originalExternalID, int currentConflictOption,
			TaskMonitor monitor) throws CancelledException {

		currentExternalConflictType = ExternalConflictType.EXTERNAL_REMOVE_CONFLICT;
		ExternalLocation[] externalLocations =
			getExternalLocationsForOriginalID(originalExternalID);
		if (externalLocations[ORIGINAL] == null) {
			throw new AssertException(
				"Couldn't get original external location for ID, " + originalExternalID + ".");
		}

		updateExternalNameInfo(externalLocations, ORIGINAL);
		boolean askUser = (externalRemoveChoice == ASK_USER) && (currentConflictOption == ASK_USER);
		updateAddressTranslators(externalLocations);

		if (askUser && mergeManager != null) {
			VerticalChoicesPanel choicesPanel =
				createRemoveConflictPanel(externalLocations, monitor);

			boolean useForAll = (externalRemoveChoice != ASK_USER);
			choicesPanel.setUseForAll(useForAll);
			choicesPanel.setConflictType("External Removal");

			setupConflictPanel(listingMergePanel, choicesPanel, externalLocations, monitor);
			monitor.checkCancelled();
		}
		else {
			// If we have a function remove choice then a "Use For All" has already occurred.
			int optionToUse =
				(externalRemoveChoice == ASK_USER) ? currentConflictOption : externalRemoveChoice;
			merge(externalLocations, optionToUse, monitor);
		}
	}

	private void updateExternalNameInfo(ExternalLocation[] externalLocations, int programVersion) {
		conflictInfoPanel.setExternalName(getVersionName(programVersion),
			externalLocations[programVersion].getSymbol().getName(true));
	}

	private VerticalChoicesPanel createAddConflictPanel(final ExternalLocation[] externalLocations,
			final TaskMonitor monitor) {
		String[] header = getExternalInfo(externalLocations, HEADER);
		String[] latest = getExternalInfo(externalLocations, LATEST);
		String[] my = getExternalInfo(externalLocations, MY);
		String[] keepBoth = { "Keep Both", "", "", "", "", "", "" };
		String[] mergeBoth = { "Merge Together", "", "", "", "", "", "" };

		VerticalChoicesPanel panel = getEmptyVerticalPanel();

		runSwing(() -> {
			panel.setTitle("External Add");
			StringBuffer buf = new StringBuffer();
			buf.append(LATEST_TITLE + " external '");
			String latestName = getExternalName(externalLocations, LATEST, true);
			buf.append(ConflictUtility.getEmphasizeString(latestName));
			buf.append("' and " + MY_TITLE + " external '");
			String myName = getExternalName(externalLocations, MY, true);
			buf.append(ConflictUtility.getEmphasizeString(myName));
			buf.append("' were added,<br>but are possibly intended to be the same external.");
			buf.append(HTMLUtilities.spaces(2));
			buf.append("Choose which one(s) you want to keep.<br>");
			buf.append(HTMLUtilities.spaces(2));
			panel.setHeader(buf.toString());
			ChangeListener changeListener =
				new ExternalAddConflictChangeListener(externalLocations, panel, monitor);
			panel.setRowHeader(header);
			panel.addRadioButtonRow(latest, LATEST_BUTTON_NAME, KEEP_LATEST_ADD, changeListener);
			panel.addRadioButtonRow(my, CHECKED_OUT_BUTTON_NAME, KEEP_MY_ADD, changeListener);
			panel.addRadioButtonRow(keepBoth, KEEP_BOTH_BUTTON_NAME, KEEP_BOTH_ADDS,
				changeListener);
			panel.addRadioButtonRow(mergeBoth, MERGE_BOTH_BUTTON_NAME, MERGE_BOTH_ADDS,
				changeListener);
		});
		return panel;
	}

	private VerticalChoicesPanel createRemoveConflictPanel(
			final ExternalLocation[] externalLocations, final TaskMonitor monitor) {
		String[] header = getExternalInfo(externalLocations, HEADER);
		String[] latest = getExternalInfo(externalLocations, LATEST);
		String[] my = getExternalInfo(externalLocations, MY);
		String[] original = getExternalInfo(externalLocations, ORIGINAL);

		VerticalChoicesPanel panel = getEmptyVerticalPanel();

		runSwing(() -> {
			panel.setTitle("External Remove");
			StringBuffer buf = new StringBuffer();
			buf.append("One external was removed and the other changed for ");
			buf.append(getExternalName(externalLocations, ORIGINAL, true));
			buf.append(".");
			panel.setHeader(buf.toString());
			ChangeListener changeListener =
				new ExternalRemoveConflictChangeListener(externalLocations, panel, monitor);
			panel.setRowHeader(header);
			panel.addRadioButtonRow(latest, LATEST_BUTTON_NAME, KEEP_LATEST, changeListener);
			panel.addRadioButtonRow(my, CHECKED_OUT_BUTTON_NAME, KEEP_MY, changeListener);
			panel.addRadioButtonRow(original, ORIGINAL_BUTTON_NAME, KEEP_ORIGINAL, changeListener);

		});
		return panel;
	}

	private VariousChoicesPanel createExternalDetailConflictPanel(
			final ExternalLocation[] locations, Address myEntryPoint, final TaskMonitor monitor) {

		int conflicts = 0;
		try {
			conflicts = externalDetailConflicts.get(myEntryPoint);
		}
		catch (NoValueException e) {
			throw new AssertException();
		}
		return createExternalDetailConflictPanel(locations, conflicts, monitor);
	}

	private VariousChoicesPanel createExternalDetailConflictPanel(
			final ExternalLocation[] locations, int conflicts, final TaskMonitor monitor) {

		VariousChoicesPanel panel = getEmptyVariousPanel();

		Address resultExternalAddress =
			(locations[RESULT] != null) ? locations[RESULT].getExternalSpaceAddress() : null;
		Address latestExternalAddress =
			(locations[LATEST] != null) ? locations[LATEST].getExternalSpaceAddress() : null;
		Address myExternalAddress =
			(locations[MY] != null) ? locations[MY].getExternalSpaceAddress() : null;
		Address originalExternalAddress =
			(locations[ORIGINAL] != null) ? locations[ORIGINAL].getExternalSpaceAddress() : null;

		// Set up address translator information for any ProgramMerge method calls.
		myAddressTranslator.setPair(resultExternalAddress, myExternalAddress);
		latestAddressTranslator.setPair(resultExternalAddress, latestExternalAddress);
		originalAddressTranslator.setPair(resultExternalAddress, originalExternalAddress);

		runSwing(() -> {
			panel.setTitle("External Detail");
			String typeString;
			String addressString;
			String label;
			if (locations[ORIGINAL] != null) {
				typeString = ORIGINAL_TITLE;
				label = locations[ORIGINAL].getSymbol().getName(true);
				Address address = locations[ORIGINAL].getAddress();
				addressString = (address != null)
						? (" associated with external memory address '" +
							ConflictUtility.getAddressString(address, true) + "'")
						: "";
			}
			else {
				typeString = RESULT_TITLE;
				label = locations[RESULT].getLabel();
				Address address = locations[RESULT].getAddress();
				addressString = (address != null)
						? (" associated with external memory address '" +
							ConflictUtility.getAddressString(address, true) + "'")
						: "";
			}
			String text = "Detail conflicts need to be resolved for the " + typeString +
				" external '" + ConflictUtility.getEmphasizeString(label) + "'" + addressString +
				".<br>Make a choice for each conflict type.";
			panel.setHeader(text);
			panel.addInfoRow("Conflict", new String[] { LATEST_TITLE, MY_TITLE }, true);

			if ((conflicts & EXTERNAL_NAMESPACE) != 0) {
				Namespace latestNamespace = locations[LATEST].getParentNameSpace();
				Namespace myNamespace = locations[MY].getParentNameSpace();
				String latest = latestNamespace.getName(true);
				String my = myNamespace.getName(true);
				panel.addSingleChoice("Namespace", new String[] { latest, my },
					new ExternalDetailChangeListener(EXTERNAL_NAMESPACE, locations, panel,
						monitor));
			}
			if ((conflicts & EXTERNAL_LABEL) != 0) {
				String latest = locations[LATEST].getLabel();
				String my = locations[MY].getLabel();
				panel.addSingleChoice("Name", new String[] { latest, my },
					new ExternalDetailChangeListener(EXTERNAL_LABEL, locations, panel, monitor));
			}
			if ((conflicts & EXTERNAL_ADDRESS) != 0) {
				Address latestAddress = locations[LATEST].getAddress();
				Address myAddress = locations[MY].getAddress();
				String latest = (latestAddress != null) ? latestAddress.toString() : null;
				String my = (myAddress != null) ? myAddress.toString() : null;
				panel.addSingleChoice("Address", new String[] { latest, my },
					new ExternalDetailChangeListener(EXTERNAL_ADDRESS, locations, panel, monitor));
			}
//		// SourceType is handled along with Label.
//		if ((conflicts & EXTERNAL_SOURCE_TYPE) != 0) {
//			String latest = locations[LATEST].getSource().getDisplayString();
//			String my = locations[MY].getSource().getDisplayString();
////			String original = locations[ORIGINAL].getSource().getDisplayString();
//			panel.addSingleChoice("Source Type", new String[] { latest, my },
//				new ExternalDetailChangeListener(EXTERNAL_SOURCE_TYPE, locations, panel, monitor));
//		}
			if ((conflicts & EXTERNAL_DATA_TYPE) != 0) {
				DataType latestResultDt = getResultDataType(locations[LATEST]);
				DataType myResultDt = getResultDataType(locations[MY]);
				String latest = (latestResultDt != null) ? latestResultDt.getName() : "";
				String my = (myResultDt != null) ? myResultDt.getName() : "";
				panel.addSingleChoice("Data Type", new String[] { latest, my },
					new ExternalDetailChangeListener(EXTERNAL_DATA_TYPE, locations, panel,
						monitor));
			}
			// Types and Functions are handled elsewhere.

		});
		return panel;
	}

	private VerticalChoicesPanel createExternalDataTypeConflictPanel(
			final ExternalLocation[] externalLocations, final TaskMonitor monitor) {

		DataType latestDataType = getResultDataType(externalLocations[LATEST]);
		DataType myDataType = getResultDataType(externalLocations[MY]);
		String removeString;
		String changeString;
		if (latestDataType == null) {
			removeString = LATEST_TITLE;
			changeString = MY_TITLE;
		}
		else if (myDataType == null) {
			removeString = MY_TITLE;
			changeString = LATEST_TITLE;
		}
		else {
			removeString = null;
			changeString = null;
		}

		String[] header = getExternalInfo(externalLocations, HEADER);
		String[] latest = getExternalInfo(externalLocations, LATEST);
		String[] my = getExternalInfo(externalLocations, MY);
		String[] original = getExternalInfo(externalLocations, ORIGINAL);

		VerticalChoicesPanel panel = getEmptyVerticalPanel();

		runSwing(() -> {
			panel.setTitle("External Data Type");
			StringBuffer buf = new StringBuffer();
			if (removeString != null) {
				buf.append("External data type was removed in " + removeString +
					" and changed in " + changeString + " /nfor ");
				buf.append(getExternalName(externalLocations, ORIGINAL, true));
				buf.append(".");
			}
			else {
				buf.append(LATEST_TITLE + " and " + MY_TITLE + " both changed data type \nfor ");
				buf.append(getExternalName(externalLocations, ORIGINAL, true));
				buf.append(".");
			}
			panel.setHeader(buf.toString());
			ChangeListener changeListener =
				new ExternalDataTypeConflictChangeListener(externalLocations, panel, monitor);
			panel.setRowHeader(header);
			panel.addRadioButtonRow(latest, LATEST_BUTTON_NAME, KEEP_LATEST, changeListener);
			panel.addRadioButtonRow(my, CHECKED_OUT_BUTTON_NAME, KEEP_MY, changeListener);
			original[0] = ORIGINAL_TITLE + " version"; // Change since original is only info row.
			panel.addInfoRow(original);
		});
		return panel;
	}

	private VerticalChoicesPanel createExternalRemoveFunctionConflictPanel(
			final ExternalLocation[] externalLocations, final TaskMonitor monitor) {

		Function latestFunction =
			(externalLocations[LATEST] != null) ? externalLocations[LATEST].getFunction() : null;
		Function myFunction =
			(externalLocations[MY] != null) ? externalLocations[MY].getFunction() : null;

		String[] header = getExternalInfo(externalLocations, HEADER);
		String[] latest = getExternalInfo(externalLocations, LATEST);
		String[] my = getExternalInfo(externalLocations, MY);
		String[] original = getExternalInfo(externalLocations, ORIGINAL);

		String latestRemovedOrChanged = (latestFunction == null) ? "removed" : "changed";
		String myRemovedOrChanged = (myFunction == null) ? "removed" : "changed";
		String originalName = externalLocations[ORIGINAL].getSymbol().getName(true);
		String headerString =
			"The external function '" + originalName + "' was " + latestRemovedOrChanged + " in " +
				LATEST_TITLE + ", but was " + myRemovedOrChanged + " in " + MY_TITLE + ".";

		VerticalChoicesPanel panel = getEmptyVerticalPanel();

		runSwing(() -> {
			panel.setTitle("External Function Remove");
			panel.setHeader(headerString);
			ChangeListener changeListener =
				new ExternalRemoveFunctionConflictChangeListener(externalLocations, panel, monitor);
			panel.setRowHeader(header);
			panel.addRadioButtonRow(latest, LATEST_BUTTON_NAME, KEEP_LATEST, changeListener);
			panel.addRadioButtonRow(my, CHECKED_OUT_BUTTON_NAME, KEEP_MY, changeListener);
			original[0] = ORIGINAL_TITLE + " version"; // Change since original is only info row.
			panel.addInfoRow(original);
		});
		return panel;
	}

	private VerticalChoicesPanel createExternalFunctionVsDataTypeConflictPanel(
			final ExternalLocation[] externalLocations, final TaskMonitor monitor) {

		DataType latestDataType = getResultDataType(externalLocations[LATEST]);

		Function latestFunction = externalLocations[LATEST].getFunction();
		Function originalFunction =
			(externalLocations[ORIGINAL] != null) ? externalLocations[ORIGINAL].getFunction()
					: null;

		String[] header = getExternalInfo(externalLocations, HEADER);
		String[] latest = getExternalInfo(externalLocations, LATEST);
		String[] my = getExternalInfo(externalLocations, MY);
		String[] original = getExternalInfo(externalLocations, ORIGINAL);

		String latestName = externalLocations[LATEST].getSymbol().getName(true);
		String dataTypeIsLatestOrMy = (latestDataType == null) ? MY_TITLE : LATEST_TITLE;
		String functionIsLatestOrMy = (latestFunction == null) ? MY_TITLE : LATEST_TITLE;
		String headerString;
		if (externalLocations[ORIGINAL] != null) {
			String originalName = externalLocations[ORIGINAL].getSymbol().getName(true);
			if (originalFunction == null) {
				headerString = "The external label, " + originalName +
					", had its data type changed in " + dataTypeIsLatestOrMy +
					", but was switched to a function in " + functionIsLatestOrMy + ".";
			}
			else {
				headerString = "The external function, " + originalName + ", was changed in " +
					functionIsLatestOrMy + ", but was switched to a label with a data type in " +
					dataTypeIsLatestOrMy + ".";
			}
		}
		else {
			if (latestFunction == null) {
				headerString = "The external label, " + latestName +
					", was added with a data type in " + dataTypeIsLatestOrMy +
					", but was added as a function in " + functionIsLatestOrMy + ".";
			}
			else {
				headerString = "The external function, " + latestName +
					", was added as a function in " + functionIsLatestOrMy +
					", but was added as a label with a data type in " + dataTypeIsLatestOrMy + ".";
			}
		}

		VerticalChoicesPanel panel = getEmptyVerticalPanel();

		runSwing(() -> {
			panel.setTitle("External Function Versus Data Type");
			panel.setHeader(headerString);
			ChangeListener changeListener = new ExternalFunctionVsDataTypeConflictChangeListener(
				externalLocations, panel, monitor);
			panel.setRowHeader(header);
			panel.addRadioButtonRow(latest, LATEST_BUTTON_NAME, KEEP_LATEST, changeListener);
			panel.addRadioButtonRow(my, CHECKED_OUT_BUTTON_NAME, KEEP_MY, changeListener);
			original[0] = ORIGINAL_TITLE + " version"; // Change since original is only info row.
			panel.addInfoRow(original);

		});
		return panel;
	}

	protected VariousChoicesPanel createParamInfoConflictPanel(final Function[] functions,
			final ParamInfoConflict pc, final TaskMonitor monitor) {
		int ordinal = pc.ordinal;
		int conflicts = pc.paramConflicts;
		Parameter latestParam =
			(functions[LATEST] != null) ? functions[LATEST].getParameter(ordinal) : null;
		Parameter myParam = (functions[MY] != null) ? functions[MY].getParameter(ordinal) : null;
//		Parameter originalParam =
//			(functions[ORIGINAL] != null) ? functions[ORIGINAL].getParameter(ordinal) : null;
		VariousChoicesPanel panel = getEmptyVariousPanel();

		runSwing(() -> {
			panel.setTitle("Function Parameter");
			Parameter param = (latestParam != null) ? latestParam : myParam;
			String varInfo = "Stack Parameter" + ConflictUtility.spaces(4) + "Storage: " +
				ConflictUtility.getEmphasizeString(param.getVariableStorage().toString());
			String text =
				"The following parameter has conflicts between " + LATEST_TITLE + " and " +
					MY_TITLE + ". For each conflict choose the detail you want to keep.<br><br>" +
					RESULT_TITLE + " External Function: " +
					ConflictUtility.getEmphasizeString(functions[RESULT].getName(true)) +
					ConflictUtility.spaces(4) + ConflictUtility.spaces(4) + "Parameter #" +
					ConflictUtility.getNumberString(param.getOrdinal() + 1) +
					ConflictUtility.spaces(4) + varInfo;
			panel.setHeader(text);
			panel.addInfoRow("Conflict", new String[] { LATEST_TITLE, MY_TITLE }, true);

//		if ((conflicts & VAR_TYPE) != 0) {
//			String latest = (latestParam instanceof RegisterParameter) ? "Register" : "Stack";
//		String my = (myParam instanceof RegisterParameter) ? "Register" : "Stack";
//		String original = (originalParam instanceof RegisterParameter) ? "Register" : "Stack";
//			panel.addSingleChoice("Parameter Type", new String[] { latest, my },
//				new ExternalParameterChangeListener(VAR_TYPE, functions, ordinal, panel, monitor));
//		}
			if ((conflicts & VAR_NAME) != 0) {
				String latest = (latestParam != null) ? latestParam.getName() : "";
				String my = (myParam != null) ? myParam.getName() : "";
//			String original = (originalParam != null) ? originalParam.getName() : "";
				panel.addSingleChoice("Parameter Name", new String[] { latest, my },
					new ExternalParameterChangeListener(VAR_NAME, functions, ordinal, panel,
						monitor));
			}
			if ((conflicts & VAR_DATATYPE) != 0) {
				DataType latestDataType = getResultDataType(latestParam.getDataType());
				DataType myDataType = getResultDataType(myParam.getDataType());
//			DataType originalDataType = getResultDataType(originalParam.getDataType());
				String latest = (latestDataType != null) ? latestDataType.getName() : "";
				String my = (myDataType != null) ? myDataType.getName() : "";
//			String original = (originalDataType != null) ? originalDataType.getName() : "";
				panel.addSingleChoice("Parameter Data Type", new String[] { latest, my },
					new ExternalParameterChangeListener(VAR_DATATYPE, functions, ordinal, panel,
						monitor));
			}
//		if ((conflicts & VAR_LENGTH) != 0) {
//			String latest = (latestParam != null) ? latestParam.getLength() : "";
//			String my = (myParam != null) ? myParam.getLength() : "";
//			String original = (originalParam != null) ? originalParam.getLength() : "";
//			panel.addSingleChoice("Parameter Length", new String[] {latest, my},
//					new ExternalParameterChangeListener(VAR_LENGTH, entryPt, ordinal, panel, monitor));
//		}
			if ((conflicts & VAR_COMMENT) != 0) {
				String latest = (latestParam != null) ? latestParam.getComment() : "";
				String my = (myParam != null) ? myParam.getComment() : "";
//			String original = (originalParam != null) ? originalParam.getComment() : "";
				panel.addSingleChoice("Parameter Comment", new String[] { latest, my },
					new ExternalParameterChangeListener(VAR_COMMENT, functions, ordinal, panel,
						monitor));
			}
		});
		return panel;
	}

	class ExternalParameterChangeListener implements ChangeListener {
		int type;
		Function[] functions;
		int ordinal;
		TaskMonitor monitor;
		VariousChoicesPanel vPanel;

		ExternalParameterChangeListener(final int type, final Function[] functions,
				final int ordinal, final VariousChoicesPanel vPanel, final TaskMonitor monitor) {
			this.type = type;
			this.functions = functions;
			this.ordinal = ordinal;
			this.monitor = monitor;
			this.vPanel = vPanel;
		}

		@Override
		public void stateChanged(ChangeEvent e) {
			ResolveConflictChangeEvent re = (ResolveConflictChangeEvent) e;
			int choice = re.getChoice();
			mergeParameter(type, functions, ordinal, getOptionForChoice(choice), monitor);
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

	private String getExternalName(final ExternalLocation[] externalLocations, int programVersion,
			boolean includeNamespace) {
		Symbol symbol = null;
		switch (programVersion) {
			case LATEST:
				Address latestAddress = (externalLocations[LATEST] != null)
						? externalLocations[LATEST].getExternalSpaceAddress()
						: null;
				if (latestAddress != null) {
					symbol = symbolTables[LATEST].getPrimarySymbol(latestAddress);
				}
				break;
			case MY:
				Address myAddress = (externalLocations[MY] != null)
						? externalLocations[MY].getExternalSpaceAddress()
						: null;
				if (myAddress != null) {
					symbol = symbolTables[MY].getPrimarySymbol(myAddress);
				}
				break;
			case ORIGINAL:
				Address originalAddress = (externalLocations[ORIGINAL] != null)
						? externalLocations[ORIGINAL].getExternalSpaceAddress()
						: null;
				if (originalAddress != null) {
					symbol = symbolTables[ORIGINAL].getPrimarySymbol(originalAddress);
				}
				break;
		}
		if (symbol != null) {
			return symbol.getName(includeNamespace);
		}
		return "Unknown"; // ???
	}

	private void resolveAddConflict(ExternalLocation[] externalLocations, int choice,
			TaskMonitor monitor) throws CancelledException {

		// resolve based on user choice (KEEP_LATEST_ADD, KEEP_MY_ADD, KEEP_BOTH_ADDS, or MERGE_BOTH_ADDS.
		switch (choice) {
			case KEEP_LATEST_ADD:
				// RESULT already has LATEST so no external to add.
				adjustIDMapsForReplace(externalLocations, LATEST);
				break;
			case KEEP_MY_ADD:
				// Replace RESULT with MY external.
				merge(externalLocations, KEEP_MY, monitor);
				adjustIDMapsForReplace(externalLocations, MY);
				break;
			case KEEP_BOTH_ADDS:
				// Add MY external giving it a new name if necessary.
				// Add the references from MY to the newly created MY in RESULT.
				ExternalLocation resultExternalLocation =
					addMyExternal(externalLocations[MY], monitor);
				adjustIDMapsForAdd(externalLocations, resultExternalLocation, MY);
				break;
			case MERGE_BOTH_ADDS:
				// Merge LATEST and MY into the RESULT external.
				mergeLatestAndMyForAddConflict(externalLocations, monitor);
				adjustIDMapsForReplace(externalLocations, RESULT);
				break;
			default:
				String message =
					"Resolving External ADD conflict. " + choice + " is not a valid choice.";
				throw new AssertException(message);
		}

	}

	private Namespace resolveNamespace(Program sourceProgram, Namespace sourceNamespace)
			throws DuplicateNameException, InvalidInputException {
		return listingMergeManager.resolveNamespace(sourceProgram, sourceNamespace);
	}

	public ExternalLocation replaceExternalLocation(ExternalLocation toExternalLocation,
			ExternalLocation fromExternalLocation, ProgramMerge programMerge, TaskMonitor monitor)
			throws DuplicateNameException, InvalidInputException, CancelledException {

		// Change the namespace.
		replaceNamespace(toExternalLocation, fromExternalLocation, monitor);

		// Change the label, address and source.
		replaceLocation(toExternalLocation, fromExternalLocation, monitor);

		// TODO: replacing data type on a function seems wrong.  Do we handle the case
		// where we replace a function with a non-function?  

		// Replace the data type.
		replaceExternalDataType(toExternalLocation, fromExternalLocation, monitor);

		// Replace the function.
		return replaceFunction(toExternalLocation, fromExternalLocation, programMerge, monitor);
	}

	private void replaceNamespace(ExternalLocation toExternalLocation,
			ExternalLocation fromExternalLocation, TaskMonitor monitor) {

		Symbol toSymbol = toExternalLocation.getSymbol();
		Symbol fromSymbol = fromExternalLocation.getSymbol();
		Program fromProgram = fromSymbol.getProgram();

		Namespace currentResultNamespace = toSymbol.getParentNamespace();
		Namespace fromNamespace = fromExternalLocation.getParentNameSpace();
		Exception exc = null;
		try {
			// Get the namespace we need from result.
			Namespace desiredResultNamespace = resolveNamespace(fromProgram, fromNamespace);
			if (currentResultNamespace == desiredResultNamespace) {
				return;
			}
			toSymbol.setNamespace(desiredResultNamespace);
		}
		catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
			exc = e;
		}
		if (exc != null) {
			Msg.error(this, "Couldn't replace namespace '" + currentResultNamespace.getName(true) +
				"' with '" + fromNamespace.getName(true) + "'." + exc.getMessage());
		}
	}

	private void replaceLocation(ExternalLocation toExternalLocation,
			ExternalLocation fromExternalLocation, TaskMonitor monitor)
			throws DuplicateNameException, InvalidInputException {

		Address fromAddress = fromExternalLocation.getAddress();
		Address toAddress = toExternalLocation.getAddress();
		boolean addressChanged = !SystemUtilities.isEqual(fromAddress, toAddress);

		String fromLabel = fromExternalLocation.getSource() == SourceType.DEFAULT ? null
				: fromExternalLocation.getLabel();
		String toLabel = toExternalLocation.getSource() == SourceType.DEFAULT ? null
				: toExternalLocation.getLabel();
		if (!SystemUtilities.isEqual(fromLabel, toLabel)) {
			if (fromLabel == null && addressChanged) {
				// need to update address first if switching to null/default label
				toExternalLocation.setAddress(fromAddress);
				addressChanged = false;
			}
			SourceType fromSourceType = fromExternalLocation.getSource();
			toExternalLocation.getSymbol().setName(fromLabel, fromSourceType);
		}
		if (addressChanged) {
			toExternalLocation.setAddress(fromAddress);
		}
	}

	private ExternalLocation replaceFunction(ExternalLocation toExternalLocation,
			ExternalLocation fromExternalLocation, ProgramMerge programMerge, TaskMonitor monitor)
			throws CancelledException, UnsupportedOperationException {

		Function fromFunction = fromExternalLocation.getFunction();
		Function toFunction = toExternalLocation.getFunction();
		if (fromFunction == null) {
			if (toFunction == null) {
				return toExternalLocation;
			}
			DataType dataType = getResultDataType(toExternalLocation);
			Namespace namespace = toExternalLocation.getParentNameSpace();
			String label = toExternalLocation.getLabel();
			// Need to remove the function.
			Symbol toSymbol = toExternalLocation.getSymbol();
			Address addr = toSymbol.getAddress();
			// The location is no longer valid so get the location and restore the data type.
			ExternalManager externalManager = programMerge.getResultProgram().getExternalManager();
			toSymbol.delete(); // This should remove the function and it becomes a label.
			SymbolTable symbolTable = programMerge.getResultProgram().getSymbolTable();
			Symbol symbol = symbolTable.getSymbol(label, addr, namespace);
			ExternalLocation newLocation = externalManager.getExternalLocation(symbol);
			if (newLocation != null && dataType != null && dataType != DataType.DEFAULT) {
				newLocation.setDataType(dataType); // Restore the datatype
			}
			return newLocation;
		}
		if (toFunction == null) {
			toFunction = toExternalLocation.createFunction();
		}
		if (ProgramDiff.equivalentFunctions(fromFunction, toFunction)) {
			return toExternalLocation;
		}
		programMerge.replaceExternalFunction(toFunction, fromFunction, monitor);
		return toFunction.getExternalLocation();
	}

	private ExternalLocation addMyExternal(ExternalLocation myExternalLocation, TaskMonitor monitor)
			throws CancelledException {

		ExternalLocation resultExternalLocation = null;
		try {
			// Add MY external giving it a new name if necessary.
			resultExternalLocation = addExternal(myExternalLocation, monitor);
		}
		catch (DuplicateNameException e) {
			Msg.showError(this, mergeManager.getMergeTool().getToolFrame(),
				"Error Merging External Location", "Couldn't merge external '" +
					myExternalLocation.getLabel() + "'. " + e.getMessage());
		}
		catch (InvalidInputException e) {
			Msg.showError(this, mergeManager.getMergeTool().getToolFrame(),
				"Error Merging External Location", "Couldn't merge external '" +
					myExternalLocation.getLabel() + "'. " + e.getMessage());
		}
		return resultExternalLocation;
	}

	/**
	 * Method called for merging an external that was added in LATEST and one that was added in MY.
	 * @param externalLocations RESULT, LATEST, and MY locations and ORIGINAL is null.
	 * @param monitor task monitor for progress and cancelling.
	 * @throws CancelledException if user cancels the merge.
	 */
	private void mergeLatestAndMyForAddConflict(ExternalLocation[] externalLocations,
			TaskMonitor monitor) throws CancelledException {
		// Merge LATEST and MY into the RESULT external.
		// This is a merge of LATEST and MY added externals, so every difference is a conflict.
		int latestMyChanges =
			getBasicExternalDiffs(externalLocations[LATEST], externalLocations[MY]);

		int detailConflictFlags =
			latestMyChanges & (EXTERNAL_NAMESPACE | EXTERNAL_LABEL | EXTERNAL_ADDRESS);
//			(EXTERNAL_NAMESPACE | EXTERNAL_LABEL | EXTERNAL_SOURCE_TYPE | EXTERNAL_ADDRESS);
		if ((detailConflictFlags & EXTERNAL_ADDRESS) != 0) {
			Address latestAddress = externalLocations[LATEST].getAddress();
			Address myAddress = externalLocations[MY].getAddress();
			if (latestAddress != null && myAddress == null) {
				// Want to set the external to LATEST address, which it already is, so nothing to do.
				detailConflictFlags &= ~EXTERNAL_ADDRESS; // Turn off the ADDRESS conflict flag.
			}
			else if (latestAddress == null && myAddress != null) {
				// Set the external to MY address.
				mergeExternalDetail(EXTERNAL_ADDRESS, externalLocations[RESULT],
					externalLocations[MY], monitor);
				detailConflictFlags &= ~EXTERNAL_ADDRESS; // Turn off the ADDRESS conflict flag.
			}
		}
		if (detailConflictFlags != 0) {
			saveExternalDetailConflict(externalLocations, detailConflictFlags);
		}

		// Check Data Type vs Function and for just data type differences.
		Address myExternalAddress = externalLocations[MY].getExternalSpaceAddress();

		DataType latestDataType = getResultDataType(externalLocations[LATEST]);
		DataType myDataType = getResultDataType(externalLocations[MY]);
		boolean latestHasDataType =
			(latestDataType != null) && (latestDataType != DataType.DEFAULT);
		boolean myHasDataType = (myDataType != null) && (myDataType != DataType.DEFAULT);
		boolean differentDataTypes =
			latestHasDataType && myHasDataType && (latestMyChanges & EXTERNAL_DATA_TYPE) != 0;
		boolean latestIsFunction = externalLocations[LATEST].isFunction();
		boolean myIsFunction = externalLocations[MY].isFunction();
		boolean differentFunctions =
			latestIsFunction && myIsFunction && (latestMyChanges & EXTERNAL_FUNCTION) != 0;
		// If the data types are different, then did a change to one conflict with a
		// data type or function change to the other?
		if (differentDataTypes) {
			// Conflict: Both set the data type differently.
			saveExternalDataTypeConflict(myExternalAddress);
		}
		if (differentFunctions) {
			// Conflict: Both created different functions.
			determineDetailedFunctionConflicts(externalLocations, monitor);
		}
		if ((latestIsFunction && !latestHasDataType && !myIsFunction && myHasDataType) ||
			(myIsFunction && !myHasDataType && !latestIsFunction && latestHasDataType)) {
			// Conflict: LATEST is function and MY is label with data type
			//   - or -  MY is function and LATEST is label with data type.
			saveExternalFunctionVersusDataTypeConflict(myExternalAddress);
		}
		else {
			if (myHasDataType && !latestHasDataType) {
				// Auto Merge My data type change.
				replaceExternalDataType(externalLocations[RESULT], externalLocations[MY], monitor);
			}
			if (myIsFunction && !latestIsFunction) {
				// Auto Merge MY external function changes.
				replaceFunction(externalLocations[RESULT], externalLocations[MY], getMergeMy(),
					monitor);
			}
		}
	}

	class ExternalAddConflictChangeListener implements ChangeListener {
		ExternalLocation[] externalLocations;
		TaskMonitor monitor;
		ConflictPanel vPanel;

		ExternalAddConflictChangeListener(final ExternalLocation[] externalLocations,
				final ConflictPanel vPanel, final TaskMonitor monitor) {
			this.externalLocations = externalLocations;
			this.monitor = monitor;
			this.vPanel = vPanel;
		}

		@Override
		public void stateChanged(ChangeEvent e) {
			// Add conflict choices are KEEP_LATEST_ADD, KEEP_MY_ADD, KEEP_BOTH_ADDS, or MERGE_BOTH_ADDS.
			ResolveConflictChangeEvent re = (ResolveConflictChangeEvent) e;
			final int choice = re.getChoice();
			conflictListener = () -> {
				try {
					resolveAddConflict(externalLocations, choice, monitor);
				}
				catch (CancelledException e1) {
					// Do nothing here and let a higher level detect and catch the Cancel.
				}
			};

			adjustApply();
		}

		void adjustApply() {
			if (mergeManager != null) {
				mergeManager.setApplyEnabled(vPanel.allChoicesAreResolved());
			}
		}
	}

	class ExternalDataTypeConflictChangeListener implements ChangeListener {
		ExternalLocation[] externalLocations;
		TaskMonitor monitor;
		ConflictPanel vPanel;

		ExternalDataTypeConflictChangeListener(final ExternalLocation[] externalLocations,
				final ConflictPanel vPanel, final TaskMonitor monitor) {
			this.externalLocations = externalLocations;
			this.monitor = monitor;
			this.vPanel = vPanel;
		}

		@Override
		public void stateChanged(ChangeEvent e) {
			ResolveConflictChangeEvent re = (ResolveConflictChangeEvent) e;
			int choice = re.getChoice();
			try {
				mergeExternalDataType(externalLocations, choice, monitor);
				refreshResultPanel(externalLocations);
			}
			catch (CancelledException e1) {
				// Do nothing here and let a higher level detect and catch the Cancel.
			}
			adjustApply();
		}

		void adjustApply() {
			if (mergeManager != null) {
				mergeManager.setApplyEnabled(vPanel.allChoicesAreResolved());
			}
		}
	}

	class ExternalFunctionVsDataTypeConflictChangeListener implements ChangeListener {
		ExternalLocation[] externalLocations;
		TaskMonitor monitor;
		ConflictPanel vPanel;

		ExternalFunctionVsDataTypeConflictChangeListener(final ExternalLocation[] externalLocations,
				final ConflictPanel vPanel, final TaskMonitor monitor) {
			this.externalLocations = externalLocations;
			this.monitor = monitor;
			this.vPanel = vPanel;
		}

		@Override
		public void stateChanged(ChangeEvent e) {
			ResolveConflictChangeEvent re = (ResolveConflictChangeEvent) e;
			int choice = re.getChoice();
			try {
				merge(externalLocations, choice, monitor);
				refreshResultPanel(externalLocations);
			}
			catch (CancelledException e1) {
				// Do nothing here and let a higher level detect and catch the Cancel.
			}
			adjustApply();
		}

		void adjustApply() {
			if (mergeManager != null) {
				mergeManager.setApplyEnabled(vPanel.allChoicesAreResolved());
			}
		}
	}

	class ExternalRemoveFunctionConflictChangeListener implements ChangeListener {
		ExternalLocation[] externalLocations;
		TaskMonitor monitor;
		ConflictPanel vPanel;

		ExternalRemoveFunctionConflictChangeListener(final ExternalLocation[] externalLocations,
				final ConflictPanel vPanel, final TaskMonitor monitor) {
			this.externalLocations = externalLocations;
			this.monitor = monitor;
			this.vPanel = vPanel;
		}

		@Override
		public void stateChanged(ChangeEvent e) {
			ResolveConflictChangeEvent re = (ResolveConflictChangeEvent) e;
			int choice = re.getChoice();
			try {
				mergeFunction(externalLocations, choice, monitor);
				refreshResultPanel(externalLocations);
			}
			catch (CancelledException e1) {
				// Do nothing here and let a higher level detect and catch the Cancel.
			}
			adjustApply();
		}

		void adjustApply() {
			if (mergeManager != null) {
				mergeManager.setApplyEnabled(vPanel.allChoicesAreResolved());
			}
		}
	}

	class ExternalRemoveConflictChangeListener implements ChangeListener {
		ExternalLocation[] externalLocations;
		TaskMonitor monitor;
		ConflictPanel vPanel;

		ExternalRemoveConflictChangeListener(final ExternalLocation[] externalLocations,
				final ConflictPanel vPanel, final TaskMonitor monitor) {
			this.externalLocations = externalLocations;
			this.monitor = monitor;
			this.vPanel = vPanel;
		}

		@Override
		public void stateChanged(ChangeEvent e) {
			ResolveConflictChangeEvent re = (ResolveConflictChangeEvent) e;
			int choice = re.getChoice();
			try {
				merge(externalLocations, choice, monitor);
				refreshResultPanel(externalLocations);
			}
			catch (CancelledException e1) {
				// Do nothing here and let a higher level detect and catch the Cancel.
			}
			adjustApply();
		}

		void adjustApply() {
			if (mergeManager != null) {
				mergeManager.setApplyEnabled(vPanel.allChoicesAreResolved());
			}
		}
	}

	class ExternalDetailChangeListener implements ChangeListener {
		int type;
		ExternalLocation[] locations;
		TaskMonitor monitor;
		VariousChoicesPanel vPanel;

		ExternalDetailChangeListener(final int type, final ExternalLocation[] locations,
				final VariousChoicesPanel vPanel, final TaskMonitor monitor) {
			this.type = type;
			this.locations = locations;
			this.monitor = monitor;
			this.vPanel = vPanel;
		}

		@Override
		public void stateChanged(ChangeEvent e) {
			ResolveConflictChangeEvent re = (ResolveConflictChangeEvent) e;
			int choice = re.getChoice();
			try {
				mergeBasicExternalDetail(type, locations, getOptionForChoice(choice), monitor);
			}
			catch (CancelledException e1) {
				// Do nothing here and let a higher level detect and catch the Cancel.
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

	protected void mergeBasicExternalDetail(int type, ExternalLocation[] externalLocations,
			int currentChosenOption, TaskMonitor monitor) throws CancelledException {

		ExternalLocation externalLocation = null;
		switch (currentChosenOption) {
			case KEEP_LATEST:
				externalLocation = externalLocations[LATEST];
				break;
			case KEEP_MY:
				externalLocation = externalLocations[MY];
				break;
			case KEEP_ORIGINAL:
			default:
				throw new AssertException("Can only merge external detail from Latest or My.");
		}

		mergeExternalDetail(type, externalLocations[RESULT], externalLocation, monitor);
	}

	public void mergeFunction(ExternalLocation[] externalLocations, int currentChosenOption,
			TaskMonitor monitor) throws CancelledException, UnsupportedOperationException {

		switch (currentChosenOption) {
			case KEEP_LATEST:
				replaceFunction(externalLocations[RESULT], externalLocations[LATEST],
					getMergeLatest(), monitor);
				break;
			case KEEP_MY:
				replaceFunction(externalLocations[RESULT], externalLocations[MY], getMergeMy(),
					monitor);
				break;
			case KEEP_ORIGINAL:
				replaceFunction(externalLocations[RESULT], externalLocations[ORIGINAL],
					getMergeOriginal(), monitor);
			default:
				throw new AssertException("Can only merge external detail from Latest or My.");
		}
	}

	/**
	 * Merges the entire external so that it will match the external as it is in the program
	 * indicated by the chosen option.
	 * @param externalLocations the external locations for the external in Latest, My, and Original.
	 * (Any of these locations can be null if the external is not in that program.)
	 * @param chosenConflictOption ListingMergeConstant (KEEP_LATEST, KEEP_MY, KEEP_ORIGINAL)
	 * indicating which program the resulting external should become.
	 * @param monitor the task monitor for feedback and cancelling the merge.
	 * @throws CancelledException if the user cancels the merge.
	 * @throws InvalidInputException
	 * @throws DuplicateNameException
	 */
	private void merge(ExternalLocation[] externalLocations, int chosenConflictOption,
			TaskMonitor monitor) throws CancelledException {

		try {
			switch (chosenConflictOption) {
				case KEEP_LATEST:
					mergeLatest(externalLocations, monitor);
					break;
				case KEEP_MY:
					mergeMy(externalLocations, monitor);
					break;
				case KEEP_ORIGINAL:
					mergeOriginal(externalLocations, monitor);
					break;
			}
		}
		catch (DuplicateNameException e) {
			Msg.showError(this, mergeManager.getMergeTool().getToolFrame(),
				"Error Merging External Location", e.getMessage());
		}
		catch (InvalidInputException e) {
			Msg.showError(this, mergeManager.getMergeTool().getToolFrame(),
				"Error Merging External Location", e.getMessage());
		}
	}

	private void mergeLatest(ExternalLocation[] externalLocations, TaskMonitor monitor)
			throws DuplicateNameException, InvalidInputException, CancelledException {

		if (externalLocations[LATEST] == null) {
			removeExternal(programs[ORIGINAL], externalLocations[ORIGINAL]);
			externalLocations[RESULT] = null;
			adjustIDMapsForRemove(externalLocations, LATEST);
		}
		else if (externalLocations[RESULT] == null) {
			// Don't have it in result so add LATEST.
			ExternalLocation resultExternalLocation =
				addExternal(externalLocations[LATEST], mergeLatest, monitor);
			externalLocations[RESULT] = resultExternalLocation;
			adjustIDMapsForAdd(externalLocations, resultExternalLocation, LATEST);
		}
		else {
			latestAddressTranslator.setPair(externalLocations[RESULT].getExternalSpaceAddress(),
				externalLocations[LATEST].getExternalSpaceAddress());
			ExternalLocation resultExternalLocation = replaceExternalLocation(
				externalLocations[RESULT], externalLocations[LATEST], getMergeLatest(), monitor);
			externalLocations[RESULT] = resultExternalLocation;
			adjustIDMapsForReplace(externalLocations, LATEST);
		}
	}

	private void mergeMy(ExternalLocation[] externalLocations, TaskMonitor monitor)
			throws DuplicateNameException, InvalidInputException, CancelledException {

		if (externalLocations[MY] == null) {
			removeExternal(programs[ORIGINAL], externalLocations[ORIGINAL]);
			externalLocations[RESULT] = null;
			adjustIDMapsForRemove(externalLocations, MY);
		}
		else if (externalLocations[RESULT] == null) {
			// Don't have it in result so add MY.
			ExternalLocation resultExternalLocation =
				addExternal(externalLocations[MY], mergeMy, monitor);
			externalLocations[RESULT] = resultExternalLocation;
			adjustIDMapsForAdd(externalLocations, resultExternalLocation, MY);
		}
		else {
			myAddressTranslator.setPair(externalLocations[RESULT].getExternalSpaceAddress(),
				externalLocations[MY].getExternalSpaceAddress());
			ExternalLocation resultExternalLocation = replaceExternalLocation(
				externalLocations[RESULT], externalLocations[MY], getMergeMy(), monitor);
			externalLocations[RESULT] = resultExternalLocation;
			adjustIDMapsForReplace(externalLocations, MY);
		}
	}

	private void mergeOriginal(ExternalLocation[] externalLocations, TaskMonitor monitor)
			throws DuplicateNameException, InvalidInputException, CancelledException {

		if (externalLocations[ORIGINAL] == null) {
			Program fromProgram = programs[LATEST];
			ExternalLocation fromLocation = externalLocations[LATEST];
			if (fromLocation == null) {
				fromProgram = programs[MY];
				fromLocation = externalLocations[MY];
			}
			if (fromLocation == null) {
				return; // Shouldn't get here. LATEST or MY should have a value.
			}
			removeExternal(fromProgram, fromLocation);
			externalLocations[RESULT] = null;
			adjustIDMapsForRemove(externalLocations, ORIGINAL);
		}
		else if (externalLocations[RESULT] == null) {
			// Don't have it in result so add ORIGINAL.
			ExternalLocation resultExternalLocation =
				addExternal(externalLocations[ORIGINAL], mergeOriginal, monitor);
			externalLocations[RESULT] = resultExternalLocation;
			adjustIDMapsForAdd(externalLocations, resultExternalLocation, ORIGINAL);
		}
		else {
			originalAddressTranslator.setPair(externalLocations[RESULT].getExternalSpaceAddress(),
				externalLocations[ORIGINAL].getExternalSpaceAddress());
			ExternalLocation resultExternalLocation =
				replaceExternalLocation(externalLocations[RESULT], externalLocations[ORIGINAL],
					getMergeOriginal(), monitor);
			externalLocations[RESULT] = resultExternalLocation;
			adjustIDMapsForReplace(externalLocations, ORIGINAL);
		}
	}

	private void adjustIDMapsForRemove(ExternalLocation[] externalLocations, int chosenExternal) {

		long originalID =
			(externalLocations[ORIGINAL] != null) ? externalLocations[ORIGINAL].getSymbol().getID()
					: -1;
		if (originalID != -1) {
			originalResolvedSymbols.put(originalID, -1);
		}
		switch (chosenExternal) {
			case LATEST:
				long myID = resolveMyIDFromOriginalID(originalID);
				myResolvedSymbols.put(myID, -1);
				break;
			case MY:
				long latestID = resolveLatestIDFromOriginalID(originalID);
				latestResolvedSymbols.put(latestID, -1);
				break;
			case ORIGINAL:
				long latestID2 = (externalLocations[LATEST] != null)
						? externalLocations[LATEST].getSymbol().getID()
						: -1;
				if (latestID2 != -1) {
					latestResolvedSymbols.put(latestID2, -1);
				}
				long myID2 =
					(externalLocations[MY] != null) ? externalLocations[MY].getSymbol().getID()
							: -1;
				if (myID2 != -1) {
					myResolvedSymbols.put(myID2, -1);
				}
				break;
			default:
				Msg.error(this, "    ERROR :  UNRECOGNIZED chosenExternal=" + chosenExternal + ".");
				return;
		}
	}

	private void adjustIDMapsForAdd(ExternalLocation[] externalLocations,
			ExternalLocation resultExternalLocation, int chosenExternal) {

		long latestID =
			(externalLocations[LATEST] != null) ? externalLocations[LATEST].getSymbol().getID()
					: -1;
		long myID =
			(externalLocations[MY] != null) ? externalLocations[MY].getSymbol().getID() : -1;
		long originalID =
			(externalLocations[ORIGINAL] != null) ? externalLocations[ORIGINAL].getSymbol().getID()
					: -1;

		long resultID = resultExternalLocation.getSymbol().getID();
		long chosenID = externalLocations[chosenExternal].getSymbol().getID();
		boolean isChange = originalID != -1;
		switch (chosenExternal) {
			case LATEST:
//				if (chosenID != resultID) {
				latestResolvedSymbols.put(chosenID, resultID);

				if (isChange && myID == originalID) {
					myResolvedSymbols.put(myID, resultID);
				}
//				}
//				else if (latestResolvedSymbols.contains(chosenID)) {
//					latestResolvedSymbols.remove(chosenID);
//				}
				break;
			case MY:
//				if (chosenID != resultID) {
				myResolvedSymbols.put(chosenID, resultID);

				if (isChange && latestID == originalID) {
					latestResolvedSymbols.put(latestID, resultID);
				}
//				}
//				else if (myResolvedSymbols.contains(chosenID)) {
//					myResolvedSymbols.remove(chosenID);
//				}
				break;
			case ORIGINAL: // Restoring the original.
				if (chosenID != resultID) {
					originalResolvedSymbols.put(chosenID, resultID);

					if (isChange) {
						if (latestID != -1) {
							latestResolvedSymbols.put(latestID, resultID);
						}
						if (myID != -1) {
							myResolvedSymbols.put(myID, resultID);
						}
					}
				}
				else {
					if (latestID != -1) {
//						if (latestID != resultID) {
						latestResolvedSymbols.put(latestID, resultID);
//						}
//						else if (latestResolvedSymbols.contains(latestID)) {
//							latestResolvedSymbols.remove(latestID);
//						}
					}
					if (myID != -1) {
//						if (myID != resultID) {
						myResolvedSymbols.put(myID, resultID);
//						}
//						else if (myResolvedSymbols.contains(myID)) {
//							myResolvedSymbols.remove(myID);
//						}
					}
				}
				break;
			default:
				Msg.error(this, "    ERROR :  UNRECOGNIZED chosenExternal=" + chosenExternal + ".");
		}
		if (isChange) {
			originalResolvedSymbols.put(originalID, resultID);
		}
	}

	private void adjustIDMapsForReplace(ExternalLocation[] externalLocations, int chosenExternal) {

		long resultID =
			(externalLocations[RESULT] != null) ? externalLocations[RESULT].getSymbol().getID()
					: -1;
		long latestID =
			(externalLocations[LATEST] != null) ? externalLocations[LATEST].getSymbol().getID()
					: -1;
		long myID =
			(externalLocations[MY] != null) ? externalLocations[MY].getSymbol().getID() : -1;
		long originalID =
			(externalLocations[ORIGINAL] != null) ? externalLocations[ORIGINAL].getSymbol().getID()
					: -1;
		if (originalID != -1) {
//			if (originalID != resultID) {
			originalResolvedSymbols.put(originalID, resultID);
//			}
//			else if (originalResolvedSymbols.contains(originalID)) {
//				originalResolvedSymbols.remove(originalID);
//			}
		}
		if (latestID != -1) {
//			if (latestID != resultID) {
			latestResolvedSymbols.put(latestID, resultID);
//			}
//			else if (latestResolvedSymbols.contains(latestID)) {
//				latestResolvedSymbols.remove(latestID);
//			}
		}
		if (myID != -1) {
//			if (myID != resultID) {
			myResolvedSymbols.put(myID, resultID);
//			}
//			else if (myResolvedSymbols.contains(myID)) {
//				myResolvedSymbols.remove(myID);
//			}
		}
	}

	public void refreshResultPanel(ExternalLocation[] externalLocations) {
		Address resultAddress = (externalLocations[RESULT] != null)
				? externalLocations[RESULT].getExternalSpaceAddress()
				: null;
		Address latestAddress = (externalLocations[LATEST] != null)
				? externalLocations[LATEST].getExternalSpaceAddress()
				: null;
		Address myAddress =
			(externalLocations[MY] != null) ? externalLocations[MY].getExternalSpaceAddress()
					: null;
		Address originalAddress = (externalLocations[ORIGINAL] != null)
				? externalLocations[ORIGINAL].getExternalSpaceAddress()
				: null;
		mergeManager.refreshListingMergePanel(resultAddress, latestAddress, myAddress,
			originalAddress);
	}

	private void removeExternal(long resultExternalSymbolID) {
		Symbol externalSymbol = symbolTables[RESULT].getSymbol(resultExternalSymbolID);
		if (!externalSymbol.isExternal()) {
			throw new AssertException("Symbol to remove isn't an external as expected.");
		}
		ExternalLocation resultExternalLocation =
			externalManagers[RESULT].getExternalLocation(externalSymbol);
		if (resultExternalLocation == null) {
			return;
		}
		if (resultExternalLocation.isFunction()) {
			Symbol symbol = resultExternalLocation.getSymbol();
			Address addr = symbol.getAddress();
			symbol.delete();
			// Re-acquire the external location which should now be an external label.
			Symbol resultSymbol = symbolTables[RESULT].getPrimarySymbol(addr);
			resultExternalLocation = externalManagers[RESULT].getExternalLocation(resultSymbol);
			if (resultExternalLocation == null) {
				throw new AssertException("Why isn't there an external label.");
			}
		}
		Symbol symbol = resultExternalLocation.getSymbol();
		if (symbol != null) {
			symbol.delete();
		}
	}

	/**
	 * Removes the indicated external from the result program.
	 * @param sourceProgram the program that is the source of the external location
	 * (Either Latest, My, or Original program.)
	 * @param sourceExternalLocation the external location that indicates which external
	 * is to be removed from the result. (External is from Latest, My, or Original program.)
	 */
	private void removeExternal(Program sourceProgram, ExternalLocation sourceExternalLocation) {
		ExternalLocation resultExternalLocation = SimpleDiffUtility.getMatchingExternalLocation(
			sourceProgram, sourceExternalLocation, programs[RESULT], false);
		if (resultExternalLocation == null) {
			return;
		}
		Address externalSpaceAddress = resultExternalLocation.getExternalSpaceAddress();
		if (resultExternalLocation.isFunction()) {
			functionManagers[RESULT].removeFunction(externalSpaceAddress);
			// See if the location is now just a label.
			resultExternalLocation = SimpleDiffUtility.getMatchingExternalLocation(sourceProgram,
				sourceExternalLocation, programs[RESULT], false);
			if (resultExternalLocation == null) {
				return;
			}
		}
		Symbol symbol = resultExternalLocation.getSymbol();
		if (symbol != null) {
			symbol.delete();
		}
	}

	@Override
	ProgramMerge getMergeLatest() {
		return mergeLatest;
	}

	@Override
	ProgramMerge getMergeMy() {
		return mergeMy;
	}

	@Override
	ProgramMerge getMergeOriginal() {
		return mergeOriginal;
	}

	private void setupAddConflictPanel(final ExternalAddConflictPanel addConflictPanel,
			final JPanel conflictPanel, final ExternalLocation latestLocation,
			ExternalLocation myLocation, final TaskMonitor monitor) {

		this.currentMonitor = monitor;
		this.currentConflictPanel = (ConflictPanel) conflictPanel;

		try {
			SwingUtilities.invokeAndWait(() -> addConflictPanel.setBottomComponent(conflictPanel));
		}
		catch (InterruptedException e) {
			Msg.showError(this, null, "Error Displaying Conflict Panel", e);
			return;
		}
		catch (InvocationTargetException e) {
			Msg.showError(this, null, "Error Displaying Conflict Panel", e);
			return;
		}
		if (mergeManager != null) {
			mergeManager.setApplyEnabled(false);
			addConflictPanel.setConflictInfo(conflictIndex, latestLocation, myLocation);
			HelpLocation helpLocation = null;

			// Need to remove the multi-listing panel since add conflict has its own panel.
			mergeManager.removeListingMergePanel();

			// Show the add conflict panel.
			mergeManager.showComponent(addConflictPanel, "ExternalAddConflictPanel", helpLocation);
		}
		// block until the user either cancels or hits the "Apply" button
		// on the merge dialog...
		// when the "Apply" button is hit, get the user's selection
		// and continue.

		// Remove the add conflict panel so listing can once again display without interference.
		mergeManager.removeComponent(addConflictPanel);
	}

	private void setupConflictPanel(final ListingMergePanel listingPanel,
			final ConflictPanel conflictPanel, final ExternalLocation[] externalLocations,
			final TaskMonitor monitor) {

		if (conflictPanel == null) {
			Msg.showError(this, null, "Error Displaying Conflict Panel",
				"The conflict panel could not be created.");
			return;
		}

		this.currentMonitor = monitor;
		this.currentConflictPanel = conflictPanel;

		try {
			SwingUtilities.invokeAndWait(() -> listingPanel.setBottomComponent(conflictPanel));
			SwingUtilities.invokeLater(() -> {
				// Set background color of function entry point code unit
//					listingPanel.clearAllBackgrounds();
//					listingPanel.paintAllBackgrounds(new AddressSet(resultAddressFactory,
//						entryPtAddr, entryPtAddr));
			});
		}
		catch (InterruptedException e) {
			Msg.showError(this, null, "Error Displaying Conflict Panel", e);
			return;
		}
		catch (InvocationTargetException e) {
			Msg.showError(this, null, "Error Displaying Conflict Panel", e);
			return;
		}
		if (mergeManager != null) {
			mergeManager.setApplyEnabled(false);

			Address resultAddress = (externalLocations[RESULT] != null)
					? externalLocations[RESULT].getExternalSpaceAddress()
					: null;
			Address latestAddress = (externalLocations[LATEST] != null)
					? externalLocations[LATEST].getExternalSpaceAddress()
					: null;
			Address myAddress =
				(externalLocations[MY] != null) ? externalLocations[MY].getExternalSpaceAddress()
						: null;
			Address originalAddress = (externalLocations[ORIGINAL] != null)
					? externalLocations[ORIGINAL].getExternalSpaceAddress()
					: null;
			mergeManager.showListingMergePanel(resultAddress, latestAddress, myAddress,
				originalAddress);
		}
		// block until the user either cancels or hits the "Apply" button
		// on the merge dialog...
		// when the "Apply" button is hit, get the user's selection
		// and continue.
	}

	@Override
	protected void saveFunctionDetailConflict(Function[] functions, int type) {

		Address myEntry = functions[MY].getEntryPoint();
		int bits = 0;
		try {
			bits = funcConflicts.get(myEntry);
		}
		catch (NoValueException e) {
			// It's ok if there isn't one, but we want its bits if there is.
		}
		bits |= type;
		funcConflicts.put(myEntry, bits);
		funcSet.addRange(myEntry, myEntry);
	}

	private String[] getExternalInfo(final ExternalLocation[] externalLocations,
			int programVersion) {

		Address latestAddress = (externalLocations[LATEST] != null)
				? externalLocations[LATEST].getExternalSpaceAddress()
				: null;
		Address myAddress =
			(externalLocations[MY] != null) ? externalLocations[MY].getExternalSpaceAddress()
					: null;
		Address originalAddress = (externalLocations[ORIGINAL] != null)
				? externalLocations[ORIGINAL].getExternalSpaceAddress()
				: null;

		String[] info = new String[] { "", "", "", "", "", "", "" };

		String versionName = RESULT_TITLE;
		String externalName = "";
		String externalType = "label";
		String actionString = "Keep";
		ExternalLocation externalLocation = null;
		Program pgm = programs[RESULT];

		switch (programVersion) {
			case HEADER:
				return new String[] { "Option", "Name", "Type", "Address", "DataType", "Source",
					"Function" };
			case LATEST:
				pgm = programs[LATEST];
				versionName = LATEST_TITLE;
				if (latestAddress == null) {
					actionString = "Remove";
					break;
				}
				externalLocation = getExternalLocation(latestAddress, LATEST);
				break;
			case MY:
				pgm = programs[MY];
				versionName = MY_TITLE;
				if (myAddress == null) {
					actionString = "Remove";
					break;
				}
				externalLocation = getExternalLocation(myAddress, MY);
				break;
			case ORIGINAL:
				pgm = programs[ORIGINAL];
				versionName = ORIGINAL_TITLE;
				if (originalAddress == null) {
					actionString = "No";
					break;
				}
				externalLocation = getExternalLocation(originalAddress, ORIGINAL);
				break;
		}

		info[0] = actionString + " '" + versionName + "'.";
		if (externalLocation != null) {
			Symbol symbol = externalLocation.getSymbol();
			externalName = symbol.getName(true);
			if (symbol.getSymbolType() == SymbolType.FUNCTION) {
				externalType = "function";
			}
			Address externalAddress = externalLocation.getAddress();
			DataType dataType = getResultDataType(externalLocation);
			SourceType sourceType = externalLocation.getSource();
			Function function = externalLocation.getFunction();

			info[1] = externalName;
			info[2] = externalType;
			info[3] = DiffUtility.getUserToAddressString(pgm, externalAddress);
			if (dataType != null) {
				info[4] = dataType.getDisplayName();
			}
			info[5] = sourceType.getDisplayString();
			if (function != null) {
				info[6] = function.getPrototypeString(true, true);
			}
		}
		return info;
	}

	private ExternalLocation getExternalLocation(Address externalSpaceAddress, int version) {
		if (externalSpaceAddress == null || !externalSpaceAddress.isExternalAddress()) {
			return null;
		}
		Symbol symbol = symbolTables[version].getPrimarySymbol(externalSpaceAddress);
		if (symbol == null) {
			return null;
		}
		ExternalLocation externalLocation = externalManagers[version].getExternalLocation(symbol);
		return externalLocation;
	}

	private StringBuffer getRenamedConflictsInfo() {
		StringBuffer buf = new StringBuffer();
		Iterator<Long> iter = renamedConflictIDs.iterator();
		boolean hasSome = iter.hasNext();
		if (hasSome) {
			buf.append("The following externals were renamed to avoid conflicts: \n");
		}
		while (iter.hasNext()) {
			long id = iter.next().longValue();
			Symbol s = symbolTables[RESULT].getSymbol(id);
			buf.append(s.getName(true) + "\n");
		}
		if (hasSome) {
			buf.append("\n");
		}
		return buf;
	}

	@Override
	public String getConflictType() {
		return CONFLICT_TYPE;
	}

	@Override
	public int getNumConflictsResolved() {
		// Used by listing's apply() method, but we count each conflict prompt as 1.
		return 1;
	}

	@Override
	public boolean hasConflict(Address addr) {
		// Not Used. ExternalFunctionMerger gets called directly instead of by default methods.
		return false;
	}

	@Override
	public int getConflictCount(Address addr) {
		// Not Used. ExternalFunctionMerger gets called directly instead of by default methods.
		return 0;
	}

	@Override
	public void mergeConflicts(ListingMergePanel listingPanel, Address addr, int conflictOption,
			TaskMonitor monitor) throws CancelledException, MemoryAccessException {
		// Not Used. ExternalFunctionMerger gets called directly instead of by default methods.
	}

	@Override
	public AddressSetView getConflicts() {
		// Not Used. ExternalFunctionMerger gets called directly instead of by default methods.
		return null;
	}

	private interface ConflictListener {
		public void resolveConflict();
	}

	@Override
	protected String getInfoTitle() {
		return INFO_TITLE;
	}

	@Override
	protected String getErrorTitle() {
		return ERROR_TITLE;
	}

	private String getVersionName(int programVersion) {
		switch (programVersion) {
			case RESULT:
				return RESULT_TITLE;
			case LATEST:
				return LATEST_TITLE;
			case MY:
				return MY_TITLE;
			case ORIGINAL:
				return ORIGINAL_TITLE;
			default:
				return "UNKNOWN";
		}
	}

	@Override
	public void dispose() {
		// The program change sets.
		latestChanges = null;
		myChanges = null;

		// Symbol ID maps for externals that changed from label to function via a remove/add.
		originalToLatestHash = null;
		latestToOriginalHash = null;
		originalToMyHash = null;
		myToOriginalHash = null;

		originalResolvedSymbols = null; // Maps original symbolID to result symbolID
		latestResolvedSymbols = null; // Maps latest symbolID to result symbolID
		myResolvedSymbols = null; // Maps my symbolID to result symbolID

		latestAddIDs = null; // Added Latest IDs only (initially adds and changes)
		latestRemovedOriginalIDs = null; // Latest Removed Original IDs only (initially adds and changes)
		latestModifiedIDs = null; // Changed Latest IDs only
		myAddIDs = null; // Added My IDs only (initially adds and changes)
		myRemovedOriginalIDs = null; // My Removed Original IDs only (initially adds and changes)
		myModifiedIDs = null; // Changed My IDs only
		removeConflictIDs = null; // IDs from ORIGINAL where there are external location removal conflicts.
		removeFunctionConflictIDs = null; // IDs from ORIGINAL where there are external function removal conflicts.
		renamedConflictIDs = null; // result ID for symbol that was renamed to avoid a conflict.

		symbolTables = null;
		externalManagers = null;
		conflictListener = null;

		// Address sets.
		latestExternalSet = null;
		myExternalSet = null;

		// The conflict sets.
		externalDetailConflicts = null;
		externalDataTypeConflicts = null;
		externalFunctionVersusDataTypeConflicts = null;
		externalAddConflicts = null;

		// The ProgramMerge instances.
		mergeMy = null;
		mergeLatest = null;
		mergeOriginal = null;
		// The translators that get used by the ProgramMerge instances.
		myAddressTranslator = null;
		latestAddressTranslator = null;
		originalAddressTranslator = null;

		super.dispose();
	}
}
