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

import javax.swing.SwingUtilities;

import ghidra.app.merge.*;
import ghidra.app.merge.tool.ListingMergePanel;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramChangeSet;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Manages program listing changes and conflicts between the latest versioned
 * program (LATEST) and the modified program (MY) being checked into version control.
 * <br>Listing changes include:
 * <ul>
 * <li>bytes</li>
 * <li>code units [instructions and data]</li>
 * <li>equates</li>
 * <li>functions</li>
 * <li>symbols</li>
 * <li>references [memory, stack, and external]</li>
 * <li>comments [plate, pre, end-of-line, repeatable, and post]</li>
 * <li>properties</li>
 * <li>bookmarks</li>
 * </ul>
 */
public class ListingMergeManager implements MergeResolver, ListingMergeConstants {

	private static String[] LISTING_PHASE = new String[] { "Listing" };
	private static String[] CODE_UNITS_PHASE =
		new String[] { "Listing", CodeUnitMerger.CODE_UNITS_PHASE };
	private static String[] EXTERNALS_PHASE =
		new String[] { "Listing", ExternalFunctionMerger.EXTERNALS_PHASE };
	private static String[] FUNCTIONS_PHASE =
		new String[] { "Listing", FunctionMerger.FUNCTIONS_PHASE };
	private static String[] SYMBOLS_PHASE = new String[] { "Listing", SymbolMerger.SYMBOLS_PHASE };
	private static String[] ADDRESS_BASED_PHASE = new String[] { "Listing",
		EquateMerger.EQUATES_PHASE + ", " + UserDefinedPropertyMerger.USER_DEFINED_PHASE + ", " +
			ReferenceMerger.REFERENCES_PHASE + ", " + BookmarkMerger.BOOKMARKS_PHASE + " & " +
			CommentMerger.COMMENTS_PHASE };
	private static final int RESULT = MergeConstants.RESULT;
	private static final int LATEST = MergeConstants.LATEST;
	private static final int MY = MergeConstants.MY;
	private static final int ORIGINAL = MergeConstants.ORIGINAL;

	/** conflictOption CANCELED, ASK_USER, PICK_ORIGINAL, PICK_LATEST, PICK_MY */
	private int conflictOption = ASK_USER;

	ProgramMultiUserMergeManager mergeManager; // overall program version merge manager
	private ListingMerger currentMerger;

	private ExternalFunctionMerger externalFunctionMerger;
	private CodeUnitMerger cuMerge;
	private EquateMerger equateMerger;
	private UserDefinedPropertyMerger userPropertyMerger;
	private FunctionMerger functionMerger;
	private ReferenceMerger referenceMerger;
	private CommentMerger commentMerger;
	private BookmarkMerger bookmarkMerger;
	private SymbolMerger symbolMerger;
	private FunctionTagListingMerger functionTagMerger;

	private ConflictInfoPanel conflictInfoPanel; // This goes above the listing merge panels
	// mergePanel is a panel for listing merge conflicts.
	// listings in CENTER, conflictInfoPanel in NORTH, mergeConflicts in SOUTH.
	private ListingMergePanel mergePanel;
	private TaskMonitor currentStatusMonitor; // The current status monitor.

	/**
	 * The four programs used in a versioned program merge.
	 * <br>RESULT: the program to be updated with the result of the merge.
	 * This is the program that will actually get checked in.
	 * <br>ORIGINAL: the program that was checked out.
	 * <br>LATEST: the latest checked-in version of the program.
	 * <br>MY: the program requesting to be checked in.
	 */
	Program[] programs = new Program[4];
	/** Used to determine differences between the original program and latest program.
	 *  <br>Note: This diff is restricted to only where there are possible conflicts with the "My" program.
	 *  If an individual merger needs to find all diffs between the original and latest programs
	 *  then it must use its own diff.
	 */
	ProgramDiff diffOriginalLatest;
	/** Used to determine differences between the original program and my program. */
	ProgramDiff diffOriginalMy;
	/** Used to determine differences between the result program and latest program. */
	ProgramDiff diffResultLatest;
	/** Used to determine differences between the result program and my program. */
	ProgramDiff diffResultMy;
	/** Used to determine differences between the latest program and my program. */
	ProgramDiff diffLatestMy;
	/** program changes between the original and latest versioned program. */
	ProgramChangeSet latestChanges;
	/** program changes between the original and my modified program. */
	ProgramChangeSet myChanges;
	/** addresses of listing changes between the original and latest versioned program. */
	AddressSetView latestSet;
	/** addresses of listing changes between the original and my modified program. */
	AddressSetView mySet;

	/** Used to merge from Checked Out version to Result version. */
	ProgramMerge mergeMy;
	/** Used to merge from Latest version to Result version. */
	ProgramMerge mergeLatest;
	/** Used to merge from Original version to Result version. */
	ProgramMerge mergeOriginal;

	private int totalConflictsInPhase; // Total number of conflicts for current phase of listing.
	private int conflictNum; // Current conflict number being resolved.
	private boolean showListingPanel = true;

	/**
	 * Manages listing changes and conflicts between the latest versioned
	 * program and the modified program being checked into version control.
	 * @param mergeManager the top level merge manager for merging a program version.
	 * @param resultPgm the program to be updated with the result of the merge.
	 * This is the program that will actually get checked in.
	 * @param originalPgm the program that was checked out.
	 * @param latestPgm the latest checked-in version of the program.
	 * @param myPgm the program requesting to be checked in.
	 * @param latestChanges the address set of changes between original and latest versioned program.
	 * @param myChanges the address set of changes between original and my modified program.
	 */
	public ListingMergeManager(ProgramMultiUserMergeManager mergeManager, Program resultPgm,
			Program originalPgm, Program latestPgm, Program myPgm, ProgramChangeSet latestChanges,
			ProgramChangeSet myChanges) {
		this.mergeManager = mergeManager;
		programs[RESULT] = resultPgm;
		programs[ORIGINAL] = originalPgm;
		programs[LATEST] = latestPgm;
		programs[MY] = myPgm;
		this.latestChanges = latestChanges;
		this.myChanges = myChanges;
	}

	public FunctionTagListingMerger getFunctionTagListingMerger() {
		return functionTagMerger;
	}

	/**
	 * True signals to show the listing panel (default); false signals to show an empty listing (faster)
	 * @param showListingPanel
	 */
	public void setShowListingPanel(boolean showListingPanel) {
		this.showListingPanel = showListingPanel;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#apply()
	 */
	@Override
	public void apply() {
		if (mergeManager == null) {
			return;
		}
		if (currentMerger != null) {
			boolean resolvedAll = currentMerger.apply();
			if (resolvedAll) {
				conflictNum += currentMerger.getNumConflictsResolved();
				if (conflictNum <= totalConflictsInPhase) {
					conflictInfoPanel.setConflictInfo(conflictNum, totalConflictsInPhase);
				}
				mergeManager.setApplyEnabled(false);
			}
			else {
				mergeManager.setStatusText("Please select an option to resolve each conflict.");
			}
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#cancel()
	 */
	@Override
	public void cancel() {
		if (mergeManager != null) {
			mergeManager.setStatusText("User cancelled merge.");
		}
		if (currentMerger != null) {
			currentMerger.cancel();
		}
		conflictOption = CANCELED;
		if (currentStatusMonitor != null) {
			currentStatusMonitor.cancel();
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#getDescription()
	 */
	@Override
	public String getDescription() {
		return "Merge Listing";
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#getName()
	 */
	@Override
	public String getName() {
		return "Listing Merger";
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#merge(ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void merge(TaskMonitor monitor) throws ProgramConflictException, MemoryAccessException {
		mergeManager.setInProgress(LISTING_PHASE);
		// This manager will need to update the phase progress for each sub-phase.

		initMergeInfo();
		if (mergeManager != null) {
			mergePanel = mergeManager.getListingMergePanel();
			if (conflictInfoPanel == null) {
				conflictInfoPanel = new ConflictInfoPanel();
			}
			mergePanel.setTopComponent(conflictInfoPanel);
		}
		try {
			this.currentStatusMonitor = monitor;

			int transactionID = programs[RESULT].startTransaction("Merge Listing");
			boolean commit = false;
			try {
				mergeManager.showProgressIcon(true);
				monitor.setMessage("Initializing Listing Merge Managers...");
				initializeMergers();
				removeBottomComponent();

				mergeCodeUnits(monitor);
				mergeExternalFunctions(monitor);
				mergeFunctions(monitor);
				mergeSymbols(monitor);
				mergeAddressBasedProgramItems(monitor);

				currentMerger = null;
				commit = true;
			}
			catch (CancelledException e1) {
				mergeManager.setStatusText("User cancelled merge.");
				cancel();
			}
			finally {
				programs[RESULT].endTransaction(transactionID, commit);
			}
		}
		finally {
			monitor = null;
		}
		mergeManager.setCompleted(LISTING_PHASE);
	}

	/**
	 * Performs autoMerge of bytes and code units followed by merge of byte and code unit conflicts.
	 * @param monitor the task monitor for canceling the merge
	 * @throws ProgramConflictException if programs can't be compared using Diff.
	 * @throws MemoryAccessException if bytes can't be merged.
	 * @throws CancelledException if the user cancels the merge.
	 */
	private void mergeExternalFunctions(TaskMonitor monitor)
			throws ProgramConflictException, MemoryAccessException, CancelledException {

		emptyListingViewForPrograms();

		displayInitialPhaseMessage(EXTERNALS_PHASE, "Merge of External Function and Label changes");

		conflictInfoPanel.setConflictType(externalFunctionMerger.getConflictType());
		currentMerger = externalFunctionMerger;
		// Only one merger so it gets all of the progress bar to fill in.
		int progressMin = 0;
		int progressMax = 100;
		externalFunctionMerger.autoMerge(progressMin, progressMax, monitor);
		progressMin = progressMax;

		mergeManager.showProgressIcon(false);

		externalFunctionMerger.mergeConflicts(conflictOption, conflictInfoPanel, monitor);

		mergeManager.showProgressIcon(true);
		removeBottomComponent();
		mergeManager.setCompleted(EXTERNALS_PHASE);

		setListingViewsToEntireProgram();
		externalFunctionMerger.dispose();
	}

	private void setListingViewsToEntireProgram() {
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				mergePanel.setViewToProgram(RESULT);
				mergePanel.setViewToProgram(LATEST);
				mergePanel.setViewToProgram(MY);
				mergePanel.setViewToProgram(ORIGINAL);
			}
		});
	}

	private void emptyListingViewForPrograms() {
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				mergePanel.emptyViewForProgram(RESULT);
				mergePanel.emptyViewForProgram(LATEST);
				mergePanel.emptyViewForProgram(MY);
				mergePanel.emptyViewForProgram(ORIGINAL);
			}
		});
	}

	/**
	 * Performs autoMerge of bytes and code units followed by merge of byte and code unit conflicts.
	 * @param monitor the task monitor for canceling the merge
	 * @throws ProgramConflictException if programs can't be compared using Diff.
	 * @throws MemoryAccessException if bytes can't be merged.
	 * @throws CancelledException if the user cancels the merge.
	 */
	private void mergeCodeUnits(TaskMonitor monitor)
			throws ProgramConflictException, MemoryAccessException, CancelledException {

		displayInitialPhaseMessage(CODE_UNITS_PHASE, "Merge of Byte & Code Unit changes");

		AbstractListingMerger[] mergers = new AbstractListingMerger[] { cuMerge };
		autoMerge(mergers, monitor);

		currentMerger = cuMerge;
		mergeManager.showProgressIcon(false);

		cuMerge.mergeConflicts(this.mergePanel, conflictOption, monitor);

		mergeManager.showProgressIcon(true);
		removeBottomComponent();
		mergeManager.setCompleted(CODE_UNITS_PHASE);
	}

	/**
	 * Performs autoMerge of functions followed by merge of function conflicts.
	 * @param monitor the task monitor for canceling the merge
	 * @throws ProgramConflictException if programs can't be compared using Diff.
	 * @throws MemoryAccessException if bytes can't be merged.
	 * @throws CancelledException if the user cancels the merge.
	 */
	private void mergeFunctions(TaskMonitor monitor)
			throws ProgramConflictException, MemoryAccessException, CancelledException {

		displayInitialPhaseMessage(FUNCTIONS_PHASE, "Merge of Function changes");

		ListingMerger[] mergers = new ListingMerger[] { functionMerger };
		autoMerge(mergers, monitor);

		mergeManager.showProgressIcon(false);

		mergeConflicts(mergers, monitor);
		functionMerger.mergeThunks(mergePanel, conflictOption, monitor);

		mergeManager.showProgressIcon(true);
		removeBottomComponent();
		mergeManager.setCompleted(FUNCTIONS_PHASE);

		functionMerger.dispose();
	}

	/**
	 * Performs autoMerge of symbols followed by merge of symbol conflicts.
	 * @param monitor the task monitor for canceling the merge
	 * @throws ProgramConflictException if programs can't be compared using Diff.
	 * @throws MemoryAccessException if bytes can't be merged.
	 * @throws CancelledException if the user cancels the merge.
	 */
	private void mergeSymbols(TaskMonitor monitor)
			throws ProgramConflictException, MemoryAccessException, CancelledException {

		displayInitialPhaseMessage(SYMBOLS_PHASE, "Merge of Symbol changes");

		conflictInfoPanel.setConflictType(symbolMerger.getConflictType());
		currentMerger = symbolMerger;

		symbolMerger.merge(0, 100, monitor);

		removeBottomComponent();
		mergeManager.setCompleted(SYMBOLS_PHASE);
	}

	/**
	 * Performs autoMerge of each remaining address based program item followed by merge of
	 * their conflicts in address order.
	 * @param monitor the task monitor for canceling the merge
	 * @throws ProgramConflictException if programs can't be compared using Diff.
	 * @throws MemoryAccessException if bytes can't be merged.
	 * @throws CancelledException if the user cancels the merge.
	 */
	private void mergeAddressBasedProgramItems(TaskMonitor monitor)
			throws ProgramConflictException, MemoryAccessException, CancelledException {

		// Now that the final code units are established,
		// merge the remaining listing at the address level in address order.
		// Each of the following mergers are address based listing mergers.
		displayInitialPhaseMessage(ADDRESS_BASED_PHASE,
			"Merge of Equate, User Defined Property, Reference,Function Tags, Bookmark & Comment changes");

		AbstractListingMerger[] mergers = new AbstractListingMerger[] { equateMerger,
			userPropertyMerger, referenceMerger, bookmarkMerger, commentMerger, functionTagMerger };
		autoMerge(mergers, monitor);

		mergeManager.showProgressIcon(false);

		mergeConflicts(mergers, monitor);

		mergeManager.showProgressIcon(true);
		removeBottomComponent();
		mergeManager.setCompleted(ADDRESS_BASED_PHASE);
	}

	/**
	 * Updates the phase status and message information in the mergeManager.
	 * @param phaseIndicator indicates the phase for the merge manager to change to "In Progress".
	 * @param phaseMessage text indicating what this phase will be merging.
	 */
	private void displayInitialPhaseMessage(String[] phaseIndicator, String phaseMessage) {
		mergeManager.setInProgress(phaseIndicator);
		mergeManager.showDefaultMergePanel(phaseMessage);
		mergeManager.updateProgress(0, phaseMessage);
	}

	/**
	 * Removes the bottom component (the conflict component) from the listing merge panel.
	 * This should be called when the conflict Apply button is activated.
	 */
	private void removeBottomComponent() {
		try {
			SwingUtilities.invokeAndWait(new Runnable() {
				@Override
				public void run() {
					if (mergePanel != null) {
						mergePanel.setBottomComponent(null);
					}
				}
			});
		}
		catch (InterruptedException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
		catch (InvocationTargetException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
	}

	/**
	 * Sets up the change address sets, Diffs between the various program versions,
	 * and Merges from various versions to the resulting program.
	 */
	public void initMergeInfo() {
		// Memory Merge may have limited the changed code units we are working with.
		AddressSetView resultSet = programs[RESULT].getMemory();
		this.latestSet = latestChanges.getAddressSet().intersect(resultSet);
		this.mySet = myChanges.getAddressSet().intersect(resultSet);
		currentMerger = null;

		try {
			// Set up for the different types of diffs that are needed to resolve differences.
			/* Important: diffOriginalLatest uses "possibleLatestInConflict" for its limiting set
			 * and not "latestSet". This is because the result program already has the latest changes.
			 * So we are only concerned with finding conflicts with latest.
			 */
			AddressSetView possibleLatestInConflict = latestSet.intersect(mySet);
			diffOriginalLatest =
				new ProgramDiff(programs[ORIGINAL], programs[LATEST], possibleLatestInConflict);
			diffOriginalMy = new ProgramDiff(programs[ORIGINAL], programs[MY], mySet);
			diffLatestMy =
				new ProgramDiff(programs[LATEST], programs[MY], possibleLatestInConflict);

			// Set up for the different types of merges that are needed to merge changes.
			mergeMy = new ProgramMerge(programs[RESULT], programs[MY]);
			mergeLatest = new ProgramMerge(programs[RESULT], programs[LATEST]);
			mergeOriginal = new ProgramMerge(programs[RESULT], programs[ORIGINAL]);
		}
		catch (ProgramConflictException e) {
			throw new AssertException(e);
		}
		catch (IllegalArgumentException e) {
			throw new AssertException(e);
		}
	}

	/**
	 * Creates all of the individual mergers that are used by the ListingMergeManager.
	 * Each of these listing mergers will autoMerge() non-conflicting changes and will
	 * determine conflicts. The conflicts are handled later by calling manualMerge().
	 */
	private void initializeMergers() {
		externalFunctionMerger = new ExternalFunctionMerger(this, showListingPanel);
		cuMerge = new CodeUnitMerger(this);
		functionMerger = new FunctionMerger(this);
		symbolMerger = new SymbolMerger(this);
		equateMerger = new EquateMerger(this);
		userPropertyMerger = new UserDefinedPropertyMerger(this);
		referenceMerger = new ReferenceMerger(this);
		commentMerger = new CommentMerger(this);
		bookmarkMerger = new BookmarkMerger(this);
		functionTagMerger = new FunctionTagListingMerger(this);
	}

	/**
	 * Performs an automatic merge of My changes that are not conflicts for all the mergers
	 * specified. Each of the merger's autoMerge is performed in the order they
	 * are found in the array. Each autoMerge will cause that merger to determine conflicts.
	 * <br>Note: This method should be called a single time for any set of listing mergers
	 * and then be followed by the mergeConflicts() call to resolve conflicts.
	 * @param mergers the listing mergers to be auto-merged.
	 * @param monitor indicates progress to user and allows cancel.
	 * @throws ProgramConflictException if programs can't be compared using Diff.
	 * @throws MemoryAccessException if bytes can't be merged.
	 * @throws CancelledException if the user cancels the merge.
	 */
	private void autoMerge(ListingMerger[] mergers, TaskMonitor monitor)
			throws ProgramConflictException, MemoryAccessException, CancelledException {
		float progressRangeSize = 100 / mergers.length;
		int progressMin = 0;
		for (int mergerIndex = 0; mergerIndex < mergers.length; mergerIndex++) {
			conflictInfoPanel.setConflictType(mergers[mergerIndex].getConflictType());
			currentMerger = mergers[mergerIndex];
			// Give each of the mergers an equal portion of the progress bar to fill in.
			int progressMax = (int) progressRangeSize * (mergerIndex + 1);
			mergers[mergerIndex].autoMerge(progressMin, progressMax, monitor);
			progressMin = progressMax;
		}
	}

	/**
	 * For JUnit testing only, set the option for resolving a conflict.
	 * @param decision CANCELED, ASK_USER, PICK_LATEST, PICK_MY, PICK_ORIGINAL
	 */
	void setConflictDecision(int decision) {
		if (decision < CANCELED || decision > KEEP_ALL) {
			throw new IllegalArgumentException();
		}
		conflictOption = decision;
	}

	/**
	 * Performs a manual merge of the Listing conflicts for all the mergers
	 * specified. The addresses with conflicts will be resolved in order
	 * from minimum address to maximum address.
	 * At each address all conflicts are resolved before moving to the next address.
	 * <br>Note: Call the autoMerge() method before this method in order to
	 * determine the conflicts.
	 * @param mergers the listing mergers whose conflicts are to be merged.
	 * @param monitor indicates progress to user and allows cancel.
	 * @throws ProgramConflictException if programs can't be compared using Diff.
	 * @throws MemoryAccessException if bytes can't be merged.
	 * @throws CancelledException if the user cancels the merge.
	 */
	private void mergeConflicts(ListingMerger[] mergers, TaskMonitor monitor)
			throws MemoryAccessException, CancelledException {
		int originalConflictOption = conflictOption;
		AddressSet listingConflictSet = getListingConflicts(mergers);
		long totalAddresses = listingConflictSet.getNumAddresses();
		AddressIterator iter = listingConflictSet.getAddresses(true);
		for (long addressNum = 1; iter.hasNext(); addressNum++) {
			Address addr = iter.next();
			conflictNum = 1;
			totalConflictsInPhase = getTotalNumConflicts(mergers, addr);
			if (mergePanel != null) {
				conflictInfoPanel.setAddressInfo(addr, addressNum, totalAddresses);
				conflictInfoPanel.setConflictInfo(conflictNum, totalConflictsInPhase);
			}
			for (ListingMerger merger : mergers) {
				currentMerger = merger;
				conflictInfoPanel.setConflictType(currentMerger.getConflictType());
				currentMerger.mergeConflicts(this.mergePanel, addr, originalConflictOption,
					monitor);
			}
		}
	}

	/**
	 * Gets the number of Listing conflicts to resolve at the indicated address.
	 * @param mergers the mergers whose address based conflicts are of interest.
	 * @param addr the address
	 * @return the number of Listing conflicts at the address
	 */
	private int getTotalNumConflicts(ListingMerger[] mergers, Address addr) {
		int totalConflicts = 0;
		for (ListingMerger merger : mergers) {
			totalConflicts += merger.getConflictCount(addr);
		}
		return totalConflicts;
	}

	/**
	 * Gets the set of addresses where conflicts need to be resolved in the listing
	 * by each of the merger's specified.
	 * @param mergers the mergers whose address based conflicts are of interest.
	 * @return the set of addresses with conflicts.
	 */
	private AddressSet getListingConflicts(ListingMerger[] mergers) {
		AddressSet conflicts = new AddressSet();
		for (ListingMerger merger : mergers) {
			conflicts.add(merger.getConflicts());
		}
		return conflicts;
	}

	/**
	 * Gets the address set for the code units that were changed in the result
	 * by the merge.
	 * @return the address set indicating the code units that changed in the
	 * result program due to the merge
	 */
	public AddressSet getMergedCodeUnits() {
		if (mergeManager != null) {
			return (AddressSet) mergeManager.getResolveInformation(
				MergeConstants.RESOLVED_CODE_UNITS);
		}
		return new AddressSet();
	}

	/**
	 * Returns the listing merge panel.
	 * This panel displays all four programs for a versioned merge.
	 * Above the listings in conflict information.
	 * Below the listings is a conflict panel for the user to resolve conflicts.
	 * @return the listing merge conflict panel
	 */
	ListingMergePanel getListingMergePanel() {
		return mergePanel;
	}

	/**
	 * Returns the conflict information panel. This panel appears above
	 * the listings on a listing merge conflict dialog. It indicates the type
	 * of conflict, address (if applicable), how many conflicts, etc.
	 * @return the conflict information panel.
	 */
	ConflictInfoPanel getConflictInfoPanel() {
		return conflictInfoPanel;
	}

	/**
	 * This method allows other listing merge managers to resolve a namespace
	 * via the symbol merge manager. This is because the symbol merge manager
	 * actually merges namespaces and best knows how to resolve them.
	 * It also keeps track of how they have been resolved.
	 * @param srcProgram the program version that the namespace to be resolved is coming from.
	 * @param srcNamespace the namespace to be resolved
	 * @return the namespace from the result program version
	 * @throws DuplicateNameException if the name space can't be resolved due
	 * to a name conflict that can't be dealt with.
	 * @throws InvalidInputException if the name space is not validly named
	 * for the result program.
	 */
	Namespace resolveNamespace(Program srcProgram, Namespace srcNamespace)
			throws DuplicateNameException, InvalidInputException {
		return symbolMerger.resolveNamespace(srcProgram, srcNamespace);
	}

	/**
	 * This method returns all of the phases of the Listing Merge Manager that will be
	 * displayed in the Program Merge Manager.
	 * The first item is a phase indicator for the Listing Phase as a whole and
	 * the others are for each sub-phase of the Listing.
	 */
	@Override
	public String[][] getPhases() {
		return new String[][] { LISTING_PHASE, CODE_UNITS_PHASE, EXTERNALS_PHASE, FUNCTIONS_PHASE,
			SYMBOLS_PHASE, ADDRESS_BASED_PHASE };
		// The ADDRESS_BASED_PHASE actually handles the merge of multiple parts of the program that
		// have their conflicts merged in address order.
	}

}
