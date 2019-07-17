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

import javax.swing.SwingUtilities;
import javax.swing.event.ChangeListener;

import docking.widgets.dialogs.ReadTextDialog;
import ghidra.app.merge.*;
import ghidra.app.merge.util.ConflictUtility;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramChangeSet;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramMerge;
import ghidra.program.util.SimpleDiffUtility;
import ghidra.util.*;
import ghidra.util.datastruct.LongLongHashtable;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Manages external program name changes and conflicts between the latest versioned
 * program and the modified program being checked into version control.
 */
public class ExternalProgramMerger implements MergeResolver, ListingMergeConstants {

//	private static final int CANCELED = ListingMergeManager.CANCELED;
//	private static final int ASK_USER = ListingMergeManager.ASK_USER;

	private static String[] EXTERNAL_PROGRAM_PHASE = new String[] { "External Programs" };
	private VerticalChoicesPanel conflictPanel;
	private int conflictOption;
	private IDGroup currentIDGroup; // Symbol ID group for the current conflict.
	private TaskMonitor currentMonitor;

	private ArrayList<IDGroup> extPgms; // SymbolID groups for the conflicts.

	private ProgramMultiUserMergeManager mergeManager;
	/** the program to be updated with the result of the merge.
	 * This is the program that will actually get checked in. */
	private Program resultPgm;
	/** the program that was checked out. */
	private Program originalPgm;
	/** the latest checked-in version of the program. */
	private Program latestPgm;
	/** the program requesting to be checked in. */
	private Program myPgm;

	private ExternalManager originalExtMgr;
	private ExternalManager latestExtMgr;
	private ExternalManager myExtMgr;
	private ExternalManager resultExtMgr;

	private StringBuffer infoBuf;
	private int externalProgramChoice = ASK_USER;

	// Maps for accessing symbol resolution information.
	// These were passed on from prior mergers (i.e.SymbolMerger).
	LongLongHashtable originalResolvedSymbols; // Maps original symbolID to result symbolID
	LongLongHashtable latestResolvedSymbols; // Maps latest symbolID to result symbolID
	LongLongHashtable myResolvedSymbols; // Maps my symbolID to result symbolID

	// Reverse ID maps for just Library symbols.
	LongLongHashtable resultToOriginalMap; // Maps result symbolID to original symbolID for Libs.
	LongLongHashtable resultToLatestMap; // Maps result symbolID to latest symbolID for Libs.
	LongLongHashtable resultToMyMap; // Maps result symbolID to my symbolID for Libs.

	// When determining groups of IDs for each Library symbol, keep track of those that have a
	// Result program symbol ID, so we don't duplicate the groups for a single resulting symbol.
	Set<Long> resultIDsInAGroup = new HashSet<>();

	/**
	 * Manages code unit changes and conflicts between the latest versioned
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
	public ExternalProgramMerger(ProgramMultiUserMergeManager mergeManager, Program resultPgm,
			Program originalPgm, Program latestPgm, Program myPgm, ProgramChangeSet latestChanges,
			ProgramChangeSet myChanges) {
		this.mergeManager = mergeManager;
		this.resultPgm = resultPgm;
		this.originalPgm = originalPgm;
		this.latestPgm = latestPgm;
		this.myPgm = myPgm;
		init();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.AbstractListingMerger#init()
	 */
	public void init() {
		extPgms = new ArrayList<>(); // symbol ID group for an external program name
		originalExtMgr = originalPgm.getExternalManager();
		latestExtMgr = latestPgm.getExternalManager();
		myExtMgr = myPgm.getExternalManager();
		resultExtMgr = resultPgm.getExternalManager();
		infoBuf = new StringBuffer();

		originalResolvedSymbols = new LongLongHashtable();
		latestResolvedSymbols = new LongLongHashtable();
		myResolvedSymbols = new LongLongHashtable();

		resultToOriginalMap = new LongLongHashtable();
		resultToLatestMap = new LongLongHashtable();
		resultToMyMap = new LongLongHashtable();
	}

	/**
	 * For JUnit testing only, set the option for resolving a conflict.
	 * @param decision CANCELED, ASK_USER, LATEST, MY, ORIGINAL
	 */
	void setConflictDecision(int decision) {
		switch (decision) {
			case CANCELED:
			case ASK_USER:
			case KEEP_MY:
			case KEEP_LATEST:
			case KEEP_ORIGINAL:
				conflictOption = decision;
				break;
			default:
				throw new IllegalArgumentException();
		}
	}

	/**
	 * Clears all text from the information buffer.
	 */
	void clearResolveInfo() {
		if (infoBuf.length() > 0) {
			infoBuf = new StringBuffer();
		}
	}

	/**
	 * This is a generic method for displaying the contents of the information
	 * buffer to the user.
	 */
	void showResolveInfo() {
		if (infoBuf.length() > 0) {
			try {
				SwingUtilities.invokeAndWait(new Runnable() {
					@Override
					public void run() {
						String title = getConflictType() + " Merge Information";
						String msg = infoBuf.toString();
						ReadTextDialog dialog = new ReadTextDialog(title, msg);
						mergeManager.getMergeTool().showDialog(dialog,
							mergeManager.getMergeTool().getToolFrame());
					}
				});
			}
			catch (InterruptedException e) {
				throw new AssertException(e);
			}
			catch (InvocationTargetException e) {
				throw new AssertException(e);
			}
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#determineConflicts(ghidra.util.task.TaskMonitor)
	 */
	public void autoMerge(TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Auto-merging External Program Names and determining conflicts.");
		if (monitor.isCancelled()) {
			throw new CancelledException();
		}

		if (mergeManager != null) {
			latestResolvedSymbols = (LongLongHashtable) mergeManager
				.getResolveInformation(MergeConstants.RESOLVED_LATEST_SYMBOLS);
			myResolvedSymbols = (LongLongHashtable) mergeManager
				.getResolveInformation(MergeConstants.RESOLVED_MY_SYMBOLS);
			originalResolvedSymbols = (LongLongHashtable) mergeManager
				.getResolveInformation(MergeConstants.RESOLVED_ORIGINAL_SYMBOLS);

			// Populate the reverse maps.
			mapResultsToOriginalLibs();
			mapResultsToLatestLibs();
			mapResultsToMyLibs();
		}

		// Determine the symbol ID group for each external program (Library) to possibly merge.
		List<IDGroup> idGroups = new ArrayList<>();
		idGroups.addAll(getGroupsForOriginalLibs());
		idGroups.addAll(getGroupsForLatestNewLibs());
		idGroups.addAll(getGroupsForMyNewLibs());

		// Process each Library symbol ID group and determine any conflicts.
		int resolveCount = 0;
		int maximum = idGroups.size();
		monitor.initialize(maximum);
		for (IDGroup idGroup : idGroups) {
			int progress = (int) (((float) (resolveCount / maximum)) * 100);
			autoMergeNamedExternalProgram(idGroup, progress);
			monitor.setProgress(++resolveCount);
		}
	}

	/**
	 * Populate the reverse map for the Library symbols in the Original program.
	 */
	private void mapResultsToOriginalLibs() {
		SymbolTable originalSymbolManager = originalPgm.getSymbolTable();
		String[] originalNames = originalExtMgr.getExternalLibraryNames();
		for (String originalName : originalNames) {
			Symbol librarySymbol = originalSymbolManager.getLibrarySymbol(originalName);
			long originalID = librarySymbol.getID();
			long resultID = getResultIDFromOriginalID(originalID);
			if (resultID != -1) {
				resultToOriginalMap.put(resultID, originalID);
			}
		}
	}

	/**
	 * Populate the reverse map for the Library symbols in the Latest program.
	 */
	private void mapResultsToLatestLibs() {
		SymbolTable latestSymbolManager = latestPgm.getSymbolTable();
		String[] latestNames = latestExtMgr.getExternalLibraryNames();
		for (String latestName : latestNames) {
			Symbol librarySymbol = latestSymbolManager.getLibrarySymbol(latestName);
			long latestID = librarySymbol.getID();
			long resultID;
			try {
				resultID = getResultIDFromLatestID(latestID);
			}
			catch (NoValueException e) {
				resultID = latestID;
			}
			if (resultID != -1) {
				resultToLatestMap.put(resultID, latestID);
			}
		}
	}

	/**
	 * Populate the reverse map for the Library symbols in the My program.
	 */
	private void mapResultsToMyLibs() {
		SymbolTable mySymbolManager = myPgm.getSymbolTable();
		String[] myNames = myExtMgr.getExternalLibraryNames();
		for (String myName : myNames) {
			Symbol librarySymbol = mySymbolManager.getLibrarySymbol(myName);
			long myID = librarySymbol.getID();
			long resultID;
			try {
				resultID = getResultIDFromMyID(myID);
			}
			catch (NoValueException e) {
				resultID = myID;
			}
			if ((resultID != -1) && (resultID != myID)) {
				resultToMyMap.put(resultID, myID);
			}
		}
	}

	/**
	 * Gets symbol ID groups for each Library symbol that was in the Original program.
	 * <br> Note: This method excludes any new Library symbols in Original whose matching Result ID
	 * has already been placed in the resultIDsInAGroup set. Otherwise, each ID group that has a
	 * Result ID will add it to the resultIDsInAGroup set.
	 * @return the ID groups for Library symbols in the Original program.
	 */
	private List<IDGroup> getGroupsForOriginalLibs() {
		List<IDGroup> idGroups = new ArrayList<>();
		String[] originalNames = originalExtMgr.getExternalLibraryNames();
		SymbolTable originalSymbolTable = originalPgm.getSymbolTable();
		SymbolTable latestSymbolTable = latestPgm.getSymbolTable();
		SymbolTable mySymbolTable = myPgm.getSymbolTable();
		for (String originalName : originalNames) {
			Symbol originalLibrarySymbol = originalSymbolTable.getLibrarySymbol(originalName);
			long originalID = originalLibrarySymbol.getID();
			long resultID = getResultIDFromOriginalID(originalID);
			long latestID = (latestSymbolTable.getSymbol(originalID) != null) ? originalID : -1;
			long myID = (mySymbolTable.getSymbol(originalID) != null) ? originalID : -1;
			if (resultIDsInAGroup.contains(resultID)) {
				continue; // Already have this result as an IDGroup.
			}
			idGroups.add(new IDGroup(resultID, originalID, latestID, myID));
			if (resultID != -1) {
				resultIDsInAGroup.add(resultID);
			}
		}
		return idGroups;
	}

	/**
	 * Gets symbol ID groups for each Library symbol that is new in the Latest program
	 * (symbol wasn't in the Original program).
	 * <br> Note: This method excludes any new Library symbols in Original whose matching Result ID
	 * has already been placed in the resultIDsInAGroup set. Otherwise, each ID group that has a
	 * Result ID will add it to the resultIDsInAGroup set.
	 * @return the ID groups for new Library symbols in the Latest program.
	 */
	private List<IDGroup> getGroupsForLatestNewLibs() {
		List<IDGroup> idGroups = new ArrayList<>();
		String[] latestNames = latestExtMgr.getExternalLibraryNames();
		SymbolTable originalSymbolTable = originalPgm.getSymbolTable();
		SymbolTable latestSymbolTable = latestPgm.getSymbolTable();
		for (String latestName : latestNames) {
			Symbol latestLibrarySymbol = latestSymbolTable.getLibrarySymbol(latestName);
			long latestID = latestLibrarySymbol.getID();
			if (originalSymbolTable.getSymbol(latestID) != null) {
				continue; // getGroupsForOriginalLibs already got this.
			}
			long resultID;
			try {
				resultID = getResultIDFromLatestID(latestID);
			}
			catch (NoValueException e) {
				resultID = latestID;
			}
			// Get original and my for this Latest's matching result ID.
			long originalID = getOriginalIDForResultID(resultID);
			long myID = getMyIDForResultID(resultID);
			if (resultIDsInAGroup.contains(resultID)) {
				continue; // Already have this result as an IDGroup.
			}
			idGroups.add(new IDGroup(resultID, originalID, latestID, myID));
			if (resultID != -1) {
				resultIDsInAGroup.add(resultID);
			}
		}
		return idGroups;
	}

	/**
	 * Gets symbol ID groups for each Library symbol that is new in the My program
	 * (symbol wasn't in the Original program).
	 * <br> Note: This method excludes any new Library symbols in Original whose matching Result ID
	 * has already been placed in the resultIDsInAGroup set. Otherwise, each ID group that has a
	 * Result ID will add it to the resultIDsInAGroup set.
	 * @return the ID groups for new Library symbols in the My program.
	 */
	private List<IDGroup> getGroupsForMyNewLibs() {
		List<IDGroup> idGroups = new ArrayList<>();
		String[] myNames = myExtMgr.getExternalLibraryNames();
		SymbolTable originalSymbolTable = originalPgm.getSymbolTable();
		SymbolTable mySymbolTable = myPgm.getSymbolTable();
		for (String myName : myNames) {
			Symbol myLibrarySymbol = mySymbolTable.getLibrarySymbol(myName);
			long myID = myLibrarySymbol.getID();
			if (originalSymbolTable.getSymbol(myID) != null) {
				continue; // getGroupsForOriginalLibs already got this.
			}
			long resultID;
			try {
				resultID = getResultIDFromMyID(myID);
			}
			catch (NoValueException e) {
				resultID = myID;
			}

			// Get original and latest for this My's matching result ID.
			long originalID = getOriginalIDForResultID(resultID);
			long latestID = getLatestIDForResultID(resultID);
			if (resultIDsInAGroup.contains(resultID)) {
				continue; // Already have this result as an IDGroup.
			}
			idGroups.add(new IDGroup(resultID, originalID, latestID, myID));
			if (resultID != -1) {
				resultIDsInAGroup.add(resultID);
			}
		}
		return idGroups;
	}

	private long getOriginalIDForResultID(long resultID) {
		if (resultID == -1) {
			return -1;
		}
		try {
			return resultToOriginalMap.get(resultID);
		}
		catch (NoValueException e) {
			// Didn't find it, so return -1;
		}
		return -1;
	}

	private long getLatestIDForResultID(long resultID) {
		if (resultID == -1) {
			return -1;
		}
		try {
			return resultToLatestMap.get(resultID);
		}
		catch (NoValueException e) {
			// Didn't find it, so return -1;
		}
		return -1;
	}

	private long getMyIDForResultID(long resultID) {
		if (resultID == -1) {
			return -1;
		}
		try {
			return resultToMyMap.get(resultID);
		}
		catch (NoValueException e) {
			// Didn't find it, so return -1;
		}
		return -1;
	}

	private void autoMergeNamedExternalProgram(IDGroup idGroup, int progress) {

		long resultID = idGroup.getResultID();
		String resultName = idGroup.getResultName();
		String originalName = idGroup.getOriginalName();
		String latestName = idGroup.getLatestName();
		String myName = idGroup.getMyName();
		String name = (resultName != null) ? resultName
				: (originalName != null) ? originalName
						: (latestName != null) ? latestName : (myName != null) ? myName : "unknown";

		mergeManager.updateProgress(progress,
			"Merging external program information for " + name + "...");

		String originalPath =
			(originalName != null) ? originalExtMgr.getExternalLibraryPath(originalName) : null;
		String latestPath =
			(latestName != null) ? latestExtMgr.getExternalLibraryPath(latestName) : null;
		String myPath = (myName != null) ? myExtMgr.getExternalLibraryPath(myName) : null;
		if (same(latestName, myName) && same(latestPath, myPath)) {
			return;
		}
		boolean changedLatestName = !same(originalName, latestName);
		boolean changedMyName = !same(originalName, myName);
		boolean changedLatestPath = !same(originalPath, latestPath);
		boolean changedMyPath = !same(originalPath, myPath);
		boolean changedLatest = changedLatestName || changedLatestPath;
		boolean changedMy = changedMyName || changedMyPath;
		if (changedLatest) {
			if (changedMy) {
				// conflict: Ask to keep latest or my
				extPgms.add(idGroup);
			}
			else {
				// Keep latest
				// AutoMerge latest
				if (resultID != -1 && resultName == null) {
					resultName = latestName; // Need to create Library symbol in Result program.
				}
				autoMergeWhenOnlyLatestChanged(resultName, latestName, latestPath);
			}
		}
		else {
			if (changedMy) {
				// AutoMerge my
				if (resultID != -1 && resultName == null) {
					resultName = myName; // Need to create Library symbol in Result program.
					// See if there is another symbol in conflict with this name already.
					SymbolTable resultSymbolTable = resultPgm.getSymbolTable();
					Symbol symbol = resultSymbolTable.getSymbol(resultName, Address.NO_ADDRESS,
						resultPgm.getGlobalNamespace());
					if (symbol != null && symbol.getSymbolType() != SymbolType.LIBRARY) {
						resultName = ProgramMerge.getUniqueName(resultSymbolTable, resultName,
							Address.NO_ADDRESS, resultPgm.getGlobalNamespace(),
							symbol.getSymbolType());
					}
				}
				autoMergeWhenOnlyMyChanged(resultName, myName, myPath);
			}
		}
	}

	private void autoMergeWhenOnlyLatestChanged(String resultName, String latestName,
			String latestPath) {
		if (resultName == null) {
			// latestName appears to have been discarded during SymbolMerge.
			return;
		}
		try {
			if (latestName == null) {
				removeExternalLibrary(resultPgm, resultName);
			}
			else {
				resultExtMgr.setExternalPath(resultName, latestPath,
					isExternalUserDefined(latestPgm, latestName));
			}
		}
		catch (InvalidInputException e) {
			infoBuf.append(e.getMessage() + "\n");
		}
	}

	private void autoMergeWhenOnlyMyChanged(String resultName, String myName, String myPath) {
		if (resultName == null) {
			// myName appears to have been discarded during SymbolMerge.
			return;
		}
		try {
			if (myName == null) {
				removeExternalLibrary(resultPgm, resultName);
			}
			else {
				resultExtMgr.setExternalPath(resultName, myPath,
					isExternalUserDefined(myPgm, myName));
			}
		}
		catch (InvalidInputException e) {
			infoBuf.append(e.getMessage() + "\n");
		}
	}

	private boolean isExternalUserDefined(Program pgm, String externalName) {
		SymbolTable symTab = pgm.getSymbolTable();
		Symbol s = symTab.getLibrarySymbol(externalName);
		if (s != null) {
			return (s.getSource() == SourceType.USER_DEFINED);
		}
		return false;
	}

	/**
	 * Removes the indicated external library from the indicated program version
	 * if it is empty.
	 * @param program the program
	 * @param libName the external library name
	 * @throws InvalidInputException if there is no such enterrnal library in the program
	 */
	private void removeExternalLibrary(Program program, String libName)
			throws InvalidInputException {
		ExternalManager extMgr = program.getExternalManager();
		ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
		if (iter.hasNext()) {
			throw new InvalidInputException(
				"Didn't remove external library " + libName + " since it isn't empty.");
		}
		if (!extMgr.removeExternalLibrary(libName)) {
			throw new InvalidInputException("Didn't remove external library " + libName);
		}
	}

	/**
	 * Determines whether the latest external program name and my external program name are equals.
	 * @param latestName the latest external program name or null.
	 * @param myName my external program name or null.
	 * @return true if the names are equal.
	 */
	private boolean same(String latestName, String myName) {
		return SystemUtilities.isEqual(latestName, myName);
	}

	/**
	 * Performs a manual merge of external program conflicts.
	 * @param chosenConflictOption ASK_USER means interactively resolve conflicts.
	 * JUnit testing also allows setting this to LATEST, MY, or ORIGINAL to force
	 * selection of a particular version change.
	 * @param monitor task monitor for informing the user of progress.
	 * @throws CancelledException if the user cancels the merge.
	 */
	public void mergeConflicts(int chosenConflictOption, TaskMonitor monitor)
			throws CancelledException {
		monitor.setMessage("Resolving External Program Name conflicts");
		boolean askUser = (chosenConflictOption == ASK_USER);
		int totalConflicts = extPgms.size();
		monitor.initialize(totalConflicts);
		for (int conflictIndex = 0; conflictIndex < totalConflicts; conflictIndex++) {
			IDGroup idGroup = extPgms.get(conflictIndex);
			if ((externalProgramChoice == ASK_USER) && askUser && mergeManager != null) {
				monitor.checkCanceled();
				showMergePanel(idGroup, monitor);
			}
			else {
				int optionToUse = (externalProgramChoice == ASK_USER) ? chosenConflictOption
						: externalProgramChoice;
				merge(idGroup, optionToUse, monitor);
			}
			monitor.setProgress(conflictIndex + 1);
		}
	}

	/**
	 * Displays the external program name conflict panel to the user.
	 * @param idGroup the symbol ID group for the external program (Library) being merged.
	 * @param monitor task monitor to provide merge status to the user and allow canceling.
	 */
	private void showMergePanel(final IDGroup idGroup, TaskMonitor monitor) {
		this.currentIDGroup = idGroup;
		this.currentMonitor = monitor;

		try {
			final ChangeListener changeListener = e -> {
				conflictOption = conflictPanel.getSelectedOptions();
				if (conflictOption == ASK_USER || conflictOption == CANCELED) {
					if (mergeManager != null) {
						mergeManager.setApplyEnabled(false);
					}
					return;
				}
				if (mergeManager != null) {
					mergeManager.clearStatusText();
				}
				merge(idGroup, conflictOption, currentMonitor);
				if (mergeManager != null) {
					mergeManager.setApplyEnabled(true);
				}
			};
			SwingUtilities.invokeAndWait(() -> conflictPanel =
				getConflictPanel(ExternalProgramMerger.this.currentIDGroup, changeListener));
		}
		catch (InterruptedException | InvocationTargetException e) {
			Msg.error(this,
				"Unexpected error showing merge panel for external program " + idGroup.getName(),
				e);
		}
		if (mergeManager != null) {
			mergeManager.setApplyEnabled(false);

			boolean useForAll = (externalProgramChoice != ASK_USER);
			conflictPanel.setUseForAll(useForAll);
			conflictPanel.setConflictType("External Program");

			mergeManager.showComponent(conflictPanel, "ExternalProgramMerge",
				new HelpLocation(HelpTopics.REPOSITORY, "ExternalConflict"));
		}
		// block until the user either cancels or hits the "Apply" button
		// on the merge dialog...
		// when the "Apply" button is hit, get the user's selection
		// and continue.
	}

	/**
	 * Gets the conflict resolution panel to display
	 * @param idGroup the symbol ID group for the external program (Library) in conflict.
	 * @param listener the listener for the user's choice when resolving the conflict.
	 * @return the panel.
	 */
	VerticalChoicesPanel getConflictPanel(IDGroup idGroup, ChangeListener listener) {
		if (conflictPanel == null) {
			conflictPanel = new VerticalChoicesPanel();
			conflictPanel.setTitle(getConflictType());
		}
		conflictPanel.clear();
		// Initialize the conflict panel.
		conflictPanel.setHeader(getConflictInfo(idGroup, 1, 1));

		conflictPanel.setRowHeader(getExternalNameInfo(null, null, null, null));
		ExternalManager latestMgr = latestPgm.getExternalManager();
		ExternalManager myMgr = myPgm.getExternalManager();
		String latestName = idGroup.getLatestName();
		String myName = idGroup.getMyName();
		String originalName = idGroup.getOriginalName();
		boolean inLatest = (latestName != null) ? latestMgr.contains(latestName) : false;
		boolean inMy = (myName != null) ? myMgr.contains(myName) : false;
		String latestPrefix = (inLatest) ? "Change as in '" : "Remove as in '";
		String myPrefix = (inMy) ? "Change as in '" : "Remove as in '";
		String suffix = "' version";
		conflictPanel.addRadioButtonRow(
			getExternalNameInfo(latestPgm, latestName, latestPrefix, suffix), LATEST_BUTTON_NAME,
			KEEP_LATEST, listener);
		conflictPanel.addRadioButtonRow(getExternalNameInfo(myPgm, myName, myPrefix, suffix),
			CHECKED_OUT_BUTTON_NAME, KEEP_MY, listener);
		conflictPanel.addInfoRow(getExternalNameInfo(originalPgm, originalName, "'", suffix));
		return conflictPanel;
	}

	/**
	 * Returns an array of strings to display for a row of external program name information.
	 * @param pgm the program version
	 * @param extPgmName the external program name
	 * @param prefix prefix for the first column's info.
	 * @param suffix suffix for the first column's info.
	 * @return an array of strings (one for each column of the conflict choice table.
	 */
	private String[] getExternalNameInfo(Program pgm, String extPgmName, String prefix,
			String suffix) {
		if (pgm == null) { // Header info
			return new String[] { "Option", "Name", "Path" };
		}
		String[] info = new String[] { "", "", "", };
		String version = "";
		if (pgm == originalPgm) {
			version = ORIGINAL_TITLE;
		}
		else if (pgm == latestPgm) {
			version = LATEST_TITLE;
		}
		else if (pgm == myPgm) {
			version = MY_TITLE;
		}
		else if (pgm == resultPgm) {
			version = RESULT_TITLE;
		}
		info[0] = prefix + version + suffix;
		ExternalManager em = pgm.getExternalManager();
		if ((extPgmName != null) && em.contains(extPgmName)) {
			info[1] = extPgmName;
			info[2] = em.getExternalLibraryPath(extPgmName);
		}
		return info;
	}

	/**
	 * Gets the information to display at the top of the conflict window indicating
	 * which conflict this is of the total external program name conflicts.
	 * @param idGroup the symbol ID group for the external program (Library) in conflict.
	 * @param conflictIndex the index of the current conflict.
	 * @param totalConflicts the total number of conflicts.
	 */
	public String getConflictInfo(IDGroup idGroup, int conflictIndex, int totalConflicts) {
		String leftText = getConflictCount(conflictIndex, totalConflicts);
		String rightText = createNameInfo(idGroup.getName());
		String text = leftText + ConflictUtility.spaces(8) + rightText;
		return text;
	}

	private String getConflictCount(int conflictNum, int totalConflicts) {
		return "Conflict #" + ConflictUtility.getNumberString(conflictNum) + " of " +
			ConflictUtility.getNumberString(totalConflicts);
	}

	private String createNameInfo(String name) {
		return "External Program Name: " + ConflictUtility.getEmphasizeString(name);
	}

	/**
	 * Actually merges the indicated program name from the program version indicated
	 * by conflictOption into the result program.
	 * @param idGroup the symbol ID group for the external program (Library) to merge.
	 * @param chosenConflictOption conflict option indicating the program version the user chose.
	 * @param monitor the task monitor for feedback and canceling.
	 * @throws CancelledException if the user cancels the merge.
	 */
	private void merge(IDGroup idGroup, int chosenConflictOption, TaskMonitor monitor) {
		Program fromPgm = null;
		switch (chosenConflictOption) {
			case KEEP_LATEST:
				fromPgm = latestPgm;
				break;
			case KEEP_MY:
				fromPgm = myPgm;
				break;
			case KEEP_ORIGINAL:
				fromPgm = originalPgm;
				break;
			default:
				return;
		}
		mergeExternalProgramName(resultPgm, fromPgm, idGroup, monitor);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#hasConflict(ghidra.program.model.address.Address)
	 */
	public boolean hasConflict() {
		return (extPgms.size() > 0);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#getConflictCount(ghidra.program.model.address.Address)
	 */
	public int getConflictCount() {
		return extPgms.size();
	}

	/**
	 * Returns an array of symbol ID groups for all the external programs that are in conflict.
	 */
	public IDGroup[] getConflicts() {
		return extPgms.toArray(new IDGroup[extPgms.size()]);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#getName()
	 */
	@Override
	public String getName() {
		return "External Program Merger";
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#getDescription()
	 */
	@Override
	public String getDescription() {
		return "Merge External Program Names";
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.AbstractListingMerger#getConflictType()
	 */
	String getConflictType() {
		return "External Program Name";
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#apply()
	 */
	@Override
	public void apply() {
		conflictOption = conflictPanel.getSelectedOptions();

		// If the "Use For All" check box is selected
		// then save the option chosen for this conflict type.
		if (conflictPanel.getUseForAll()) {
			externalProgramChoice = conflictOption;
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#cancel()
	 */
	@Override
	public void cancel() {
		conflictOption = CANCELED;
		if (conflictPanel != null) {
			conflictPanel.clear();
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#merge(ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void merge(TaskMonitor monitor) {

		mergeManager.setInProgress(EXTERNAL_PROGRAM_PHASE);
		int transactionID = resultPgm.startTransaction(getDescription());
		boolean commit = false;
		try {
			monitor.checkCanceled();
			clearResolveInfo();

			autoMerge(monitor);

			monitor.checkCanceled();
			mergeConflicts(ASK_USER, monitor);
			monitor.checkCanceled();
			clearConflictPanel();
			showResolveInfo();
			commit = true;
		}
		catch (CancelledException e) {
			mergeManager.setStatusText("User cancelled merge.");
			cancel();
		}
		finally {
			resultPgm.endTransaction(transactionID, commit);
		}
		mergeManager.setCompleted(EXTERNAL_PROGRAM_PHASE);
	}

	private void clearConflictPanel() {
		try {
			SwingUtilities.invokeAndWait(new Runnable() {
				@Override
				public void run() {
					if (conflictPanel != null) {
						conflictPanel.clear();
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
	 * Actually merges (sets or removes) the indicated external program name in
	 * program1 based on the same external program name in program2
	 * @param program1 the program to merge into.
	 * @param program2 the program to get the merge information from.
	 * @param idGroup the symbol ID group for the external program (Library) to merge.
	 * @param monitor task monitor for feedback or canceling the merge.s
	 */
	public void mergeExternalProgramName(Program program1, Program program2, IDGroup idGroup,
			TaskMonitor monitor) {
		ExternalManager em1 = program1.getExternalManager();
		ExternalManager em2 = program2.getExternalManager();
		String libName1 = idGroup.getName(program1);
		String libName2 = idGroup.getName(program2);
		if (libName2 != null && em2.contains(libName2)) {
			try {
				em1.setExternalPath(libName2, em2.getExternalLibraryPath(libName2),
					isExternalUserDefined(program2, libName2));
			}
			catch (InvalidInputException e) {
				Msg.showError(this, null, "Error Setting External Program Name",
					"Couldn't set path to '" + em2.getExternalLibraryPath(libName2) +
						"' for external program name '" + libName2 + "'");
			}
		}
		else {
			if (libName1 != null && em1.contains(libName1)) {
				boolean removed = em1.removeExternalLibrary(libName1);
				if (!removed) {
					Msg.showError(this, null, "Error Removing External Program Name",
						"Couldn't remove external program name '" + libName1 + "'");
				}
			}
		}
	}

	@Override
	public String[][] getPhases() {
		return new String[][] { EXTERNAL_PROGRAM_PHASE };
	}

	private long getResultIDFromOriginalID(long originalSymbolID) {
		try {
			return originalResolvedSymbols.get(originalSymbolID);
		}
		catch (NoValueException e) {
			if (resultPgm.getSymbolTable().getSymbol(originalSymbolID) != null) {
				return originalSymbolID;
			}
		}
		return -1;
	}

	private long getResultIDFromLatestID(long latestSymbolID) throws NoValueException {
		try {
			return latestResolvedSymbols.get(latestSymbolID);
		}
		catch (NoValueException e) {
			if (resultPgm.getSymbolTable().getSymbol(latestSymbolID) != null) {
				return latestSymbolID;
			}
			Symbol latestSymbol = latestPgm.getSymbolTable().getSymbol(latestSymbolID);
			if (latestSymbol != null) {
				Symbol resultSymbol = SimpleDiffUtility.getSymbol(latestSymbol, resultPgm);
				if (resultSymbol != null) {
					return resultSymbol.getID();
				}
			}
			throw e;
		}
	}

	private long getResultIDFromMyID(long mySymbolID) throws NoValueException {
		try {
			return myResolvedSymbols.get(mySymbolID);
		}
		catch (NoValueException e) {
			Symbol originalSymbol = originalPgm.getSymbolTable().getSymbol(mySymbolID);
			if (originalSymbol == null) {
				throw e;
			}
			if (resultPgm.getSymbolTable().getSymbol(mySymbolID) != null) {
				return mySymbolID;
			}
			Symbol mySymbol = myPgm.getSymbolTable().getSymbol(mySymbolID);
			if (mySymbol != null) {
				Symbol resultSymbol = SimpleDiffUtility.getSymbol(mySymbol, resultPgm);
				if (resultSymbol != null) {
					return resultSymbol.getID();
				}
			}
			throw e;
		}
	}

	/**
	 * IDGroup is used to associate the symbol IDs from each of the four programs
	 * (Result, Original, Latest, My) for a single symbol. If the symbol doesn't
	 * exist for any particular program a -1 is entered for its ID.
	 */
	private class IDGroup {

		private long resultID;
		private long originalID;
		private long latestID;
		private long myID;

		/**
		 * Creates a group of IDs in the four programs for a particular symbol.
		 * @param resultID the symbol's ID in the Result program or -1 if it doesn't exist in Result.
		 * @param originalID the symbol's ID in the Original program or -1 if it doesn't exist in Original.
		 * @param latestID the symbol's ID in the Latest program or -1 if it doesn't exist in Latest.
		 * @param myID the symbol's ID in the My program or -1 if it doesn't exist in My.
		 */
		private IDGroup(long resultID, long originalID, long latestID, long myID) {
			this.resultID = resultID;
			this.originalID = originalID;
			this.latestID = latestID;
			this.myID = myID;
		}

		private long getResultID() {
			return resultID;
		}

		private Symbol getResultSymbol() {
			SymbolTable resultSymbolTable = resultPgm.getSymbolTable();
			return (resultID != -1) ? resultSymbolTable.getSymbol(resultID) : null;
		}

		private Symbol getOriginalSymbol() {
			SymbolTable originalSymbolTable = originalPgm.getSymbolTable();
			return (originalID != -1) ? originalSymbolTable.getSymbol(originalID) : null;
		}

		private Symbol getLatestSymbol() {
			SymbolTable latestSymbolTable = latestPgm.getSymbolTable();
			return (latestID != -1) ? latestSymbolTable.getSymbol(latestID) : null;
		}

		private Symbol getMySymbol() {
			SymbolTable mySymbolTable = myPgm.getSymbolTable();
			return (myID != -1) ? mySymbolTable.getSymbol(myID) : null;
		}

		private String getResultName() {
			Symbol resultSymbol = getResultSymbol();
			return (resultSymbol != null) ? resultSymbol.getName() : null;
		}

		private String getOriginalName() {
			Symbol originalSymbol = getOriginalSymbol();
			return (originalSymbol != null) ? originalSymbol.getName() : null;
		}

		private String getLatestName() {
			Symbol latestSymbol = getLatestSymbol();
			return (latestSymbol != null) ? latestSymbol.getName() : null;
		}

		private String getMyName() {
			Symbol mySymbol = getMySymbol();
			return (mySymbol != null) ? mySymbol.getName() : null;
		}

		/**
		 * Gets a name to display for the symbol. If the names int the 4 programs differ or
		 * a program doesn't have a symbol, the first one found is returned.
		 * Programs are checked in this order: Result, Original, Latest, My.
		 * @return the first discovered name for the symbol or "unknown".
		 */
		private String getName() {
			String resultName = getResultName();
			String originalName = getOriginalName();
			String latestName = getLatestName();
			String myName = getMyName();
			return (resultName != null) ? resultName
					: (originalName != null) ? originalName
							: (latestName != null) ? latestName
									: (myName != null) ? myName : "unknown";
		}

		/**
		 * Get the name of the symbol in the indicated program or null if it doesn't exist in
		 * the indicated program.
		 * @param program the program (Result, Original, Latest, My) to check.
		 * @return the symbol name or null.
		 */
		private String getName(Program program) {
			if (program == resultPgm) {
				return getResultName();
			}
			if (program == originalPgm) {
				return getOriginalName();
			}
			if (program == latestPgm) {
				return getLatestName();
			}
			if (program == myPgm) {
				return getMyName();
			}
			return null;
		}
	}
}
