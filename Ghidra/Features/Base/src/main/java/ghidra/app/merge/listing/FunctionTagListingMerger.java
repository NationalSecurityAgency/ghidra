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

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

import javax.swing.SwingUtilities;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import ghidra.app.merge.tool.ListingMergePanel;
import ghidra.app.merge.util.ConflictUtility;
import ghidra.program.database.function.FunctionManagerDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Handles merging of function tags when they are added/removed from 
 * functions. 
 * 
 * Most merging can be done automatically; the exception being when a
 * tag has been added to a function by one user, but deleted from the
 * program by another.
 * 
 * Note that there are other tag related conflict cases, but they are 
 * handled by the {@link FunctionTagMerger}, which handles all aspects of
 * creation/deletion/editing of tags independent of functions. 
 * 
 * THIS CLASS ONLY DEALS WITH FUNCTION-RELATED ADDS/REMOVES.
 * 
 * The specific cases handled by the class are described below:
 * 
 *  - X and Y are tags
 *  - ** indicates a conflict
 *  
 * 		User A	|	Add X	Add Y	Delete X	Delete Y	
 * 				|
 * User B		|
 * -------------------------------------------------------
 * Add X		|	X		X,Y			**			X		
 * 				|
 * Add Y		|	X,Y		Y			Y			**		
 * 				|
 * Delete X		|	**		Y			-			-				
 * 				|
 * Delete Y		|	X		**			-			-		
 * 
 * 
 */
public class FunctionTagListingMerger extends AbstractListingMerger {

	final static String[] FUNCTION_TAG_LISTING_PHASE = { "Function Tags" };

	private VerticalChoicesPanel conflictPanel;

	// Keeps track of all the conflicts found during the merge process. This maps
	// which tag IDs are in conflict at which address.
	private Map<Address, List<Long>> conflictMap = new HashMap<>();

	// Keeps track of the tag currently being addressed in the 
	// conflict resolution panel. If there are multiple conflicts, even at 
	// the same address, they will still require separate conflict
	// panels. This keeps track of which one we're currently resolving.
	private Long currentlyMergingTagID = null;
	
	private int tagChoice = ASK_USER;

	/**
	 * Constructor.
	 * 
	 * @param listingMergeMgr the listing merge manager that owns this merger.
	 */
	public FunctionTagListingMerger(ListingMergeManager listingMergeMgr) {
		super(listingMergeMgr);
	}

	/******************************************************************************
	 * PUBLIC METHODS
	 ******************************************************************************/

	@Override
	public void init() {
		super.init();
	}

	@Override
	public String getConflictType() {
		return "Function Tags";
	}

	@Override
	public int getConflictCount(Address addr) {
		int count = 0;
		if (hasConflict(addr)) {
			List<Long> conflicts = conflictMap.get(addr);
			count = conflicts.size();
		}
		return count;
	}

	@Override
	public boolean apply() {
		conflictOption = conflictPanel.getSelectedOptions();

		// If the "Use For All" check box is selected 
		// then save the option chosen for this conflict type.
		if (conflictPanel.getUseForAll()) {
			tagChoice = conflictOption;
		}

		return super.apply();
	}

	/**
	 * Stores the users' selection for how to handle a conflict.
	 * 
	 * @param option user option, from {@link ListingMergeConstants}
	 */
	public void setConflictResolution(int option) {
		this.conflictOption = option;
		this.tagChoice = option;
	}

	@Override
	public void autoMerge(int progressMin, int progressMax, TaskMonitor monitor)
			throws ProgramConflictException, MemoryAccessException, CancelledException {

		initializeAutoMerge("Auto-merging Function Tags and determining conflicts.", progressMin,
			progressMax, monitor);

		updateProgress(0, "Auto-merging Function Tags and determining conflicts.");

		try {
			autoMerge(ProgramDiffFilter.FUNCTION_TAG_DIFFS, monitor);
		}
		catch (IOException e) {
			Msg.error(this, "Error performing auto merge: " + e);
		}

		updateProgress(100, "Done auto-merging Function Tags and determining conflicts.");
	}

	@Override
	public AddressSetView getConflicts() {
		AddressSet conflicts = new AddressSet();
		for (Address addr : conflictMap.keySet()) {
			conflicts.add(addr);
		}
		return conflicts;
	}

	@Override
	public boolean hasConflict(Address addr) {
		return conflictMap.keySet().contains(addr);
	}

	@Override
	public void mergeConflicts(ListingMergePanel listingPanel, Address addr,
			int chosenConflictOption, TaskMonitor monitor)
			throws CancelledException, MemoryAccessException {

		// First do a sanity check and see if this address has any conflicts.
		if (!hasConflict(addr)) {
			return;
		}

		monitor.setMessage("Resolving Function Tag conflicts.");

		boolean askUser = chosenConflictOption == ASK_USER;

		// If we're supposed to ask the user for their preferred conflict option, show
		// the merge panel. But ask check the choice (tagChoice) again after each
		// tag resolution to see if we should be using the "useForAll" option.
		//
		if ((tagChoice == ASK_USER) && askUser && mergeManager != null) {
			if (conflictMap.containsKey(addr)) {
				List<Long> ids = conflictMap.get(addr);

				// Loop over all conflicts at this address....
				for (Long id : ids) {
					currentlyMergingTagID = id;

					// Make sure we're supposed to prompt the user; if not, just use the 
					// previous choice and merge.
					if (tagChoice != ASK_USER) {
						int optionToUse =
							(tagChoice == ASK_USER) ? chosenConflictOption : tagChoice;
						mergeConflictingTag(addr, optionToUse, monitor);
					}
					else {
						showMergePanel(listingPanel, addr, id, monitor);
					}
					monitor.checkCanceled();
				}
			}
		}
		else {
			int optionToUse = (tagChoice == ASK_USER) ? chosenConflictOption : tagChoice;

			if (conflictMap.containsKey(addr)) {
				List<Long> ids = conflictMap.get(addr);
				for (Long id : ids) {
					currentlyMergingTagID = id;
					mergeConflictingTag(addr, optionToUse, monitor);
				}
			}
		}
	}

	/******************************************************************************
	 * PRIVATE METHODS
	 ******************************************************************************/

	/**
	 * Attempts to merge changes between the My and Latest versions of the program. Conflicts
	 * will be stored in the {@link #conflictMap} for later resolution.
	 * 
	 * @param diffType from {@link ProgramDiffFilter}
	 * @param monitor task monitor
	 * @throws ProgramConflictException
	 * @throws CancelledException
	 * @throws IOException
	 */
	private void autoMerge(int diffType, TaskMonitor monitor)
			throws ProgramConflictException, CancelledException, IOException {

		// Get the address of all changes in Latest and My. These changes are guaranteed to ONLY be
		// additions/removals of tags from the address; tag creations/deletions/edits will not be 
		// in these change sets.
		AddressSetView myChangedAddresses =
			listingMergeMgr.diffOriginalMy.getDifferences(new ProgramDiffFilter(diffType), monitor);
		AddressSetView latestChangedAddresses = listingMergeMgr.diffOriginalLatest.getDifferences(
			new ProgramDiffFilter(diffType), monitor);

		// Get a list of all deleted tags in My and Latest.
		Collection<? extends FunctionTag> myDeletedTags =
			getDeletedTags(myPgm, monitor);
		Collection<? extends FunctionTag> latestDeletedTags =
			getDeletedTags(latestPgm, monitor);

		// Loop over all changed addresses in My and see if any added tags are in the 
		// Latest delete list. If so, conflict panel!
		processChangedAddresses(myChangedAddresses, latestDeletedTags, myPgm);

		// Now go to the other, looping over all addresses in Latest to see if any
		// added tags are in the My delete list.
		processChangedAddresses(latestChangedAddresses, myDeletedTags, latestPgm);
	}

	/**
	 * Determines if any deleted tags from one program were added to a function in
	 * the other. If so, updates the conflict list with the offending tag/address.
	 * 
	 * If there is no conflict for a particular address, the changes are automatically
	 * merged.
	 * 
	 * @param changedAddresses list of addresses to inspect
	 * @param deletedTags all tags deleted in the 'other' program
	 * @param programAddedTo the program in which the adds reside
	 * @throws IOException
	 */
	private void processChangedAddresses(AddressSetView changedAddresses,
			Collection<? extends FunctionTag> deletedTags, Program programAddedTo)
			throws IOException {

		FunctionManagerDB functionManager = (FunctionManagerDB) resultPgm.getFunctionManager();

		AddressIterator iter = changedAddresses.getAddresses(true);
		while (iter.hasNext()) {
			Address addr = iter.next();
			Function function = functionManager.getFunctionAt(addr);
			if (function == null) {
				continue;
			}
			
			// Get all the tags added to the function and compare against
			// the delete list.
			Collection<FunctionTag> tags = getTagsAddedToFunction(programAddedTo, addr);
			for (FunctionTag tag : tags) {

				if (deletedTags.contains(tag)) {
					addToConflicts(addr, tag);
					continue;
				}

				// Not a conflict, so add to Result.
				function.addTag(tag.getName());
			}
		}
	}

	/**
	 * Adds the given tag/address combo to the global conflict list.
	 * 
	 * @param addr the conflicting address
	 * @param tag the conflicting tag
	 */
	private void addToConflicts(Address addr, FunctionTag tag) {
		if (conflictMap.get(addr) == null) {
			conflictMap.put(addr, new ArrayList<>());
		}
		List<Long> idList = conflictMap.get(addr);
		idList.add(tag.getId());
		conflictMap.put(addr, idList);
	}

	/**
	 * Returns all tags that were added to the function at the given address.
	 * 
	 * @param program the program where the function resides
	 * @param addr the function entry point
	 * @return
	 */
	private Collection<FunctionTag> getTagsAddedToFunction(Program program, Address addr) {

		// The set to return.
		Collection<FunctionTag> tags = new HashSet<>();

		// Do a check to see if a function even exists in the given program. If the entire
		// function were deleted, it won't.
		Function function = program.getListing().getFunctionContaining(addr);
		if (function == null) {
			return tags;
		}

		tags = program.getListing().getFunctionContaining(addr).getTags();

		// Do a sanity check in case the function didn't exist in the Original program. This
		// could happen if the function was created before the merge.
		Function originalFunction = originalPgm.getListing().getFunctionContaining(addr);
		if (originalFunction != null) {
			Collection<FunctionTag> originalTags = originalFunction.getTags();

			// Get the difference between the collections, which will be the tags added.
			tags.removeAll(originalTags);
		}

		return tags;
	}

	/**
	 * Compares the given program against Original to determine if any tags differ 
	 * between the two. Any tags in Original that are NOT in the given program 
	 * indicate deletions.
	 * 
	 * @param program the program version 
	 * @param monitor
	 * @return database IDs from the FunctionTagAdapter table that were deleted
	 */
	private Collection<? extends FunctionTag> getDeletedTags(Program program, TaskMonitor monitor) {

		// 1. Get all tags in the Original database.
		FunctionManagerDB origFunctionManagerDB =
			(FunctionManagerDB) originalPgm.getFunctionManager();
		Collection<? extends FunctionTag> originalTags =
			origFunctionManagerDB.getFunctionTagManager().getAllFunctionTags();

		// 2. Get all tags in the given program database.
		FunctionManagerDB myFunctionManagerDB = (FunctionManagerDB) program.getFunctionManager();
		Collection<? extends FunctionTag> programTags =
			myFunctionManagerDB.getFunctionTagManager().getAllFunctionTags();

		// 3. Determine which ones are in Original but not in the given program.
		originalTags.removeAll(programTags);

		return originalTags;
	}

	/**
	 * Sets up the conflict panel for SINGLE conflict. This will be a standard listing merge 
	 * panel showing all four programs (Latest, My, Original, Result). Choices for 
	 * resolving the conflict will appear at the bottom.
	 * 
	 * @param listingPanel the main panel
	 * @param addr 
	 * @param tagID
	 * @param changeListener
	 */
	private void setupConflictsPanel(ListingMergePanel listingPanel, Address addr, Long tagID,
			ChangeListener changeListener) {

		if (conflictPanel == null) {
			conflictPanel = new VerticalChoicesPanel();
			currentConflictPanel = conflictPanel;
		}
		else {
			conflictPanel.clear();
		}

		conflictPanel.setTitle("Function Tags");
		conflictPanel.setConflictType("Function Tags");

		try {
			FunctionTag originalTag = getTag(tagID, originalPgm);
			String original = originalTag == null ? "<tag deleted>" : originalTag.getName();

			FunctionTag latestTag = getTag(tagID, latestPgm);
			String latest = latestTag == null ? "<tag deleted>" : latestTag.getName();

			FunctionTag myTag = getTag(tagID, myPgm);
			String my = myTag == null ? "<tag deleted>" : myTag.getName();
			
			conflictPanel.setRowHeader(new String[] { "Option", "Function Tags" });
			String text = "Function Tag conflict @ address :" + ConflictUtility.getAddressString(addr);
			conflictPanel.setHeader(text);

			conflictPanel.setRowHeader(getFunctionTagInfo(-1, null));
			conflictPanel.addRadioButtonRow(getFunctionTagInfo(LATEST, latest), LATEST_BUTTON_NAME,
				KEEP_LATEST, changeListener);
			conflictPanel.addRadioButtonRow(getFunctionTagInfo(MY, my), CHECKED_OUT_BUTTON_NAME,
				KEEP_MY, changeListener);
			conflictPanel.addRadioButtonRow(getFunctionTagInfo(ORIGINAL, original),
				ORIGINAL_BUTTON_NAME, KEEP_ORIGINAL, changeListener);
		}
		catch (IOException e) {
			Msg.error(this, "Error creating conflict dialog for " + tagID + " at address " + addr);
		}
	}

	/**
	 * Returns a string containing the tag and the program version it's associated
	 * with. This is used when displaying the conflict panel.
	 * 
	 * @param version
	 * @param tags
	 * @return
	 */
	private String[] getFunctionTagInfo(int version, String tag) {
		String[] info = new String[] { "Keep", "", tag };

		if (version == LATEST) {
			info[1] = LATEST_TITLE;
		}
		else if (version == MY) {
			info[1] = MY_TITLE;
		}
		else if (version == ORIGINAL) {
			info[1] = ORIGINAL_TITLE;
		}
		else {
			return new String[] { "Option", "Type", "Tags" };
		}

		return info;
	}

	/**
	 * Merges the tag currently being resolved in the conflict panel according to the
	 * given conflict option. This is invoked when the user has made a merge 
	 * selection (keep Original, My, or Latest) in the conflict resolution panel. 
	 * 
	 * @param addr the location of the conflict
	 * @param chosenConflictOption KEEP_ORIGINAL, KEEP_LATEST, KEEP_MY
	 * @param monitor
	 * @throws CancelledException
	 */
	private void mergeConflictingTag(Address addr, int chosenConflictOption,
			TaskMonitor monitor) throws CancelledException {

		int resolutionType = ProgramMergeFilter.MERGE;

		// Set up lists to hold the tags we want to keep and the ones that 
		// are in conflict. The discard list holds the versions of a conflict we 
		// want to throw away; the keep list is the one we want to keep.
		//
		// ie: 	Original 	= "Red"
		//		My 			= "Red-my"
		//		Latest 		= "Red-latest"
		//
		// If the decision is KEEP_LATEST, then "Red-my" and "Red" will be added
		// to the discard list. "Red-latest" will be in the keep list.
		Set<FunctionTag> discardTags = new HashSet<>();
		Set<FunctionTag> keepTags = new HashSet<>();

		try {
			// Get the tag name we're doing resolution on in each of the 
			// three programs. 
			FunctionTag latestTag = getTag(currentlyMergingTagID, latestPgm);
			FunctionTag origTag = getTag(currentlyMergingTagID, originalPgm);
			FunctionTag myTag = getTag(currentlyMergingTagID, myPgm);

			// Now add those names to the proper list given the user selection.
			if ((chosenConflictOption & KEEP_ORIGINAL) != 0) {
				if (myTag != null) {
					discardTags.add(myTag);
				}
				if (latestTag != null) {
					discardTags.add(latestTag);
				}
				if (origTag != null) {
					keepTags.add(origTag);
				}
			}
			if ((chosenConflictOption & KEEP_LATEST) != 0) {
				if (myTag != null) {
					discardTags.add(myTag);
				}
				if (origTag != null) {
					discardTags.add(origTag);
				}
				if (latestTag != null) {
					keepTags.add(latestTag);
				}
			}
			if ((chosenConflictOption & KEEP_MY) != 0) {
				if (latestTag != null) {
					discardTags.add(latestTag);
				}
				if (origTag != null) {
					discardTags.add(origTag);
				}
				if (myTag != null) {
					keepTags.add(myTag);
				}
			}

			// And finally do the merge.
			listingMergeMgr.mergeOriginal.applyFunctionTagChanges(new AddressSet(addr),
				resolutionType, discardTags, keepTags, monitor);
		}
		catch (IOException e) {
			Msg.error(this, "Error merging addr: " + addr, e);
		}
	}

	/**
	 * Displays the conflict resolution panel for a single tag ID at the specified
	 * address.
	 *
	 * @param listingPanel the listing panel to display
	 * @param addr the address where the merge is occurring
	 * @param tagID the tag id being merged
	 * @param monitor the task monitor
	 */
	private void showMergePanel(final ListingMergePanel listingPanel, final Address addr,
			Long tagID, TaskMonitor monitor) {

		this.currentAddress = addr;
		this.currentMonitor = monitor;

		try {
			final ChangeListener changeListener = new ChangeListener() {
				@Override
				public void stateChanged(ChangeEvent e) {

					// If choice has already been set, then just use that option and don't
					// prompt the user.
					conflictOption = conflictPanel.getSelectedOptions();
					if (conflictOption == ASK_USER) {
						if (mergeManager != null) {
							mergeManager.setApplyEnabled(false);
							try {
								mergeConflictingTag(addr, KEEP_LATEST, currentMonitor);
							}
							catch (CancelledException ce) {
								// no need to do anything
							}
						}
						return;
					}
					if (mergeManager != null) {
						mergeManager.clearStatusText();
					}
					try {
						mergeConflictingTag(addr, conflictOption, currentMonitor);
					}
					catch (CancelledException ce) {
						// no need to do anything
					}
					if (mergeManager != null) {
						mergeManager.setApplyEnabled(true);
					}
				}
			};
			SwingUtilities.invokeAndWait(new Runnable() {
				@Override
				public void run() {
					setupConflictsPanel(listingPanel, FunctionTagListingMerger.this.currentAddress, tagID,
						changeListener);
					listingPanel.setBottomComponent(conflictPanel);
				}
			});
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					Address addressToShow = FunctionTagListingMerger.this.currentAddress;
					listingPanel.clearAllBackgrounds();
					if (addressToShow != null) {
						listingPanel.paintAllBackgrounds(getCodeUnitAddressSet(addressToShow));
						listingPanel.goTo(addressToShow);
					}
				}
			});
		}
		catch (InterruptedException | InvocationTargetException e) {
			Msg.showError(this, null, "Merge Error", "Error displaying merge panel", e);
			return;
		}

		if (mergeManager != null) {
			mergeManager.setApplyEnabled(false);
			mergeManager.showListingMergePanel(currentAddress);
		}
	}

	/**
	 * Returns the {@link FunctionTag} for the tag ID given.
	 * 
	 * @param id the tag ID
	 * @param program the program version
	 * @return null if tag not found for the given id
	 * @throws IOException
	 */
	private FunctionTag getTag(Long id, Program program) throws IOException {
		FunctionManagerDB functionManagerDB = (FunctionManagerDB) program.getFunctionManager();
		FunctionTag tag = functionManagerDB.getFunctionTagManager().getFunctionTag(id);
		return tag;
	}
}
