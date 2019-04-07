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
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

import javax.swing.SwingUtilities;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import ghidra.app.merge.*;
import ghidra.app.util.HelpTopics;
import ghidra.program.database.function.FunctionManagerDB;
import ghidra.program.database.function.FunctionTagManagerDB;
import ghidra.program.model.listing.*;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Class for merging function tag changes. Most tag differences can be easily auto-merged, 
 * which is to say the result will be the set of all of tags from both program 1 and 
 * program 2. Conflicts arise when both parties have edited/deleted the same tag.
 * 
 * The specific cases handled by the class are described below, where:
 * 
 *  - X and Y are tags
 *  - X(A) means to take A's version of tag X
 *  - ** indicates a conflict
 *  - NP means the situation is not possible
 *  
 * 		User A	|	Add X	Add Y	Delete X	Delete Y	Edit X		Edit Y
 * 				|
 * User B		|
 * ---------------------------------------------------------------------------
 * Add X		|	X		X,Y			NP			X		NP			X,Y(A)
 * 				|
 * Add Y		|	X,Y		Y			Y			NP		X(A),Y		NP
 * 				|
 * Delete X		|	NP		Y			-			-		**			Y(A)		
 * 				|
 * Delete Y		|	X		NP			-			-		X(A)		**
 * 				|
 * Edit X		|	NP		X(B),Y		**			X(B)	**			X(B),Y(A)	
 * 				|
 * Edit Y		|	X,Y(B)	NP			Y(B)		**		X(A),Y(B)	**
 */
public class FunctionTagMerger implements MergeResolver, ListingMergeConstants {

	private static String[] FUNCTION_TAG_PHASE = new String[] { "Function Tags" };

	protected static final int RESULT = MergeConstants.RESULT;
	protected static final int LATEST = MergeConstants.LATEST;
	protected static final int MY = MergeConstants.MY;
	protected static final int ORIGINAL = MergeConstants.ORIGINAL;

	private ProgramMultiUserMergeManager mergeManager;

	// The 4 programs that contain all the info we need to do a merge:
	//  Result: 	contains the result of the merge (what will be checked in)
	//	Original: 	The state of the program before any changes
	//	Latest:		The state of the checked in program
	// 	My:			The state of the checked out program
	private Program resultProgram;
	private Program originalProgram;
	private Program latestProgram;
	private Program myProgram;

	// Contains info about all of the tag changes between Latest and 
	// Original.
	ProgramChangeSet latestChanges;

	// Contains info about all of the tag changes between My and 
	// Original.
	ProgramChangeSet myChanges;

	private VerticalChoicesPanel conflictPanel;
	private int conflictOption;
	private int conflictChoice = ASK_USER;

	// Stores all tag IDs that are in conflict, along with a description of the problem that 
	// caused the conflict.
	private Map<Long, String> tagConflicts = new HashMap<>();

	// Stores the ID of the tag currently being merged. This is useful when we're in
	// the middle of resolving multiple conflicts.
	private long currentlyMergingTagID;


	/**
	 * Constructor.
	 * 
	 * @param mergeManager the merge manager
	 * @param resultPgm the program storing the result of the merge
	 * @param originalPgm the state of the program before any changes
	 * @param latestPgm	the checked in program version
	 * @param myPgm	the checked out program version
	 * @param latestChanges	tag changes in Latest
	 * @param myChanges tag changes in My
	 */
	public FunctionTagMerger(ProgramMultiUserMergeManager mergeManager, Program resultPgm,
			Program originalPgm, Program latestPgm, Program myPgm, ProgramChangeSet latestChanges,
			ProgramChangeSet myChanges) {

		this.mergeManager = mergeManager;
		this.resultProgram = resultPgm;
		this.originalProgram = originalPgm;
		this.latestProgram = latestPgm;
		this.myProgram = myPgm;
		this.myChanges = myChanges;
		this.latestChanges = latestChanges;
	}

	/******************************************************************************
	 * PUBLIC METHODS
	 ******************************************************************************/

	@Override
	public String getName() {
		return "Function Tag Merger";
	}

	@Override
	public String getDescription() {
		return "Merge Function Tags";
	}

	@Override
	public void apply() {
		conflictOption = conflictPanel.getSelectedOptions();

		// If the "Use For All" check box is selected 
		// then save the option chosen for this conflict type.
		if (conflictPanel.getUseForAll()) {
			conflictChoice = conflictOption;
		}
	}

	@Override
	public void cancel() {
		conflictOption = CANCELED;
		if (conflictPanel != null) {
			conflictPanel.clear();
		}
	}


	@Override
	public void merge(TaskMonitor monitor) throws Exception {
		autoMerge();
		handleConflicts(monitor);

		// When done, remove the merge conflict panel, if it's hidden.
		if (conflictPanel != null) {
			mergeManager.removeComponent(conflictPanel);
			conflictPanel = null;
		}
	}

	@Override
	public String[][] getPhases() {
		return new String[][] { FUNCTION_TAG_PHASE };
	}

	/******************************************************************************
	 * PRIVATE METHODS
	 ******************************************************************************/

	/**
	 * Displays a conflict resolution panel for each conflict discovered during
	 * {@link #autoMerge()}.
	 * 
	 * @param monitor the task monitor
	 * @throws CancelledException
	 */
	private void handleConflicts(TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Resolving Function Tag conflicts");
		boolean askUser = (conflictOption == ASK_USER);

		int totalConflicts = tagConflicts.size();
		monitor.initialize(totalConflicts);
		for (long id : tagConflicts.keySet()) {
			if ((conflictChoice == ASK_USER) && askUser && mergeManager != null) {
				monitor.checkCanceled();
				currentlyMergingTagID = id;
				showMergePanel(id, monitor);
			}
			else {
				int optionToUse = (conflictChoice == ASK_USER) ? conflictOption : conflictChoice;
				currentlyMergingTagID = id;
				merge(optionToUse, monitor);
			}
			monitor.incrementProgress(1);

			int pctComplete = (int) ((monitor.getProgress() / totalConflicts) * 100);
			mergeManager.updateProgress(pctComplete);
		}
	}

	/**
	 * Merges the desired program (based on the provided option) into the Result program.
	 * 
	 * @param chosenConflictOption conflict option indicating the program version to use.
	 * @param monitor the task monitor
	 * @throws CancelledException
	 */
	private void merge(int chosenConflictOption, TaskMonitor monitor) throws CancelledException {
		Program fromPgm = null;
		switch (chosenConflictOption) {
			case KEEP_LATEST:
				fromPgm = latestProgram;
				break;
			case KEEP_MY:
				fromPgm = myProgram;
				break;
			case KEEP_ORIGINAL:
				fromPgm = originalProgram;
				break;
			default:
				return;
		}

		try {
			merge(fromPgm, monitor);
		}
		catch (IOException e) {
			Msg.error(this, "error merging conflict", e);
		}
	}

	/**
	 * Merges the tag being currently resolved into the Result program. 
	 * 
	 * @param sourceProgram
	 * @param monitor
	 * @throws CancelledException
	 * @throws IOException
	 */
	private void merge(Program sourceProgram, TaskMonitor monitor)
			throws CancelledException, IOException {

		// First get the tag from the source program and Result		
		FunctionTag tag = getTag(sourceProgram, currentlyMergingTagID);
		FunctionTag resultTag = getTag(resultProgram, currentlyMergingTagID);

		// Get the Result tag manager so we can use it to store the new 
		// tag info.
		FunctionManagerDB functionManagerDBResult =
			(FunctionManagerDB) resultProgram.getFunctionManager();

		int transactionID = resultProgram.startTransaction(getDescription());

		try {
			// If the source program tag doesn't exist then the user has chosen to 
			// keep a deleted tag, so make sure the corresponding tag in Result
			// is deleted as well. 
			if (tag == null ) {
				if (resultTag != null) {
					resultTag.delete();
				}
			}

			// If the source tag exists, but the Result tag doesn't, we have to create a new
			// one in Result.
			else if (resultTag == null) {
				functionManagerDBResult.getFunctionTagManager().createFunctionTag(tag.getName(),
					tag.getComment());
			}

			// If the source tag exists and Result tag exists, just update the tag 
			// attributes in Result.
			else {
				resultTag.setName(tag.getName());
				resultTag.setComment(tag.getComment());
			}
		}
		finally {
			resultProgram.endTransaction(transactionID, true);
		}

		mergeManager.setCompleted(FUNCTION_TAG_PHASE);
	}

	/**
	 * Returns the {@link FunctionTag} instance for the given program and tag ID.
	 * 
	 * @param program the program version to use
	 * @param id the tag id
	 * @return the tag, or null if not found
	 */
	private FunctionTag getTag(Program program, long id) {
		FunctionManagerDB functionManagerDBResult =
			(FunctionManagerDB) program.getFunctionManager();
		FunctionTag tag =
			functionManagerDBResult.getFunctionTagManager().getFunctionTag(id);

		return tag;
	}

	/**
	 * Attempts to merge all tag changes between My and Latest. Any conflicts
	 * will be stored in {@link #tagConflicts} for later resolution.
	 * 
	 * @throws IOException
	 */
	private void autoMerge() throws IOException {

		//
		// Get the tag managers for each of the program versions.
		//
		FunctionManagerDB myFunctionManagerDB = (FunctionManagerDB) myProgram.getFunctionManager();
		FunctionTagManagerDB tagManagerMY =
			(FunctionTagManagerDB) myFunctionManagerDB.getFunctionTagManager();

		FunctionManagerDB latestFunctionManagerDB =
			(FunctionManagerDB) latestProgram.getFunctionManager();
		FunctionTagManagerDB tagManagerLATEST =
			(FunctionTagManagerDB) latestFunctionManagerDB.getFunctionTagManager();

		FunctionManagerDB resultFunctionManagerDB =
			(FunctionManagerDB) resultProgram.getFunctionManager();
		FunctionTagManagerDB tagManagerRESULT =
			(FunctionTagManagerDB) resultFunctionManagerDB.getFunctionTagManager();

		FunctionManagerDB originalFunctionManagerDB =
			(FunctionManagerDB) originalProgram.getFunctionManager();
		FunctionTagManagerDB tagManagerORIGINAL =
			(FunctionTagManagerDB) originalFunctionManagerDB.getFunctionTagManager();

		// Get the IDs for all changes (adds/edits/deletes) we have to process.  Note that
		// the 'change' lists contain BOTH edits and deletes; so we have to separate them
		// into their own lists below.
		long[] myAdditionIDs = myChanges.getTagCreations();
		long[] myChangeIDs = myChanges.getTagChanges();
		long[] latestAdditionIDs = latestChanges.getTagCreations();
		long[] latestChangeIDs = latestChanges.getTagChanges();

		List<Long> myEditedIDs = getEdits(myChangeIDs, tagManagerMY, tagManagerORIGINAL);
		List<Long> latestEditedIDs =
			getEdits(latestChangeIDs, tagManagerLATEST, tagManagerORIGINAL);
		List<Long> myDeletedIDs = getDeletes(myChangeIDs, tagManagerMY, tagManagerORIGINAL);
		List<Long> latestDeletedIDs =
			getDeletes(latestChangeIDs, tagManagerLATEST, tagManagerORIGINAL);

		// Now do the actual merging...
		int transactionID = resultProgram.startTransaction(getDescription());

		try {
			mergeAdditions(tagManagerMY, tagManagerLATEST, tagManagerRESULT, myAdditionIDs,
				latestAdditionIDs);

			mergeDeletions(tagManagerRESULT, myEditedIDs, latestEditedIDs, myDeletedIDs,
				latestDeletedIDs);

			mergeEdits(tagManagerMY, tagManagerLATEST, tagManagerRESULT, myEditedIDs,
				latestEditedIDs, latestDeletedIDs);
		}
		finally {
			resultProgram.endTransaction(transactionID, true);
		}
	}

	/**
	 * Merges tags that have been edited (name/comment changed). 
	 * 
	 * CONFLICT CASES:
	 * 	1. The same tag has been edited in both programs, either the name or comment.
	 * 
	 * Note that the conflict case of a tag being edited in one program and 
	 * deleted in another is handled in {@link #mergeDeletions(FunctionTagManagerDB, List, List, List, List)}.
	 */
	private void mergeEdits(FunctionTagManagerDB tagManagerMY,
			FunctionTagManagerDB tagManagerLATEST, FunctionTagManagerDB tagManagerRESULT,
			List<Long> myEditedIDs, List<Long> latestEditedIDs, List<Long> latestDeletedIDs) {

		String CONFLICT_REASON = "Tag name and/or comment edited in both programs";

		for (long id : myEditedIDs) {

			FunctionTag tagMy = tagManagerMY.getFunctionTag(id);

			if (latestEditedIDs.contains(id)) {
				tagConflicts.put(id, CONFLICT_REASON);
			}
			else {
				// Do a check here on the deleted list. If the tag was deleted in Latest, then
				// it won't exist in Result so we don't want to try to do an update. This is ok
				// since the edit/delete conflict would have already been noticed and added to
				// the conflict list in #mergeDeletes().
				if (!latestDeletedIDs.contains(id)) {
					FunctionTag functionTag = tagManagerRESULT.getFunctionTag(id);
					if (functionTag != null) {
						functionTag.setName(tagMy.getName());
						functionTag.setComment(tagMy.getComment());
					}
					
				}
			}
		}
		for (long id : latestEditedIDs) {

			if (myEditedIDs.contains(id)) {
				tagConflicts.put(id, CONFLICT_REASON);
			}
			else {
				// The Result program already has Latest changes in it, so no need to update 
				// it here. If this wasn't the case we'd have to do the following:
				// tagManagerRESULT.updateFunctionTag(id, tagLatest.getName(), tagLatest.getComment());
			}
		}
	}

	/**
	 * Merges tags that have been deleted. 
	 * 
	 * CONFLICT CASES:
	 * 	1. A tag has been deleted in one program, but edited in the other.
	 */
	private void mergeDeletions(FunctionTagManagerDB tagManagerRESULT, List<Long> myEditedIDs,
			List<Long> latestEditedIDs, List<Long> myDeletedIDs, List<Long> latestDeletedIDs) {

		String CONFLICT_REASON = "Tag was deleted in one program but edited in another";

		for (long id : myDeletedIDs) {
			if (latestEditedIDs.contains(id)) {
				tagConflicts.put(id, CONFLICT_REASON);
			}
			else {
				FunctionTag tag = tagManagerRESULT.getFunctionTag(id);
				if (tag != null) {
					tag.delete();
				}
			}
		}
		for (long id : latestDeletedIDs) {
			if (myEditedIDs.contains(id)) {
				tagConflicts.put(id, CONFLICT_REASON);
			}
			else {
				FunctionTag tag = tagManagerRESULT.getFunctionTag(id);
				if (tag != null) {
					tag.delete();
				}
			}
		}
	}

	/**
	 * Merges tags that have been added.
	 * 
	 * CONFLICT CASES: Name is the same, comment is different.
	 */
	private void mergeAdditions(FunctionTagManagerDB tagManagerMY,
			FunctionTagManagerDB tagManagerLATEST, FunctionTagManagerDB tagManagerRESULT,
			long[] myAdditionIDs, long[] latestAdditionIDs) {

		String CONFLICT_REASON = "Identical tag names added, but comments differ";

		for (long id : myAdditionIDs) {
			FunctionTag myTag = tagManagerMY.getFunctionTag(id);
			FunctionTag latestTag = tagManagerLATEST.getFunctionTag(id);

			// Sanity check: If myTag isn't valid, just return and do nothing. If 
			// the latest tag is invalid, just continue with adding what is in My.
			if (myTag == null) {
				return;
			}

			// If the names are the same, but the comments are different...
			if (latestTag != null && myTag.getName().equals(latestTag.getName()) &&
				!(myTag.getComment().equals(latestTag.getComment()))) {
				tagConflicts.put(id, CONFLICT_REASON);
				continue;
			}

			tagManagerRESULT.createFunctionTag(myTag.getName(), myTag.getComment());
		}

		// Note: The Result program already has Latest changes in it, so no need to update 
		// it here. If this wasn't the case we'd have to do the following:
		// for (long id : latestAdditionIDs) {
		//	  FunctionTag tag = tagManagerLATEST.getFunctionTag(id);
		//	  tagManagerRESULT.createFunctionTag(tag.getName(), tag.getComment());
		// }
	}

	/**
	 * Given a list of tag IDs, returns the subset of those who's tags have
	 * been edited. 
	 * 
	 * This is determined by checking the tag attributes in the given
	 * program version against Original.
	 * 
	 * @param ids the full list of ids to check
	 * @param tagManager the source program tag manager
	 * @param originalTagManager the Original program tag manager
	 * @return
	 */
	private List<Long> getEdits(long[] ids, FunctionTagManager tagManager,
			FunctionTagManager originalTagManager) {

		List<Long> retList = new ArrayList<>();

		for (long id : ids) {
			FunctionTag tag = tagManager.getFunctionTag(id);
			FunctionTag originalTag = originalTagManager.getFunctionTag(id);

			// If the tag objects aren't valid, just move to the next id.
			if (tag == null || originalTag == null) {
				continue;
			}

			// If the names and comments aren't the same between the two
			// tags, it's an edit.
			if (!(tag.getName().equals(originalTag.getName())) ||
				!(tag.getComment().equals(originalTag.getComment()))) {
				retList.add(id);
			}
		}
		return retList;
	}

	/**
	 * Given a list of tag IDs, returns the subset of those who's tags have
	 * been deleted.
	 * 
	 * A delete is identified by comparing the given program version against
	 * Original; if the tag exists in the latter but not the former, it was
	 * deleted.
	 * 
	 * @param ids the full list of ids to check
	 * @param tagManager the source program tag manager
	 * @param originalTagManager the Original program tag manager
	 * 
	 * @return
	 */
	private List<Long> getDeletes(long[] ids, FunctionTagManager tagManager,
			FunctionTagManager originalTagManager) {
		List<Long> retList = new ArrayList<>();

		for (long id : ids) {
			FunctionTag tag = tagManager.getFunctionTag(id);
			FunctionTag originalTag = originalTagManager.getFunctionTag(id);

			if (tag == null && originalTag != null) {
				retList.add(id);
			}
		}
		return retList;
	}

	/**
	 * Displays the conflict panel for a tag.
	 * 
	 * @param id the tag id to merge
	 * @param monitor task monitor
	 */
	private void showMergePanel(long id, TaskMonitor monitor) {

		try {
			final ChangeListener changeListener = new ChangeListener() {
				@Override
				public void stateChanged(ChangeEvent e) {
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
					try {
						merge(conflictOption, monitor);
						if (mergeManager != null) {
							mergeManager.setApplyEnabled(true);
						}
					}
					catch (CancelledException e1) {
						// user cancel - no need to log
					}

				}
			};
			SwingUtilities.invokeAndWait(new Runnable() {
				@Override
				public void run() {
					setupConflictPanel(id, changeListener, monitor);
				}
			});
		}
		catch (InterruptedException | InvocationTargetException e) {
			Msg.error(this, "Unexpected error showing merge panel for tag " + id, e);
		}

		if (mergeManager != null) {
			mergeManager.setApplyEnabled(false);
			mergeManager.showComponent(conflictPanel, "FunctionTagMerge",
				new HelpLocation(HelpTopics.REPOSITORY, "FunctionTags"));
		}
		// block until the user either cancels or hits the "Apply" button
		// on the merge dialog...
		// when the "Apply" button is hit, get the user's selection
		// and continue.
	}

	/**
	 * Returns the {@link FunctionTag} for the given tag id.
	 * 
	 * @param id the tag id
	 * @param program the program version 
	 * @return null function tag, or null if not found
	 * @throws IOException
	 */
	private FunctionTag getTag(Long id, Program program) throws IOException {
		FunctionManagerDB functionManagerDB = (FunctionManagerDB) program.getFunctionManager();
		return functionManagerDB.getFunctionTagManager().getFunctionTag(id);
	}

	/**
	 * For JUnit testing only, set the option for resolving a conflict.
	 * @param option
	 */
	public void setConflictResolution(int option) {
		conflictOption = option;
		conflictChoice = option;
	}

	/**
	 * Builds the UI for the conflict panel. This will show the tag ID that is in
	 * conflict, the reason for the conflict, and widgets allowing the user to
	 * select a resolution.
	 * 
	 * @param id the tag id
	 * @param listener listener for handling radio button selects
	 * @param monitor task monitor
	 */
	private void setupConflictPanel(long id, ChangeListener listener, TaskMonitor monitor) {

		if (conflictPanel == null) {
			conflictPanel = new VerticalChoicesPanel();
		}
		else {
			conflictPanel.clear();
		}

		conflictPanel.setHeader(getConflictInfo(monitor));
		conflictPanel.setTitle("Function Tags");
		conflictPanel.setUseForAll(false);
		conflictPanel.setConflictType("Function Tags");

		try {

			//
			// Create a radio button set (Original, Latest, My) for the conflict.
			//
			FunctionTag originalTag = getTag(id, originalProgram);
			String originalName = originalTag == null ? "<tag deleted>" : originalTag.getName();
			String originalComment = originalTag == null ? "" : originalTag.getComment();

			FunctionTag latestTag = getTag(id, latestProgram);
			String latestName = latestTag == null ? "<tag deleted>" : latestTag.getName();
			String latestComment = latestTag == null ? "" : latestTag.getComment();

			FunctionTag myTag = getTag(id, myProgram);
			String myName = myTag == null ? "<tag deleted>" : myTag.getName();
			String myComment = myTag == null ? "" : myTag.getComment();

			conflictPanel.setRowHeader(new String[] { "Option", "Function Tags" });

			conflictPanel.setRowHeader(getFunctionTagInfo(-1, null, null));
			conflictPanel.addRadioButtonRow(getFunctionTagInfo(LATEST, latestName, latestComment),
				LATEST_BUTTON_NAME,
				KEEP_LATEST, listener);
			conflictPanel.addRadioButtonRow(getFunctionTagInfo(MY, myName, myComment),
				CHECKED_OUT_BUTTON_NAME,
				KEEP_MY, listener);
			conflictPanel.addRadioButtonRow(
				getFunctionTagInfo(ORIGINAL, originalName, originalComment),
				ORIGINAL_BUTTON_NAME, KEEP_ORIGINAL, listener);

			currentlyMergingTagID = id;

		}
		catch (IOException e) {
			Msg.error(this, "Error creating conflict dialog for " + id, e);
		}
	}

	/**
	 * Returns a string containing information about the current conflict. This will be 
	 * displayed in the header of the conflict panel.
	 * 
	 * @param monitor the task monitor
	 * @return
	 */
	private String getConflictInfo(TaskMonitor monitor) {
		StringBuffer buf = new StringBuffer();
		buf.append(
			"<center><b>" + "Resolving conflict " + (monitor.getProgress() + 1) + " of " +
				tagConflicts.size() + "</b></center>");
		buf.append(HTMLUtilities.HTML_NEW_LINE);
		buf.append("Tag Id:");
		buf.append(HTMLUtilities.spaces(21));
		buf.append(HTMLUtilities.colorString(Color.BLUE, String.valueOf(currentlyMergingTagID)));
		buf.append(HTMLUtilities.HTML_NEW_LINE);
		buf.append("Reason for Conflict:");
		buf.append(HTMLUtilities.spaces(1));
		buf.append(
			HTMLUtilities.colorString(Color.BLUE, tagConflicts.get(currentlyMergingTagID)));
		buf.append(HTMLUtilities.HTML_NEW_LINE);
		buf.append(HTMLUtilities.HTML_NEW_LINE);

		return buf.toString();
	}

	/**
	 * Returns a string containing the tag contents for the program version
	 * given.
	 * 
	 * This is what should be displayed for each choice in the conflict panel.
	 * 
	 * @param version the program version (LATEST, MY, ORIGINAL)
	 * @param name the tag name
	 * @param comment the tag comment
	 * @return
	 */
	private String[] getFunctionTagInfo(int version, String name, String comment) {
		String[] info = new String[] { "Keep", "", name, comment };

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
			return new String[] { "Option", "Type", "Name", "Comment" };
		}

		return info;
	}
}
