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
package ghidra.app.merge.listing;

import ghidra.app.merge.tool.ListingMergePanel;
import ghidra.app.merge.util.ConflictUtility;
import ghidra.app.merge.util.MergeUtilities;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.lang.reflect.InvocationTargetException;

import javax.swing.SwingUtilities;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

/**
 * Class for merging comment changes. This class can merge non-conflicting
 * comment changes that were made to the checked out version. It can determine
 * where there are conflicts between the latest checked in version and my
 * checked out version. It can then manually merge the conflicting comments.
 * <br>Important: This class is intended to be used only for a single program 
 * version merge. It should be constructed, followed by an autoMerge(), and lastly
 * each address with a conflict should have mergeConflicts() called on it.
 */
class CommentMerger extends AbstractListingMerger {

	final static String COMMENTS_PHASE = "Comments";
	private int programMergeType;

	private AddressSet conflictPlate;
	private AddressSet conflictPre;
	private AddressSet conflictEol;
	private AddressSet conflictRepeat;
	private AddressSet conflictPost;

	// The user is asked about each comment conflict until the "Use For All" is chosen for a 
	// comment type. Then the choice at the time the "Use For All" is selected, will be used 
	// for any remaining conflicts that are the same comment type.
	private int plateCommentChoice = ASK_USER;
	private int preCommentChoice = ASK_USER;
	private int eolCommentChoice = ASK_USER;
	private int repeatCommentChoice = ASK_USER;
	private int postCommentChoice = ASK_USER;

	private VerticalChoicesPanel conflictPanel;

	/**
	 * Constructs a comments merger.
	 * @param listingMergeMgr the listing merge manager that owns this merger.
	 */
	CommentMerger(ListingMergeManager listingMergeMgr) {
		super(listingMergeMgr);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.AbstractListingMerger#init()
	 */
	@Override
	public void init() {
		super.init();
		conflictPlate = new AddressSet();
		conflictPre = new AddressSet();
		conflictEol = new AddressSet();
		conflictRepeat = new AddressSet();
		conflictPost = new AddressSet();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#getConflictType()
	 */
	public String getConflictType() {
		return "Comment";
	}

	@Override
	public boolean apply() {
		conflictOption = conflictPanel.getSelectedOptions();

		// If the "Use For All" check box is selected 
		// then save the option chosen for this conflict type.
		if (conflictPanel.getUseForAll()) {
			setChoiceForCommentType(programMergeType, conflictOption);
		}

		return super.apply();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#autoMerge(ghidra.util.task.TaskMonitor)
	 */
	public void autoMerge(int progressMin, int progressMax, TaskMonitor monitor)
			throws ProgramConflictException, MemoryAccessException, CancelledException {

		initializeAutoMerge("Auto-merging Comments and determining conflicts.", progressMin,
			progressMax, monitor);

		updateProgress(0, "Auto-merging Plate Comments and determining conflicts.");
		autoMerge(ProgramDiffFilter.PLATE_COMMENT_DIFFS, conflictPlate, monitor);

		updateProgress(20, "Auto-merging Pre-Comments and determining conflicts.");
		autoMerge(ProgramDiffFilter.PRE_COMMENT_DIFFS, conflictPre, monitor);

		updateProgress(40, "Auto-merging End of Line Comments and determining conflicts.");
		autoMerge(ProgramDiffFilter.EOL_COMMENT_DIFFS, conflictEol, monitor);

		updateProgress(60, "Auto-merging Repeatable Comments and determining conflicts.");
		autoMerge(ProgramDiffFilter.REPEATABLE_COMMENT_DIFFS, conflictRepeat, monitor);

		updateProgress(80, "Auto-merging Post-Comments and determining conflicts.");
		autoMerge(ProgramDiffFilter.POST_COMMENT_DIFFS, conflictPost, monitor);

		updateProgress(100, "Done auto-merging Comments and determining conflicts.");
	}

	private void autoMerge(int diffType, AddressSet conflictSet, TaskMonitor monitor)
			throws ProgramConflictException, CancelledException {
		AddressSetView latestDetailSet =
			listingMergeMgr.diffOriginalLatest.getDifferences(new ProgramDiffFilter(diffType),
				monitor);
		AddressSetView myDetailSet =
			listingMergeMgr.diffOriginalMy.getDifferences(new ProgramDiffFilter(diffType), monitor);
		AddressSet autoSet = new AddressSet();
		AddressSet overlapSet = new AddressSet();
		MergeUtilities.adjustSets(latestDetailSet, myDetailSet, autoSet, overlapSet);
		listingMergeMgr.mergeMy.mergeCommentType(autoSet, getMergeCommentType(diffType),
			ProgramMergeFilter.REPLACE, monitor);
		AddressSetView latestMySet =
			listingMergeMgr.diffLatestMy.getTypeDiffs(diffType, overlapSet, monitor);
		conflictSet.add(latestMySet);
	}

	/**
	 * Determines if there is a conflict for the indicated type of comment
	 * at the specified address.
	 * @param addr
	 * @param programMergeCommentType
	 * @return
	 */
	private boolean hasConflict(Address addr, int programMergeCommentType) {
		switch (programMergeCommentType) {
			case ProgramMergeFilter.PLATE_COMMENTS:
				return conflictPlate.contains(addr);
			case ProgramMergeFilter.PRE_COMMENTS:
				return conflictPre.contains(addr);
			case ProgramMergeFilter.EOL_COMMENTS:
				return conflictEol.contains(addr);
			case ProgramMergeFilter.REPEATABLE_COMMENTS:
				return conflictRepeat.contains(addr);
			case ProgramMergeFilter.POST_COMMENTS:
				return conflictPost.contains(addr);
			default:
				return false;
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#hasConflict(ghidra.program.model.address.Address)
	 */
	public boolean hasConflict(Address addr) {
		return hasConflict(addr, ProgramMergeFilter.PLATE_COMMENTS) ||
			hasConflict(addr, ProgramMergeFilter.PRE_COMMENTS) ||
			hasConflict(addr, ProgramMergeFilter.EOL_COMMENTS) ||
			hasConflict(addr, ProgramMergeFilter.REPEATABLE_COMMENTS) ||
			hasConflict(addr, ProgramMergeFilter.POST_COMMENTS);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#getConflictCount(ghidra.program.model.address.Address)
	 */
	public int getConflictCount(Address addr) {
		int count = 0;
		if (hasConflict(addr, ProgramMergeFilter.PLATE_COMMENTS)) {
			count++;
		}
		if (hasConflict(addr, ProgramMergeFilter.PRE_COMMENTS)) {
			count++;
		}
		if (hasConflict(addr, ProgramMergeFilter.EOL_COMMENTS)) {
			count++;
		}
		if (hasConflict(addr, ProgramMergeFilter.REPEATABLE_COMMENTS)) {
			count++;
		}
		if (hasConflict(addr, ProgramMergeFilter.POST_COMMENTS)) {
			count++;
		}
		return count;
	}

	private void setupConflictsPanel(ListingMergePanel listingPanel, Address addr,
			int programMergeType, ChangeListener changeListener) {
		if (conflictPanel == null) {
			conflictPanel = new VerticalChoicesPanel();
			currentConflictPanel = conflictPanel;
			conflictPanel.setTitle("Comment");
		}
		else {
			conflictPanel.clear();
		}
		int type = getCodeUnitCommentType(programMergeType);
		int choice = getChoiceForCommentType(programMergeType);
		boolean useForAll = (choice != ASK_USER);
		conflictPanel.setUseForAll(useForAll);
		String conflictTypeText = getTypeName(programMergeType);
		conflictPanel.setConflictType(conflictTypeText + " Comment");
		// Initialize the conflict panel.
		String originalComment = originalPgm.getListing().getComment(type, addr);
		String latestComment = latestPgm.getListing().getComment(type, addr);
		String myComment = myPgm.getListing().getComment(type, addr);
		String originalTrunc =
			ConflictUtility.getTruncatedHTMLString(originalComment, TRUNCATE_LENGTH);
		String latestTrunc = ConflictUtility.getTruncatedHTMLString(latestComment, TRUNCATE_LENGTH);
		String myTrunc = ConflictUtility.getTruncatedHTMLString(myComment, TRUNCATE_LENGTH);

		String msg;
		conflictPanel.setRowHeader(new String[] { "Option", "Comment" });
		if (latestComment == null || myComment == null) {
			String[] latestStrings =
				new String[] { createButtonText(LATEST_TITLE, programMergeType, latestComment),
					latestTrunc };
			String[] myStrings =
				new String[] { createButtonText(MY_TITLE, programMergeType, myComment), myTrunc };
			conflictPanel.addRadioButtonRow(latestStrings, LATEST_BUTTON_NAME, KEEP_LATEST,
				changeListener);
			conflictPanel.addRadioButtonRow(myStrings, CHECKED_OUT_BUTTON_NAME, KEEP_MY,
				changeListener);
			msg = conflictTypeText + " comments differ. Select whether or not to keep the comment.";
		}
		else {
			String[] latestStrings =
				new String[] { createCheckBoxText(LATEST_TITLE, programMergeType, latestComment),
					latestTrunc };
			String[] myStrings =
				new String[] { createCheckBoxText(MY_TITLE, programMergeType, myComment), myTrunc };
			conflictPanel.addCheckBoxRow(latestStrings, LATEST_CHECK_BOX_NAME, KEEP_LATEST,
				changeListener);
			conflictPanel.addCheckBoxRow(myStrings, CHECKED_OUT_CHECK_BOX_NAME, KEEP_MY,
				changeListener);
			msg =
				getTypeName(programMergeType) +
					" comments differ. Select either or both of the comments.";
		}
		conflictPanel.addInfoRow(new String[] { "'" + ORIGINAL_TITLE + "' version", originalTrunc });
		conflictPanel.setHeader(msg);

	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#mergeConflicts(ghidra.app.merge.tool.ListingMergePanel, ghidra.program.model.address.Address, int, ghidra.util.task.TaskMonitor)
	 */
	public void mergeConflicts(ListingMergePanel listingPanel, Address addr,
			int chosenConflictOption, TaskMonitor monitor) throws CancelledException,
			MemoryAccessException {
		mergeConflicts(ProgramMergeFilter.PLATE_COMMENTS, listingPanel, addr, chosenConflictOption,
			monitor);
		mergeConflicts(ProgramMergeFilter.PRE_COMMENTS, listingPanel, addr, chosenConflictOption,
			monitor);
		mergeConflicts(ProgramMergeFilter.EOL_COMMENTS, listingPanel, addr, chosenConflictOption,
			monitor);
		mergeConflicts(ProgramMergeFilter.REPEATABLE_COMMENTS, listingPanel, addr,
			chosenConflictOption, monitor);
		mergeConflicts(ProgramMergeFilter.POST_COMMENTS, listingPanel, addr, chosenConflictOption,
			monitor);
	}

	private void mergeConflicts(int programMergeFilterCommentType, ListingMergePanel listingPanel,
			Address addr, int chosenConflictOption, TaskMonitor monitor) throws CancelledException {
		if (!hasConflict(addr, programMergeFilterCommentType)) {
			return;
		}
		monitor.setMessage("Resolving " + getTypeName(programMergeFilterCommentType) +
			" Comment conflicts.");
		int choiceForCommentType = getChoiceForCommentType(programMergeFilterCommentType);
		if (choiceForCommentType != ASK_USER) {
			merge(addr, programMergeFilterCommentType, choiceForCommentType, monitor);
			return;
		}
		if (chosenConflictOption == ASK_USER && mergeManager != null) {
			showMergePanel(listingPanel, addr, programMergeFilterCommentType, monitor);
			monitor.checkCanceled();
		}
		else {
			merge(addr, programMergeFilterCommentType, chosenConflictOption, monitor);
		}
	}

	private void merge(Address addr, int programMergeFilterCommentType, int chosenConflictOption,
			TaskMonitor monitor) throws CancelledException {
		boolean both = false;
		if ((chosenConflictOption & KEEP_ORIGINAL) != 0) {
			listingMergeMgr.mergeOriginal.mergeComment(new AddressSet(addr),
				programMergeFilterCommentType, both, monitor);
			both = true;
		}
		if ((chosenConflictOption & KEEP_LATEST) != 0) {
			listingMergeMgr.mergeLatest.mergeComment(new AddressSet(addr),
				programMergeFilterCommentType, both, monitor);
			both = true;
		}
		if ((chosenConflictOption & KEEP_MY) != 0) {
			listingMergeMgr.mergeMy.mergeComment(new AddressSet(addr),
				programMergeFilterCommentType, both, monitor);
			both = true;
		}
	}

	private int getCodeUnitCommentType(int programMergeCommentType) {
		switch (programMergeCommentType) {
			case ProgramMergeFilter.PLATE_COMMENTS:
				return CodeUnit.PLATE_COMMENT;
			case ProgramMergeFilter.PRE_COMMENTS:
				return CodeUnit.PRE_COMMENT;
			case ProgramMergeFilter.EOL_COMMENTS:
				return CodeUnit.EOL_COMMENT;
			case ProgramMergeFilter.REPEATABLE_COMMENTS:
				return CodeUnit.REPEATABLE_COMMENT;
			case ProgramMergeFilter.POST_COMMENTS:
				return CodeUnit.POST_COMMENT;
			default:
				return -1;
		}
	}

	private int getMergeCommentType(int diffCommentType) {
		switch (diffCommentType) {
			case ProgramDiffFilter.PLATE_COMMENT_DIFFS:
				return ProgramMergeFilter.PLATE_COMMENTS;
			case ProgramDiffFilter.PRE_COMMENT_DIFFS:
				return ProgramMergeFilter.PRE_COMMENTS;
			case ProgramDiffFilter.EOL_COMMENT_DIFFS:
				return ProgramMergeFilter.EOL_COMMENTS;
			case ProgramDiffFilter.REPEATABLE_COMMENT_DIFFS:
				return ProgramMergeFilter.REPEATABLE_COMMENTS;
			case ProgramDiffFilter.POST_COMMENT_DIFFS:
				return ProgramMergeFilter.POST_COMMENTS;
			default:
				return -1;
		}
	}

	private int getChoiceForCommentType(int programMergeCommentType) {
		switch (programMergeCommentType) {
			case ProgramMergeFilter.PLATE_COMMENTS:
				return plateCommentChoice;
			case ProgramMergeFilter.PRE_COMMENTS:
				return preCommentChoice;
			case ProgramMergeFilter.EOL_COMMENTS:
				return eolCommentChoice;
			case ProgramMergeFilter.REPEATABLE_COMMENTS:
				return repeatCommentChoice;
			case ProgramMergeFilter.POST_COMMENTS:
				return postCommentChoice;
			default:
				return ASK_USER;
		}
	}

	private void setChoiceForCommentType(int programMergeCommentType, int choiceForCommentType) {
		switch (programMergeCommentType) {
			case ProgramMergeFilter.PLATE_COMMENTS:
				plateCommentChoice = choiceForCommentType;
				break;
			case ProgramMergeFilter.PRE_COMMENTS:
				preCommentChoice = choiceForCommentType;
				break;
			case ProgramMergeFilter.EOL_COMMENTS:
				eolCommentChoice = choiceForCommentType;
				break;
			case ProgramMergeFilter.REPEATABLE_COMMENTS:
				repeatCommentChoice = choiceForCommentType;
				break;
			case ProgramMergeFilter.POST_COMMENTS:
				postCommentChoice = choiceForCommentType;
				break;
			default:
				Msg.showError(this, listingMergePanel, "Unrecognized Comment Type",
					"Unrecognized indicator (" + programMergeCommentType +
						") for comment type to merge.");
		}
	}

	private void showMergePanel(final ListingMergePanel listingPanel, final Address addr,
			final int programMergeCommentType, TaskMonitor monitor) {
		this.currentAddress = addr;
		this.programMergeType = programMergeCommentType;
		this.currentMonitor = monitor;
		try {
			final ChangeListener changeListener = new ChangeListener() {
				public void stateChanged(ChangeEvent e) {
					conflictOption = conflictPanel.getSelectedOptions();
					if (conflictOption == ASK_USER) {
						if (mergeManager != null) {
							mergeManager.setApplyEnabled(false);
							try {
								merge(addr, programMergeCommentType, KEEP_LATEST, currentMonitor);
							}
							catch (CancelledException ce) {
							}
						}
						return;
					}
					if (mergeManager != null) {
						mergeManager.clearStatusText();
					}
					try {
						merge(addr, programMergeCommentType, conflictOption, currentMonitor);
					}
					catch (CancelledException ce) {
					}
					if (mergeManager != null) {
						mergeManager.setApplyEnabled(true);
					}
				}
			};
			SwingUtilities.invokeAndWait(new Runnable() {
				public void run() {
					setupConflictsPanel(listingPanel, CommentMerger.this.currentAddress,
						CommentMerger.this.programMergeType, changeListener);
					listingPanel.setBottomComponent(conflictPanel);
				}
			});
			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					Address addressToShow = CommentMerger.this.currentAddress;
					listingPanel.clearAllBackgrounds();
					if (addressToShow != null) {
						listingPanel.paintAllBackgrounds(getCodeUnitAddressSet(addressToShow));
						listingPanel.goTo(addressToShow);
					}
				}
			});
		}
		catch (InterruptedException e) {
		}
		catch (InvocationTargetException e) {
		}
		if (mergeManager != null) {
			mergeManager.setApplyEnabled(false);
			mergeManager.showListingMergePanel(currentAddress);
		}
		// block until the user either cancels or hits the "Apply" button
		// on the merge dialog...
	}

	private String createCheckBoxText(String version, int programMergeCommentType, String comment) {
		return "Keep '" + version + "' " + getTypeName(programMergeCommentType) + " Comment";
	}

	private String createButtonText(String version, int programMergeCommentType, String comment) {
		if (comment != null) {
			return "Keep '" + version + "' " + getTypeName(programMergeCommentType) + " Comment";
		}
		return "Delete " + getTypeName(programMergeCommentType) + " Comment as in '" + version +
			"'";
	}

	/**
	 * Returns the name for the specified comment type.
	 * @param programMergeCommentType the comment type
	 * @return the associated name
	 */
	private String getTypeName(int programMergeCommentType) {
		String typeStr;
		switch (programMergeCommentType) {
			case ProgramMergeFilter.PLATE_COMMENTS:
				typeStr = "Plate";
				break;
			case ProgramMergeFilter.PRE_COMMENTS:
				typeStr = "Pre";
				break;
			case ProgramMergeFilter.EOL_COMMENTS:
				typeStr = "End of Line";
				break;
			case ProgramMergeFilter.REPEATABLE_COMMENTS:
				typeStr = "Repeatable";
				break;
			case ProgramMergeFilter.POST_COMMENTS:
				typeStr = "Post";
				break;
			default:
				typeStr = "Unknown";
				break;
		}
		return typeStr;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#getConflicts()
	 */
	public AddressSetView getConflicts() {
		AddressSet conflicts = new AddressSet();
		conflicts.add(conflictPlate);
		conflicts.add(conflictPre);
		conflicts.add(conflictEol);
		conflicts.add(conflictRepeat);
		conflicts.add(conflictPost);
		return conflicts;
	}

}
