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
package ghidra.app.merge.memory;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;

import javax.swing.SwingUtilities;

import ghidra.app.merge.*;
import ghidra.app.util.HelpTopics;
import ghidra.framework.store.LockException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Merge memory blocks that have changes to the name, permissions or comments.
 * 
 * 
 */
public class MemoryMergeManager implements MergeResolver {

	private static String[] MEMORY_PHASE = new String[] { "Memory" };
	private static final int RESULT = MergeConstants.RESULT;
	private static final int ORIGINAL = MergeConstants.ORIGINAL;
	private static final int LATEST = MergeConstants.LATEST;
	private static final int MY = MergeConstants.MY;
	static final int CANCELED = -2; // user canceled the merge operation
	static final int ASK_USER = -1;// prompt the user to choose resolution 
	static final int OPTION_LATEST = 0; // Latest 
	static final int OPTION_MY = 1; // My change 
	static final int OPTION_ORIGINAL = 2; // Original

	private Program[] programs = new Program[4];
	private Memory[] mems = new Memory[4];
	private MemoryBlock[] myBlocks;
	private MemoryBlock[] latestBlocks;
	private MemoryBlock[] origBlocks;
	private MemoryBlock[] resultBlocks;

	private ProgramMultiUserMergeManager mergeManager;
	private TaskMonitor currentMonitor;
	private int conflictOption;
	private ArrayList<ConflictInfo> conflictList;
	private int currentConflictIndex;
	private int conflictCount;
	private MemoryMergePanel mergePanel;
	private int progressIndex;
	private int memoryDetailChoice = ASK_USER;

	/**
	 * Constructor
	 * @param mergeManager merge manager
	 * @param resultProgram program where changes will be applied to
	 * @param myProgram source program with changes that will be applied to
	 * result program
	 * @param originalProgram original program that was checked out
	 * @param latestProgram latest program that was checked in; the result
	 * program and latest program are initially identical
	 */
	public MemoryMergeManager(ProgramMultiUserMergeManager mergeManager, Program resultProgram,
			Program myProgram, Program originalProgram, Program latestProgram) {

		this.mergeManager = mergeManager;
		programs[RESULT] = resultProgram;
		programs[ORIGINAL] = originalProgram;
		programs[LATEST] = latestProgram;
		programs[MY] = myProgram;
		mems[RESULT] = resultProgram.getMemory();
		mems[ORIGINAL] = originalProgram.getMemory();
		mems[LATEST] = latestProgram.getMemory();
		mems[MY] = myProgram.getMemory();
		setupConflicts();
		conflictOption = ASK_USER;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#getName()
	 */
	@Override
	public String getName() {
		return "Memory Block Merger";
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#getDescription()
	 */
	@Override
	public String getDescription() {
		return "Merge Memory Blocks";
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#apply()
	 */
	@Override
	public void apply() {
		conflictOption = mergePanel.getSelectedOption();

		// If the "Use For All" check box is selected 
		// then save the option chosen for this conflict type.
		if (mergePanel.getUseForAll()) {
			memoryDetailChoice = conflictOption;
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#cancel()
	 */
	@Override
	public void cancel() {
		conflictOption = CANCELED;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#merge(ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void merge(TaskMonitor monitor) {

		mergeManager.setInProgress(MEMORY_PHASE);
		this.currentMonitor = monitor;
		int transactionID = programs[RESULT].startTransaction("Merge Memory");
		boolean commit = false;

		try {
			int numBlocks = mems[MY].getBlocks().length;
			monitor.initialize(numBlocks);

			// first check image base
//			if (isImageBaseConflict()) {
//				monitor.setMaximum(mems[MY].getBlocks().length+1);
//				++conflictCount;
//				handleImageBaseConflict();
//			}

			for (int i = 0; i < myBlocks.length; i++) {
				mergeManager.updateProgress((int) ((float) (100 / numBlocks) * i),
					"Merging memory block: " + myBlocks[i].getName());
				processBlockChanges(i);
			}
			mergeManager.updateProgress(100, "Merging Memory...");
			processConflicts();
			commit = true;

		}
		catch (CancelledException e) {
		}
		finally {
			programs[RESULT].endTransaction(transactionID, commit);
		}
		mergeManager.setCompleted(MEMORY_PHASE);
	}

	/**
	 * Identify conflicts among the memory blocks.
	 */
	private void setupConflicts() {
		// the memory map should be the same between LATEST and MY; the
		// only things that could change on the block are name, attributes,
		// and comments.

		conflictList = new ArrayList<ConflictInfo>();

		resultBlocks = mems[RESULT].getBlocks();
		myBlocks = mems[MY].getBlocks();
		latestBlocks = mems[LATEST].getBlocks();
		origBlocks = mems[ORIGINAL].getBlocks();

		if (myBlocks.length != latestBlocks.length) {
			throw new AssertException("Memory maps have different sizes!");
		}
		for (int i = 0; i < myBlocks.length; i++) {
			if (myBlocks[i].getSize() != latestBlocks[i].getSize()) {
				throw new AssertException("Memory blocks have different lengths!");
			}
			if (isNameConflict(i)) {
				conflictList.add(new ConflictInfo(i, true, false, false));
			}
			if (isPermissionConflict(i)) {
				conflictList.add(new ConflictInfo(i, false, true, false));
			}
			if (isCommentConflict(i)) {
				conflictList.add(new ConflictInfo(i, false, false, true));
			}
		}
		conflictCount = conflictList.size();
	}

//	/**
//	 * Return whether the image base address conflicts between LATEST and MY
//	 * programs.
//	 */
//	private boolean isImageBaseConflict() {
//		Address latestBaseAddr = programs[LATEST].getImageBase();
//		Address myBaseAddr = programs[MY].getImageBase();
//		Address origBaseAddr = programs[ORIGINAL].getImageBase();
//		
//		if (!myBaseAddr.equals(origBaseAddr) && 
//				!latestBaseAddr.equals(origBaseAddr) &&
//				!(myBaseAddr.equals(latestBaseAddr))) {
//			return true;
//		}
//		return false;
//	}
	/**
	 * Return whether the block names are in conflict between LATEST and MY
	 * programs.
	 * @param index block index
	 */
	private boolean isNameConflict(int index) {

		String latestName = latestBlocks[index].getName();
		String myName = myBlocks[index].getName();
		String origName = origBlocks[index].getName();

		if (!myName.equals(origName) && !latestName.equals(origName) && !myName.equals(latestName)) {
			return true;
		}
		return false;
	}

	/**
	 * Return whether the permissions on a block are in conflict between 
	 * LATEST and MY programs.
	 * @param index block index
	 */
	private boolean isPermissionConflict(int index) {
		int latestPermissions = latestBlocks[index].getPermissions();
		int myPermissions = myBlocks[index].getPermissions();
		int origPermissions = origBlocks[index].getPermissions();

		if (myPermissions != origPermissions && latestPermissions != origPermissions &&
			myPermissions != latestPermissions) {
			return true;
		}
		return false;
	}

	/**
	 * Return whether the comments on a block are in conflict between 
	 * LATEST and MY programs.
	 * @param index block index
	 */
	private boolean isCommentConflict(int index) {

		String latestComments = latestBlocks[index].getComment();
		String myComments = myBlocks[index].getComment();
		String origComments = origBlocks[index].getComment();

		if (myComments != null && !myComments.equals(origComments) && latestComments != null &&
			!latestComments.equals(origComments) && !myComments.equals(latestComments)) {
			return true;
		}
		if (myComments == null && origComments != null && latestComments != null &&
			!latestComments.equals(origComments)) {
			return true;
		}
		return false;
	}

//	/**
//	 * Show panel to resolve image base conflict.
//	 */
//	private void handleImageBaseConflict() throws CancelledException {
//
//		monitor.setProgress(++progressIndex);
//		
//		Address latestAddr = programs[LATEST].getImageBase();
//		Address myAddr = programs[MY].getImageBase();
//		Address origAddr = programs[ORIGINAL].getImageBase();
//		
//		String latestStr = "Use Image Base '" + latestAddr + 
//					"'  (" + MergeConstants.LATEST_TITLE + ")";
//		String myStr = "Use Image Base '" + myAddr + 
//					"'  (" + MergeConstants.MY_TITLE + ")";
//		String origStr = "Use Image Base '" + origAddr + 
//					"'  (" + MergeConstants.ORIGINAL_TITLE + ")";
//		++currentConflictIndex;
//		if (conflictOption == ASK_USER && mergeManager != null) {
//			showMergePanel(MemoryMergePanel.CONFLICT_PANEL_ID, "Resolve Image Base Conflict",
//					latestStr, myStr, origStr);
//		}
//		switch (conflictOption) {
//			case OPTION_LATEST:
//				// no action required
//				break;
//			case OPTION_MY:
//				try {
//					programs[RESULT].setImageBase(myAddr, true);
//				} catch (AddressOverflowException e) {
//					Err.show(null, "Set Image Base Failed", e.getMessage());
//				}
//				break;
//			case OPTION_ORIGINAL:
//				try {
//					programs[RESULT].setImageBase(origAddr, true);
//				} catch (AddressOverflowException e1) {
//					Err.show(null, "Set Image Base Failed", e1.getMessage());
//				}
//				break;
//			case CANCELED:
//				throw new CancelledException();
//		}
//		conflictOption = ASK_USER;
//	}
	/**
	 * Process block conflicts.
	 * @throws CancelledException
	 */
	private void processConflicts() throws CancelledException {
		int currentBlockIndex = -1;

		for (ConflictInfo info : conflictList) {
			if (currentMonitor.isCancelled()) {
				throw new CancelledException();
			}

			if (currentBlockIndex != info.index) {
				currentMonitor.setProgress(++progressIndex);
			}
			currentBlockIndex = info.index;
			++currentConflictIndex;
			handleConflict(info);
			conflictOption = ASK_USER;
		}
	}

	private String getUniqueBlockName(String name) {
		String uniqueName = name;
		int cnt = 1;
		while (programs[LATEST].getMemory().getBlock(uniqueName) != null) {
			uniqueName = name + "_" + cnt;
		}
		return uniqueName;
	}

	private void handleConflict(ConflictInfo info) throws CancelledException {
		String latestStr = null;
		String myStr = null;
		String origStr = null;
		String title = null;
		String panelID = MemoryMergePanel.CONFLICT_PANEL_ID;

		if (info.nameConflict) {
			title = "Resolve Name Conflict";
			latestStr =
				"Use Block name '" + latestBlocks[info.index].getName() + "'  (" +
					MergeConstants.LATEST_TITLE + ")";
			myStr =
				"Use Block name '" + getUniqueBlockName(myBlocks[info.index].getName()) + "'  (" +
					MergeConstants.MY_TITLE + ")";
			origStr =
				"Use Block name '" + origBlocks[info.index].getName() + "'  (" +
					MergeConstants.ORIGINAL_TITLE + ")";
		}
		else if (info.permissionConflict) {
			title = "Resolve Permissions Conflict";
			latestStr =
				"Use '" + getPermissionString(latestBlocks[info.index]) + "'  (" +
					MergeConstants.LATEST_TITLE + ")";
			myStr =
				"Use '" + getPermissionString(myBlocks[info.index]) + "'  (" +
					MergeConstants.MY_TITLE + ")";
			origStr =
				"Use '" + getPermissionString(origBlocks[info.index]) + "'  (" +
					MergeConstants.ORIGINAL_TITLE + ")";
		}
		else {
			// comment conflict
			title = "Resolve Comment Conflict";
			panelID = MemoryMergePanel.COMMENT_PANEL_ID;
			latestStr = latestBlocks[info.index].getComment();
			myStr = myBlocks[info.index].getComment();
			origStr = origBlocks[info.index].getComment();
		}
		if ((memoryDetailChoice == ASK_USER) && conflictOption == ASK_USER && mergeManager != null) {
			title = title + " (Block index " + info.index + ")";
			showMergePanel(panelID, title, latestStr, myStr, origStr);
		}
		int optionToUse = (memoryDetailChoice == ASK_USER) ? conflictOption : memoryDetailChoice;
		switch (optionToUse) {
			case OPTION_LATEST:
				// no action required
				break;
			case OPTION_MY:
				updateBlock(info, myBlocks[info.index]);
				break;
			case OPTION_ORIGINAL:
				updateBlock(info, origBlocks[info.index]);
				break;
			case CANCELED:
				throw new CancelledException();
		}
	}

	private void updateBlock(ConflictInfo info, MemoryBlock sourceBlock) {
		if (info.nameConflict) {
			try {
				resultBlocks[info.index].setName(getUniqueBlockName(sourceBlock.getName()));
			}
			catch (LockException e) {
				// should not happen since overlay name change should not happen during merge
				throw new AssertException();
			}
		}
		else if (info.permissionConflict) {
			resultBlocks[info.index].setRead(sourceBlock.isRead());
			resultBlocks[info.index].setWrite(sourceBlock.isWrite());
			resultBlocks[info.index].setExecute(sourceBlock.isExecute());
			resultBlocks[info.index].setVolatile(sourceBlock.isVolatile());
		}
		else {
			resultBlocks[info.index].setComment(sourceBlock.getComment());
		}

	}

	private void showMergePanel(final String panelID, final String title, final String latestStr,
			final String myStr, final String origStr) {
		try {
			SwingUtilities.invokeAndWait(new Runnable() {
				@Override
				public void run() {
					if (mergePanel == null) {
						mergePanel = new MemoryMergePanel(mergeManager, conflictCount);
					}
					mergePanel.setConflictInfo(currentConflictIndex, panelID, title, latestStr,
						myStr, origStr);
				}
			});
		}
		catch (InterruptedException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
		catch (InvocationTargetException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
		mergeManager.setApplyEnabled(false);
		mergeManager.showComponent(mergePanel, "MemoryMerge", new HelpLocation(
			HelpTopics.REPOSITORY, "MemoryConflict"));
		// block until the user either cancels or hits the "Apply" button
		// on the merge dialog...
		// when the "Apply" button is hit, get the user's selection
		// and continue.

	}

	private String getPermissionString(MemoryBlock block) {
		StringBuffer sb = new StringBuffer();
		sb.append("Read = ");
		sb.append(block.isExecute());
		sb.append(", ");
		sb.append("Write = ");
		sb.append(block.isWrite());
		sb.append(", ");
		sb.append("Execute = ");
		sb.append(block.isExecute());
		sb.append(", ");
		sb.append("Volatile = ");
		sb.append(block.isVolatile());
		return sb.toString();
	}

	private void processBlockChanges(int index) throws CancelledException {
		if (currentMonitor.isCancelled()) {
			throw new CancelledException();
		}
		boolean progressUpdated = false;

		if (!isNameConflict(index)) {
			String myName = myBlocks[index].getName();
			if (!myName.equals(origBlocks[index].getName())) {
				currentMonitor.setProgress(++progressIndex);
				progressUpdated = true;
				try {
					resultBlocks[index].setName(getUniqueBlockName(myName));
				}
				catch (LockException e) {
					// should not happen since overlay name change should not happen during merge
					throw new AssertException();
				}
			}
		}
		if (!isPermissionConflict(index)) {
			boolean permission = myBlocks[index].isRead();
			if (permission != origBlocks[index].isRead()) {
				resultBlocks[index].setRead(permission);
				if (!progressUpdated) {
					currentMonitor.setProgress(++progressIndex);
					progressUpdated = true;
				}
			}
			permission = myBlocks[index].isWrite();
			if (permission != origBlocks[index].isWrite()) {
				resultBlocks[index].setWrite(permission);
				if (!progressUpdated) {
					currentMonitor.setProgress(++progressIndex);
					progressUpdated = true;
				}
			}
			permission = myBlocks[index].isExecute();
			if (permission != origBlocks[index].isExecute()) {
				resultBlocks[index].setExecute(permission);
				if (!progressUpdated) {
					currentMonitor.setProgress(++progressIndex);
					progressUpdated = true;
				}
			}
			permission = myBlocks[index].isVolatile();
			if (permission != origBlocks[index].isVolatile()) {
				resultBlocks[index].setVolatile(permission);
				if (!progressUpdated) {
					currentMonitor.setProgress(++progressIndex);
					progressUpdated = true;
				}
			}
		}
		if (!isCommentConflict(index)) {
			String myComment = myBlocks[index].getComment();
			if (myComment != null && !myComment.equals(origBlocks[index].getComment()) ||
				(myComment == null)) {
				resultBlocks[index].setComment(myComment);
				if (!progressUpdated) {
					currentMonitor.setProgress(++progressIndex);
					progressUpdated = true;
				}
			}
		}
		if (!progressUpdated && !hasConflict(index)) {
			currentMonitor.setProgress(++progressIndex);
		}
	}

	private boolean hasConflict(int index) {
		for (ConflictInfo info : conflictList) {
			if (index == info.index) {
				return true;
			}
		}
		return false;
	}

	@Override
	public String[][] getPhases() {
		return new String[][] { MEMORY_PHASE };
	}

	private class ConflictInfo {

		int index;
		boolean permissionConflict;
		boolean nameConflict;
		boolean commentConflict;

		ConflictInfo(int index, boolean nameConflict, boolean permissionConflict,
				boolean commentConflict) {
			this.index = index;
			this.nameConflict = nameConflict;
			this.permissionConflict = permissionConflict;
			this.commentConflict = commentConflict;
		}
	}
}
