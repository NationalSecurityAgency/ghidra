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

import javax.swing.SwingUtilities;

import docking.widgets.dialogs.ReadTextDialog;
import ghidra.app.merge.MergeConstants;
import ghidra.app.merge.ProgramMultiUserMergeManager;
import ghidra.app.merge.tool.ListingMergePanel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.DiffUtility;
import ghidra.program.util.ProgramDiff;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>AbstractListingMerger</code> is an abstract class that each type of
 * listing merge manager can extend to gain access to commonly needed information
 * such as the programs, the listing merge panel,
 * Diffs for Latest-Original and My-Original and Latest-My, etc.
 */
abstract class AbstractListingMerger implements ListingMerger, ListingMergeConstants {

	protected static final int RESULT = MergeConstants.RESULT;
	protected static final int LATEST = MergeConstants.LATEST;
	protected static final int MY = MergeConstants.MY;
	protected static final int ORIGINAL = MergeConstants.ORIGINAL;

	protected static final Color MERGE_HIGHLIGHT_COLOR = MergeConstants.HIGHLIGHT_COLOR;
	protected ProgramMultiUserMergeManager mergeManager;
	protected ListingMergeManager listingMergeMgr;
	protected ListingMergePanel listingMergePanel;
	protected ConflictInfoPanel conflictInfoPanel;
	protected int conflictOption = ASK_USER;

	protected Address currentAddress;
	protected TaskMonitor currentMonitor;

	protected Program resultPgm;
	protected Program originalPgm;
	protected Program latestPgm;
	protected Program myPgm;
	protected AddressFactory resultAddressFactory;

	protected ProgramDiff diffOriginalLatest;
	protected ProgramDiff diffOriginalMy;
	protected ProgramDiff diffLatestMy;

	protected StringBuffer errorBuf;
	protected StringBuffer infoBuf;

	protected long totalChanges = 1; // Total number of changes for this auto-merger.
	protected long changeNum; // Current change number being auto-merged out of totalChanges.
	protected int minPhaseProgressPercentage; // Where to begin filling in the progress bar.
	protected int maxPhaseProgressPercentage; // Where to stop filling in the progress bar.

	protected ConflictPanel currentConflictPanel;
	protected int numConflictsResolved;

	/**
	 * Constructs a generic type of Listing merger. This should be called by any
	 * listing merger that extends this class. It can be called from the
	 * constructor as <code>super(listingMergeManager);</code>
	 * @param listingMergeMgr the overall manager for the associated listing merge.
	 * @param monitor monitor for indicating merge progress to the user and to provide Cancel.
	 * @throws CancelledException if the user Cancels.
	 */
	AbstractListingMerger(ListingMergeManager listingMergeMgr) {
		this.listingMergeMgr = listingMergeMgr;
		init();
	}

	/**
	 * Initializes the four programs and each of the ProgramDiffs
	 * typically needed to perform the merge.
	 * <br>Note: If you override this method, it should be the first method you call
	 * as "super.init()" to setup the common listing merge information.
	 *
	 */
	protected void init() {
		errorBuf = new StringBuffer();
		infoBuf = new StringBuffer();
		mergeManager = listingMergeMgr.mergeManager;
		listingMergePanel = listingMergeMgr.getListingMergePanel();
		conflictInfoPanel = listingMergeMgr.getConflictInfoPanel();

		resultPgm = listingMergeMgr.programs[RESULT];
		originalPgm = listingMergeMgr.programs[ORIGINAL];
		latestPgm = listingMergeMgr.programs[LATEST];
		myPgm = listingMergeMgr.programs[MY];

		resultAddressFactory = resultPgm.getAddressFactory();

		diffOriginalLatest = listingMergeMgr.diffOriginalLatest;
		diffOriginalMy = listingMergeMgr.diffOriginalMy;
		diffLatestMy = listingMergeMgr.diffLatestMy;
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
		if (pgm == resultPgm) {
			return RESULT;
		}
		else if (pgm == latestPgm) {
			return LATEST;
		}
		else if (pgm == myPgm) {
			return MY;
		}
		else if (pgm == originalPgm) {
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
				return latestPgm;
			case KEEP_MY:
				return myPgm;
			case KEEP_ORIGINAL:
				return originalPgm;
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
		codeSet.add(DiffUtility.getCodeUnitSet(addrs, latestPgm));
		codeSet.add(DiffUtility.getCodeUnitSet(addrs, myPgm));
		codeSet.add(DiffUtility.getCodeUnitSet(addrs, originalPgm));
		return codeSet;
	}

	/**
	 * Clears all text from the error buffer.
	 */
	void clearResolveErrors() {
		if (errorBuf.length() > 0) {
			errorBuf = new StringBuffer();
		}
	}

	/**
	 * This is a generic method for displaying the contents of the error
	 * buffer to the user.
	 */
	void showResolveErrors() {
		if (errorBuf.length() > 0) {
			try {
				SwingUtilities.invokeAndWait(new Runnable() {
					@Override
					public void run() {
						String title = getConflictType() + " Merge Errors";
						String msg = errorBuf.toString();
						ReadTextDialog dialog = new ReadTextDialog(title, msg);
						PluginTool mergeTool = mergeManager.getMergeTool();
						mergeManager.getMergeTool().showDialog(dialog, mergeTool.getActiveWindow());
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
						PluginTool mergeTool = mergeManager.getMergeTool();
						mergeManager.getMergeTool().showDialog(dialog, mergeTool.getActiveWindow());
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

	/**
	 * Returns whether or not the two indicated objects are equal. It allows
	 * either or both of the specified objects to be null.
	 * @param o1 the first object or null
	 * @param o2 the second object or null
	 * @return true if the objects are equal.
	 */
	static boolean same(Object o1, Object o2) {
		if (o1 == null) {
			return (o2 == null);
		}
		return o1.equals(o2);
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
				return true;
			}
			return false;
		}
		return true;
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
		long granularity = (totalChanges / progressRange) + 1;
		if (changeNum % granularity == 0) {
			if (totalChanges <= 0) {
				totalChanges = 1;
			}
			mergeManager.updateProgress(
				(int) (minPhaseProgressPercentage + ((changeNum * progressRange) / totalChanges)));
		}
	}

	/**
	 * Updates the progress message details associated with this phase of the merge.
	 * @param message a message indicating what is currently occurring in this phase.
	 * Null indicates to use the default message.
	 */
	protected void updateProgressMessage(String message) {
		mergeManager.updateProgress(message);
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

}
