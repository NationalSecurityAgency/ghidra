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
package ghidra.app.merge.tree;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;

import javax.swing.SwingUtilities;

import ghidra.app.merge.MergeResolver;
import ghidra.app.merge.ProgramMultiUserMergeManager;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.listing.*;
import ghidra.util.HelpLocation;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Manages changes and conflicts between the latest versioned Program and the
 * Program that is being checked into version control.
 */
public class ProgramTreeMergeManager implements MergeResolver {

	private static String[] PROGRAM_TREE_PHASE = new String[] { "Program Trees" };
	final static String NAME_PANEL_ID = "Name Panel";
	final static String CONFLICTS_PANEL_ID = "Name/Content Conflicts Panel";

	private Program resultProgram;
	private Program originalProgram;

	private ProgramChangeSet myChangeSet;
	private ProgramChangeSet latestChangeSet;
	private TaskMonitor currentMonitor;
	private Listing myListing;
	private Listing resultListing;
	private Listing latestListing;

	private ArrayList<Long> conflictsChangeList;

	private int conflictOption;
	private ProgramMultiUserMergeManager mergeManager;
	private ProgramTreeMergePanel mergePanel;
	private int progressIndex;

	private int onlyNamesChangedChoice = ASK_USER;
	private int onlyDestinationStructureChoice = ASK_USER;
	private int onlySourceStructureChoice = ASK_USER;
	private int bothStructuresChangedChoice = ASK_USER;

	static final int CANCELED = -2; // user canceled the merge operation
	static final int ASK_USER = -1;// prompt the user to choose resolution
	static final int KEEP_OTHER_NAME = 0; // keep other, lose private
	static final int KEEP_PRIVATE_NAME = 1; // keep private, lose other
	static final int ADD_NEW_TREE = 2; // add new tree for private
	static final int RENAME_PRIVATE = 3; // rename using user's name
	static final int ORIGINAL_NAME = 4; // use original name

	/**
	 * Construct a new manager for merging trees
	 * @param mergeManager the program merge manager
	 * @param resultProgram latest version of the Program that is the 
	 * destination for changes applied from the source program
	 * @param myProgram source of changes to apply to the destination
	 * program
	 * @param originalProgram program that was originally checked out
	 * @param latestProgram program that that is the latest version; the
	 * resultProgram and latestProgram start out as being identical
	 * @param latestChangeSet change set of the destination program
	 * @param myChangeSet change set for the source program
	 */
	public ProgramTreeMergeManager(ProgramMultiUserMergeManager mergeManager,
			Program resultProgram, Program myProgram, Program originalProgram,
			Program latestProgram, ProgramChangeSet latestChangeSet, ProgramChangeSet myChangeSet) {

		this.mergeManager = mergeManager;
		this.resultProgram = resultProgram;
		this.originalProgram = originalProgram;

		this.latestChangeSet = latestChangeSet;
		this.myChangeSet = myChangeSet;

		myListing = myProgram.getListing();
		resultListing = resultProgram.getListing();
		latestListing = latestProgram.getListing();

		conflictOption = ASK_USER;

	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#apply()
	 */
	@Override
	public void apply() {
		conflictOption = mergePanel.getSelectedOption();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#cancel()
	 */
	@Override
	public void cancel() {
		conflictOption = CANCELED;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#getDescription()
	 */
	@Override
	public String getDescription() {
		return "Merge Program Trees";
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#getName()
	 */
	@Override
	public String getName() {
		return "Program Tree Merger";
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#merge(ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void merge(TaskMonitor monitor) {
		mergeManager.setInProgress(PROGRAM_TREE_PHASE);
		// For now this method simply does a coarse increment of the progress bar for the current phase.

		this.currentMonitor = monitor;
		long[] myChangeIDs = myChangeSet.getProgramTreeChanges();
		long[] myIDsAdded = myChangeSet.getProgramTreeAdditions();

		long[] latestChangeIDs = latestChangeSet.getProgramTreeChanges();
		long[] latestIDsAdded = latestChangeSet.getProgramTreeAdditions();

		mergeManager.updateProgress(0,
			"Program Tree Merge is processing IDs changed in Checked Out...");
		ArrayList<Long> changeList = new ArrayList<Long>();
		for (long myChangeID : myChangeIDs) {
			changeList.add(new Long(myChangeID));
		}

		mergeManager.updateProgress(10,
			"Program Tree Merge is processing IDs added in Checked Out...");
		ArrayList<Long> myAddedList = new ArrayList<Long>();
		for (long element : myIDsAdded) {
			myAddedList.add(new Long(element));
		}

		mergeManager.updateProgress(20, "Program Tree Merge is eliminating removed IDs...");
		// remove Added IDs from changed IDs
		changeList.removeAll(myAddedList);

		mergeManager.updateProgress(30, "Program Tree Merge is processing IDs added in Latest...");
		ArrayList<Long> latestAddedList = new ArrayList<Long>();
		for (long element : latestIDsAdded) {
			latestAddedList.add(new Long(element));
		}

		conflictsChangeList = new ArrayList<Long>(changeList);

		mergeManager.updateProgress(40, "Program Tree Merge is processing change IDs...");
		ArrayList<Long> latestChangeList = new ArrayList<Long>();
		for (long latestChangeID : latestChangeIDs) {
			latestChangeList.add(new Long(latestChangeID));
		}

		mergeManager.updateProgress(50,
			"Program Tree Merge is finding changes to apply automatically...");
		//	automatic = my changes - latest changes
		changeList.removeAll(latestChangeList);

		mergeManager.updateProgress(60, "Program Tree Merge is finding conflicting IDs...");
		// get conflicting IDs
		conflictsChangeList.retainAll(latestChangeList);

		monitor.setMaximum(myAddedList.size() + changeList.size() + conflictsChangeList.size());
		int transactionID = resultProgram.startTransaction("Merge Program Trees");
		boolean commit = false;
		try {

			mergeManager.updateProgress(70, "Program Tree Merge is applying additions...");
			// apply additions of new trees
			applyAdditions(myAddedList);

			mergeManager.updateProgress(80, "Program Tree Merge is applying changes...");
			applyChanges(changeList);

			mergeManager.updateProgress(90, "Program Tree Merge is processing conflicts...");
			processConflicts(conflictsChangeList);

			mergeManager.updateProgress(100, "Done merging program trees");
			commit = true;

		}
		catch (CancelledException e) {
		}
		finally {
			resultProgram.endTransaction(transactionID, commit);
		}
		mergeManager.setCompleted(PROGRAM_TREE_PHASE);
	}

	/**
	 * For JUnit testing only, set the option for resolving a conflict.
	 * @param option
	 */
	void setConflictResolution(int option) {
		conflictOption = option;
	}

	private void applyAdditions(ArrayList<Long> myList) throws CancelledException {

		// add new trees
		for (Long element : myList) {
			if (currentMonitor.isCancelled()) {
				throw new CancelledException();
			}
			currentMonitor.setProgress(++progressIndex);
			long treeID = element.longValue();
			ProgramModule sourceRoot = myListing.getRootModule(treeID);
			if (sourceRoot != null) {
				createTree(resultListing, getUniqueTreeName(sourceRoot.getTreeName()), sourceRoot);
			}
		}

	}

	private String getUniqueTreeName(String baseName) {
		return ProgramTreeMergeManager.getUniqueTreeName(resultProgram, baseName);
	}

	static String getUniqueTreeName(Program program, String baseName) {
		Listing currentListing = program.getListing();
		if (currentListing.getRootModule(baseName) == null) {
			return baseName;
		}
		int oneUpNumber = 0;
		String userName = SystemUtilities.getUserName();
		baseName = baseName + "." + userName;
		String name = baseName;
		while (true) {
			if (currentListing.getRootModule(name) == null) {
				return name;
			}
			++oneUpNumber;
			name = baseName + oneUpNumber;
		}
	}

	/**
	 * Apply changes that are not conflicts.
	 * @param changeList list tree IDs changed in the source program.
	 * @throws CancelledException
	 */
	private void applyChanges(ArrayList<Long> changeList) throws CancelledException {

		for (Long element : changeList) {
			if (currentMonitor.isCancelled()) {
				throw new CancelledException();
			}
			currentMonitor.setProgress(++progressIndex);

			long treeID = element.longValue();
			ProgramModule sourceRoot = myListing.getRootModule(treeID);
			ProgramModule destRoot = resultListing.getRootModule(treeID);

			if (sourceRoot == null) {
				if (destRoot != null) {
					// remove the other tree since there were no conflicts
					resultListing.removeTree(destRoot.getTreeName());
				}
			}
			else if (destRoot != null) {
				String sourceTreeName = sourceRoot.getTreeName();
				String destTreeName = destRoot.getTreeName();
				if (destTreeName.equals(sourceTreeName)) {
					resultListing.removeTree(sourceTreeName);
					createTree(resultListing, getUniqueTreeName(sourceTreeName), sourceRoot);
				}
				else {
					// names are different
					if (!treeStructureChanged(treeID)) {
						try {
							resultListing.renameTree(destTreeName,
								getUniqueTreeName(sourceTreeName));
						}
						catch (DuplicateNameException e1) {
							throw new AssertException();
						}
					}
					else {
						ProgramModule originalRoot = originalProgram.getListing().getRootModule(treeID);
						// if I made the changes remove the tree; if someone else
						// made the changes, leave the tree and create a new one
						if (sourceRoot.getModificationNumber() != originalRoot.getModificationNumber()) {
							// I made the changes
							resultListing.removeTree(destTreeName);
						}
						createTree(resultListing, getUniqueTreeName(sourceTreeName), sourceRoot);
					}
				}
			}
			else {
				createTree(resultListing, getUniqueTreeName(sourceRoot.getTreeName()), sourceRoot);
			}
		}
	}

	/**
	 * Tree structure changed if the modification numbers on trees do not
	 * match, OR, modification number of original is not the same as the
	 * modification on the source tree.
	 * @param treeID ID of source root
	 * @return whether the structure changed
	 */
	private boolean treeStructureChanged(long treeID) {

		ProgramModule sourceRoot = myListing.getRootModule(treeID);
		ProgramModule destRoot = resultListing.getRootModule(treeID);
		ProgramModule originalRoot = originalProgram.getListing().getRootModule(treeID);
		long sourceModNumber = sourceRoot.getModificationNumber();
		return (destRoot != null && destRoot.getModificationNumber() != sourceModNumber) ||
			(originalRoot != null && originalRoot.getModificationNumber() != sourceModNumber);

	}

	/**
	 * Called when we need to know which tree changed (not enough to know
	 * that the structures are different).
	 * @param root1 root of the original program 
	 * @param root2 root for either the source tree or the destination tree
	 * @return true if there was no original root, OR the modification
	 * numbers for the original tree and tree containing root do not match
	 */
	private boolean treeStructureChanged(ProgramModule root1, ProgramModule root2) {
		if (root1 == null) {
			return true;
		}
		return root1.getModificationNumber() != root2.getModificationNumber();
	}

	private long createTree(Listing listing, String treeName, ProgramModule sourceRoot) {

		ArrayList<String> fragmentNameList = new ArrayList<String>();
		try {
			ProgramModule root = listing.createRootModule(treeName);
			// get a fragment for each memory block when a tree is created;
			// rename these fragments so we can remove them after 
			// we populate the tree
			Group[] kids = root.getChildren();
			String[] names = new String[kids.length];
			for (int i = 0; i < kids.length; i++) {
				names[i] = kids[i].getName() + "__default__" + i;
				kids[i].setName(names[i]);
			}
			createModules(root, sourceRoot, fragmentNameList);
			removeEmptyFragments(root, fragmentNameList);

			// remove the fragments that were created by default
			for (String name : names) {
				root.removeChild(name);
			}
			return root.getTreeID();
		}
		catch (DuplicateNameException e) {
			throw new AssertException("Got duplicate name while creating tree " + treeName);
		}
		catch (NotEmptyException e) {
			throw new AssertException("Got Not empty exception");
		}
	}

	private void removeEmptyFragments(ProgramModule module, ArrayList<String> fragmentNameList) {
		Group[] groups = module.getChildren();
		for (Group group : groups) {
			if (group instanceof ProgramFragment) {
				String name = group.getName();
				if (!fragmentNameList.contains(name)) {
					try {
						module.removeChild(name);
					}
					catch (NotEmptyException e) {
						throw new AssertException("Could not remove " + name + ": " + e);
					}
				}
			}
			else {
				removeEmptyFragments((ProgramModule) group, fragmentNameList);
			}
		}
	}

	private void createModules(ProgramModule parent, ProgramModule sourceParent,
			ArrayList<String> fragmentNameList) {

		parent.setComment(sourceParent.getComment());
		Group[] kids = sourceParent.getChildren();
		for (Group kid : kids) {
			if (currentMonitor.isCancelled()) {
				return;
			}
			String name = kid.getName();
			if (kid instanceof ProgramModule) {
				createModule(parent, name, (ProgramModule) kid, fragmentNameList);
			}
			else {
				createFragment(parent, name, (ProgramFragment) kid, fragmentNameList);
			}
		}
	}

	private void createModule(ProgramModule parent, String name, ProgramModule sourceModule,
			ArrayList<String> fragmentNameList) {

		ProgramModule m = null;
		try {
			m = parent.createModule(name);
		}
		catch (DuplicateNameException e) {
			// module exists
			m = resultProgram.getListing().getModule(parent.getTreeName(), name);
			try {
				parent.add(m);
			}
			catch (CircularDependencyException exc) {
				throw new AssertException("Could not add " + name + " to " + parent.getName() +
					": " + e);
			}
			catch (DuplicateGroupException exc) {
				// ok - module was already added
			}
		}
		createModules(m, sourceModule, fragmentNameList);
	}

	private void createFragment(ProgramModule parent, String name, ProgramFragment sourceFrag,
			ArrayList<String> fragmentNameList) {

		if (!fragmentNameList.contains(name)) {
			fragmentNameList.add(name);
		}
		ProgramFragment newFrag = null;
		try {
			newFrag = parent.createFragment(name);
			newFrag.setComment(sourceFrag.getComment());
		}
		catch (DuplicateNameException e) {
			newFrag = resultProgram.getListing().getFragment(parent.getTreeName(), name);
			try {
				parent.add(newFrag);
			}
			catch (DuplicateGroupException e1) {
				// ok - already has the fragment
			}
		}
		if (!sourceFrag.isEmpty()) {
			ArrayList<AddressRange> list = new ArrayList<AddressRange>();
			AddressRangeIterator iter = sourceFrag.getAddressRanges();
			while (iter.hasNext()) {
				list.add(iter.next());
			}
			for (AddressRange range : list) {
				try {
					newFrag.move(range.getMinAddress(), range.getMaxAddress());
				}
				catch (NotFoundException e1) {
					throw new AssertException("Address range " + range.getMinAddress() + " to " +
						range.getMaxAddress() + " not found!");
				}
			}
		}
	}

	private void processConflicts(ArrayList<Long> list) throws CancelledException {
		for (int i = 0; i < list.size(); i++) {
			if (currentMonitor.isCancelled()) {
				throw new CancelledException();
			}
			currentMonitor.setProgress(++progressIndex);

			long treeID = list.get(i).longValue();
			ProgramModule myRoot = myListing.getRootModule(treeID);
			ProgramModule resultRoot = resultListing.getRootModule(treeID);
			ProgramModule origRoot = originalProgram.getListing().getRootModule(treeID);
			ProgramModule latestRoot = latestListing.getRootModule(treeID);

			String myTreeName = null;
			String resultTreeName = null;
			String latestTreeName = null;
			String origTreeName = origRoot.getTreeName();

			if (myRoot != null) {
				myTreeName = myRoot.getTreeName();
			}
			if (resultRoot != null) {
				resultTreeName = resultRoot.getTreeName();
			}
			if (latestRoot != null) {
				latestTreeName = latestRoot.getTreeName();
			}
			if (resultRoot == null && myRoot == null) {
				// case 12: dest tree deleted, source tree delete ==> 
				// 								no action required
				continue;
			}
			if (resultRoot != null && myRoot == null) {
				// case 11: any dest change, source tree deleted ==> no action required,
				// 
				// case 15: no changes to dest tree, source deleted tree
				//  (already handled as a change and not a conflict) OR
				// case 13: new tree in destination (not a conflict) ==> no action required 
				// (keep the tree)
				continue;
			}

			if (resultRoot == null && myRoot != null) {
				if (nameChanged(origRoot, myTreeName) || treeStructureChanged(origRoot, myRoot)) {
					// case 10: dest tree deleted, any source change 
					//			(either source name changed or content changed)
					// keep the tree
					createTree(resultListing, myTreeName, myRoot);
				}
				// else no action required (tree remains deleted)
			}
			else if (!treeStructureChanged(treeID) && nameChanged(origRoot, myTreeName) &&
				nameChanged(origRoot, resultTreeName)) {
				//case 1: both names changed, no structure changes
				namesChanged(myRoot, resultRoot, origRoot, i + 1);
			}
			else if (treeStructureChanged(origRoot, latestRoot) &&
				treeStructureChanged(origRoot, myRoot)) {
				// case 6: dest content changed, source content changed
				// case 7: dest name change & content changed, 
				// 		 source name changed & content changed
				// case 8: dest name changed & content changed, source content changed
				// case 9: dest content changed, source name changed & content changed
				keepOtherOrCreateTree(origRoot, myRoot, resultRoot, i + 1);
			}
			// case 4: dest Name & content changed, source name changed
			else if (nameChanged(origRoot, latestTreeName) &&
				treeStructureChanged(origRoot, latestRoot) && nameChanged(origRoot, myTreeName)) {
				namesContentChanged(myRoot, myTreeName, resultTreeName, origRoot, i + 1);

			}
			// case 5: dest Name changed, source name & content changed
			else if (nameChanged(origRoot, latestTreeName) && nameChanged(origRoot, myTreeName) &&
				treeStructureChanged(origRoot, myRoot)) {
				nameContentsChanged(myRoot, myTreeName, resultTreeName, origTreeName, i + 1);

			}
			// case 2: dest Name changed, source content changed 
			// (not a conflict that the user must resolve)
			else if (nameChanged(origRoot, latestTreeName) &&
				treeStructureChanged(origRoot, myRoot)) {

				resultListing.removeTree(resultTreeName);
				createTree(resultListing, resultTreeName, myRoot);
			}
			// case 3: dest content changed, source name changed
			// (not a conflict that the user must resolve)
			else if (nameChanged(origRoot, myTreeName) &&
				treeStructureChanged(origRoot, latestRoot)) {
				// automatic merge: rename "other" tree to "my" tree name
				try {
					resultListing.renameTree(resultTreeName, getUniqueTreeName(myTreeName));
				}
				catch (DuplicateNameException e) {
					throw new AssertException("Got duplicate name");
				}
			}
		}
	}

	/**
	 * Covers case 6: dest content changed, source content changed;
	 *        case 7: dest name change and content changed, source name changed and content changed
	 *        case 8: dest name and content changed, source content changed
	 *        case 9: dest content changed, source name and content changed
	 * @throws CancelledException 
	 */
	private void keepOtherOrCreateTree(ProgramModule origRoot, ProgramModule sourceRoot, ProgramModule destRoot,
			int conflictIndex) throws CancelledException {

		String sourceTreeName = sourceRoot.getTreeName();
		String destTreeName = destRoot.getTreeName();
		String origTreeName = origRoot.getTreeName();

		boolean destChanged = treeStructureChanged(origRoot, destRoot);

		if (bothStructuresChangedChoice == ASK_USER && conflictOption == ASK_USER &&
			mergeManager != null) {
			// display prompt that has to choices: KEEP OTHER (lose my changes) 
			// or Create a new tree (if there is a name conflict, append
			// the user's name to the tree name)
			// or use original (put the original tree back in and lose my changes)
			showMergePanel(CONFLICTS_PANEL_ID, conflictIndex, destTreeName, sourceTreeName,
				origTreeName, nameChanged(origRoot, destTreeName), destChanged,
				nameChanged(origRoot, sourceTreeName), treeStructureChanged(origRoot, sourceRoot));

			// block until we get a response

			if (conflictOption == CANCELED) {
				throw new CancelledException();
			}
			// If the "Use For All" check box is selected 
			// then save the option chosen for this conflict type.
			if (mergePanel.getUseForAll()) {
				bothStructuresChangedChoice = conflictOption;
			}
		}
		int optionToUse =
			(bothStructuresChangedChoice == ASK_USER) ? conflictOption
					: bothStructuresChangedChoice;
		switch (optionToUse) {
			case KEEP_OTHER_NAME:
				// no action required
				break;
			case ADD_NEW_TREE:
			case RENAME_PRIVATE:
				createTree(resultListing, getUniqueTreeName(sourceTreeName), sourceRoot);
				break;
			case ORIGINAL_NAME:
				if (destChanged) {
					createTree(resultListing, getUniqueTreeName(origTreeName), origRoot);
				}
				else {
					try {
						resultListing.renameTree(destTreeName, getUniqueTreeName(origTreeName));
					}
					catch (DuplicateNameException e) {
					}
				}
				break;
		}
		conflictOption = ASK_USER;
	}

	/**
	 * Case 1: both names changed, no structure changes
	 * @param sourceRoot
	 * @param destRoot
	 */
	private void namesChanged(ProgramModule sourceRoot, ProgramModule destRoot, ProgramModule origRoot, int conflictIndex)
			throws CancelledException {

		String sourceTreeName = sourceRoot.getTreeName();
		String destTreeName = destRoot.getTreeName();
		String origTreeName = origRoot.getTreeName();

		if (onlyNamesChangedChoice == ASK_USER && conflictOption == ASK_USER &&
			mergeManager != null) {
			waitForUserInput(sourceTreeName, destTreeName, origTreeName, conflictIndex, true,
				false, true, false);

			if (conflictOption == CANCELED) {
				throw new CancelledException();
			}
			// If the "Use For All" check box is selected 
			// then save the option chosen for this conflict type.
			if (mergePanel.getUseForAll()) {
				onlyNamesChangedChoice = conflictOption;
			}
		}

		int optionToUse =
			(onlyNamesChangedChoice == ASK_USER) ? conflictOption : onlyNamesChangedChoice;
		switch (optionToUse) {
			case KEEP_OTHER_NAME:
				// no action required
				break;
			case KEEP_PRIVATE_NAME:
				try {
					resultListing.renameTree(destTreeName, getUniqueTreeName(sourceTreeName));
				}
				catch (DuplicateNameException e) {
				}
				break;
			case ADD_NEW_TREE:
				createTree(resultListing, sourceTreeName, sourceRoot);
				break;
			case RENAME_PRIVATE:
				try {
					resultListing.renameTree(sourceTreeName, getUniqueTreeName(sourceTreeName));
				}
				catch (DuplicateNameException e2) {
				}
				break;
			case ORIGINAL_NAME:
				try {
					resultListing.renameTree(destTreeName, getUniqueTreeName(origTreeName));
				}
				catch (DuplicateNameException e2) {
				}
				break;

			case CANCELED:
				throw new CancelledException();
		}
		conflictOption = ASK_USER;
	}

	private void waitForUserInput(String sourceTreeName, String destTreeName, String origTreeName,
			int conflictIndex, boolean latestNameChanged, boolean latestStructureChanged,
			boolean privNameChanged, boolean privStructureChanged) {
		String panelID = NAME_PANEL_ID;
//		String uniqueSourceTreeName = sourceTreeName;
		if (resultListing.getRootModule(sourceTreeName) != null) {
			panelID = CONFLICTS_PANEL_ID;
//			uniqueSourceTreeName = getUniqueTreeName(sourceTreeName);
		}
		// show panel: if no name conflicts in dest tree,
		// options are: keep dest name, keep source name, or add
		// new tree named source name.
		// 	if source name exists in dest tree, options are:
		// keep dest tree, or rename dest to dest name.<username>
		showMergePanel(panelID, conflictIndex, destTreeName, sourceTreeName, origTreeName,
			latestNameChanged, latestStructureChanged, privNameChanged, privStructureChanged);
		// block until we get a response
	}

	/**
	 * Case 4: destination Name and content changed, source name changed
	 * @param sourceRoot source root module
	 * @param sourceTreeName source tree name
	 * @param destTreeName destination tree name
	 * @throws CancelledException
	 */
	private void namesContentChanged(ProgramModule sourceRoot, String sourceTreeName, String destTreeName,
			ProgramModule origRoot, int conflictIndex) throws CancelledException {

		String origTreeName = origRoot.getTreeName();

		if (onlyDestinationStructureChoice == ASK_USER && conflictOption == ASK_USER &&
			mergeManager != null) {
			waitForUserInput(sourceTreeName, destTreeName, origTreeName, conflictIndex, true, true,
				true, false);

			if (conflictOption == CANCELED) {
				throw new CancelledException();
			}
			// If the "Use For All" check box is selected 
			// then save the option chosen for this conflict type.
			if (mergePanel.getUseForAll()) {
				onlyDestinationStructureChoice = conflictOption;
			}
		}
		int optionToUse =
			(onlyDestinationStructureChoice == ASK_USER) ? conflictOption
					: onlyDestinationStructureChoice;
		switch (optionToUse) {
			case KEEP_OTHER_NAME:
				// no action required
				break;
			case KEEP_PRIVATE_NAME:
				// rename other to source name
				try {
					resultListing.renameTree(destTreeName, getUniqueTreeName(sourceTreeName));
				}
				catch (DuplicateNameException e) {
					throw new AssertException("Got duplicate name exception!");
				}
				break;
			case ADD_NEW_TREE:
			case RENAME_PRIVATE:
				createTree(resultListing, getUniqueTreeName(sourceTreeName), sourceRoot);
				break;
			case ORIGINAL_NAME:
				createTree(resultListing, getUniqueTreeName(origTreeName), origRoot);
				break;
			case CANCELED:
				throw new CancelledException();
		}
		conflictOption = ASK_USER;
	}

	/**
	 * Case 5: destination Name changed, source name and content changed
	 * @param sourceRoot source root module
	 * @param sourceTreeName source tree name
	 * @param destTreeName destination tree name
	 * @throws CancelledException
	 */
	private void nameContentsChanged(ProgramModule sourceRoot, String sourceTreeName, String destTreeName,
			String origTreeName, int conflictIndex) throws CancelledException {

		if (onlySourceStructureChoice == ASK_USER && conflictOption == ASK_USER &&
			mergeManager != null) {
			waitForUserInput(sourceTreeName, destTreeName, origTreeName, conflictIndex, true,
				false, true, true);

			if (conflictOption == CANCELED) {
				throw new CancelledException();
			}
			// If the "Use For All" check box is selected 
			// then save the option chosen for this conflict type.
			if (mergePanel.getUseForAll()) {
				onlySourceStructureChoice = conflictOption;
			}
		}
		int optionToUse =
			(onlySourceStructureChoice == ASK_USER) ? conflictOption : onlySourceStructureChoice;
		switch (optionToUse) {
			case KEEP_OTHER_NAME:
				// delete and add back in using source tree
				resultListing.removeTree(destTreeName);
				createTree(resultListing, destTreeName, sourceRoot);
				break;
			case KEEP_PRIVATE_NAME:
				// delete other name
				resultListing.removeTree(destTreeName);
				createTree(resultListing, sourceTreeName, sourceRoot);
				break;
			case ADD_NEW_TREE:
				createTree(resultListing, sourceTreeName, sourceRoot);
				break;
			case RENAME_PRIVATE:
				createTree(resultListing, getUniqueTreeName(sourceTreeName), sourceRoot);
				break;
			case ORIGINAL_NAME:
				try {
					resultListing.renameTree(destTreeName, getUniqueTreeName(origTreeName));
				}
				catch (DuplicateNameException e) {
				}
				break;
			case CANCELED:
				throw new CancelledException();
		}
		conflictOption = ASK_USER;
	}

	private boolean nameChanged(ProgramModule origRoot, String treeName) {
		return !origRoot.getTreeName().equals(treeName);
	}

	private void showMergePanel(final String panelID, final int conflictIndex, final String name1,
			final String name2, final String origName, final boolean latestNameChanged,
			final boolean latestStructureChanged, final boolean privNameChanged,
			final boolean privStructureChanged) {
		try {
			SwingUtilities.invokeAndWait(new Runnable() {
				@Override
				public void run() {
					if (mergePanel == null) {
						mergePanel =
							new ProgramTreeMergePanel(mergeManager, conflictsChangeList.size());
					}
					mergePanel.setConflictInfo(panelID, conflictIndex, resultProgram, name1, name2,
						origName, latestNameChanged, latestStructureChanged, privNameChanged,
						privStructureChanged);
					setConflictDetails();
				}

				private void setConflictDetails() {
					String conflictDetails;
					if (latestStructureChanged) {
						if (privStructureChanged) {
							conflictDetails =
								" where both the Latest and the Checked Out tree structures were changed";
						}
						else {
							conflictDetails = " where only the Latest tree structure was changed";
						}
					}
					else {
						if (privStructureChanged) {
							conflictDetails =
								" where only the Checked Out tree structure was changed";
						}
						else {
							conflictDetails = " where only the tree names were changed";
						}
					}
					mergePanel.setConflictDetails(conflictDetails);
				}
			});
		}
		catch (InterruptedException e) {
		}
		catch (InvocationTargetException e) {
		}
		mergeManager.setApplyEnabled(false);
		mergeManager.showComponent(mergePanel, "ProgramTreeMerge", new HelpLocation(
			HelpTopics.REPOSITORY, "ProgramTreeConflict"));
		// block until the user either cancels or hits the "Apply" button
		// on the merge dialog...
		// when the "Apply" button is hit, get the user's selection
		// and continue.
	}

	@Override
	public String[][] getPhases() {
		return new String[][] { PROGRAM_TREE_PHASE };
	}

}
