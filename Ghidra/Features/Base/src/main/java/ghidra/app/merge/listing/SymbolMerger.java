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
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import ghidra.app.merge.MergeConstants;
import ghidra.app.merge.tool.ListingMergePanel;
import ghidra.app.merge.util.ConflictUtility;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.SymbolPath;
import ghidra.program.database.external.ExternalManagerDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.datastruct.LongArrayList;
import ghidra.util.datastruct.LongLongHashtable;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Class for merging symbol changes. This class can merge non-conflicting
 * symbol changes that were made to the checked out version. It can determine
 * where there are conflicts between the latest checked in version and my
 * checked out version. It can then manually merge the conflicting symbols.
 * <br>Important: This class is intended to be used only for a single program
 * version merge. It should be constructed and then merge() should be called on it.
 * The merge() will perform an autoMerge() followed by mergeConflicts().
 * If symbols were automatically renamed due to conflicts, then a dialog will appear
 * that shows this information to the user.
 */
class SymbolMerger extends AbstractListingMerger {

	final static String SYMBOLS_PHASE = "Symbols";
	private final static int REMOVE_CONFLICT = 1; // Symbol was removed in one program & changed in other.
	private final static int RENAME_CONFLICT = 2; // Symbol was renamed differently in the two programs.
	private final static int NAMESPACE_CONFLICT = 3; // Two different symbols with same name in same namespace
	private final static int ADDRESS_CONFLICT = 4;	// Two programs have same named symbol at same address,
													// but different namespaces.
	private final static int PRIMARY_CONFLICT = 5; // Programs have set different symbols to primary at an address.
//	private final static int COMMENT_CONFLICT = 6; // Symbol comment was updated differently in the two programs.
//	private final static int ADD_COMMENT_CONFLICT = 7; // Symbol comment was added differently in the two programs.

	VerticalChoicesPanel conflictPanel; // Re-use this panel for conflicts.
	VerticalChoicesPanel emptyConflictPanel;
	// currentAddress is declared in AbstractListingMerger
	Symbol currentSymbol; // The symbol being resolved. Gets set to original or my symbol.
	String currentSymbolName; // Original name for the symbol.
	Namespace currentNamespace; // The namespace of the symbol being resolved.
	AddressSet currentBackgroundSet; // Addresses to color as a conflict.
	String uniqueName; // a new unique name for the symbol.
	String currentSymbolComment; // Existing comment for the symbol.

	SymbolTable latestSymTab;
	SymbolTable mySymTab;
	SymbolTable originalSymTab;
	SymbolTable resultSymTab;

	AddressSetView latestDetailSet;
	AddressSetView myDetailSet;
	AddressSet addEntryPts;
	AddressSet removeEntryPts;

	long[] myAddIDs;
	long[] myChangeIDs;
	long[] myRemoveIDs;
	long[] myModifiedIDs;
	long[] myRenameIDs;
	long[] myPrimaryChangeIDs;
//	long[] myCommentChangeIDs;
	long[] mySourceChangeIDs;
	long[] myAnchorChangeIDs;
	LongHashSet myPrimaryAddIDs;
	AddressSet mySetPrimary;

	long[] latestAddIDs;
	long[] latestChangeIDs;
	long[] latestRemoveIDs;
	long[] latestModifiedIDs;
	long[] latestRenameIDs;
	long[] latestPrimaryChangeIDs;
//	long[] latestCommentChangeIDs;
	long[] latestSourceChangeIDs;
	long[] latestAnchorChangeIDs;
	LongHashSet latestPrimaryAddIDs;
	AddressSet latestSetPrimary;

	LongLongHashtable externalTypeConflictHash; // Maps my external symbolID to latest external symbolID

	LongHashSet deferredRemoveIDs; // original ID for symbol whose removal was deferred since it has children.
	LongHashSet renamedConflictIDs; // result ID for symbol that was renamed to avoid a conflict.

	Hashtable<Address, LongArrayList> removes; // key = Address, value = LongArrayList of type Symbol ID
	AddressSet removeConflicts;
	Hashtable<Address, LongArrayList> renames; // key = Address, value = LongArrayList of type Symbol ID
	AddressSet renameConflicts;
//	Hashtable<Address, LongArrayList> comments; // key = Address, value = LongArrayList of type Symbol ID
//	AddressSet commentConflicts;
	Hashtable<Address, ArrayList<SymbolPath>> symbolAddressConflicts; // key = Address, value = ArrayList of symbols
	AddressSet addressConflicts;
	Hashtable<Address, LongArrayList> addComments; // key = Address, value = LongArrayList of type Symbol ID
	AddressSet addCommentConflicts;
	AddressSet primaryConflicts;

	LongLongHashtable originalHash; // Maps original symbolID to result symbolID
	LongLongHashtable latestHash; // Maps latest symbolID to result symbolID
	LongLongHashtable myHash; // Maps my symbolID to result symbolID

	private int totalConflicts; // Total number of conflicts for current phase of listing.
	private int conflictNum; // Current conflict number being resolved.
	private String DEFAULT_PROGRESS_MESSAGE = "Auto-merging Symbols and determining conflicts.";

	protected int addressSymbolChoice = ASK_USER;
	protected int primarySymbolChoice = ASK_USER;
	protected int removeSymbolChoice = ASK_USER;
	protected int renameSymbolChoice = ASK_USER;

	protected static enum SymbolConflictType {
		ADDRESS_SYMBOL_CONFLICT,
		PRIMARY_SYMBOL_CONFLICT,
		REMOVE_SYMBOL_CONFLICT,
		RENAME_SYMBOL_CONFLICT
	}

	SymbolConflictType currentConflictType = null;

//	protected int symbolCommentChoice = ASK_USER;
//	protected int symbolAddCommentChoice = ASK_USER;

	/**
	 * Constructs a symbol merger.
	 * @param listingMergeMgr the listing merge manager that is using this symbol merger.
	 */
	SymbolMerger(ListingMergeManager listingMergeMgr) {
		super(listingMergeMgr);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.AbstractListingMerger#init()
	 */
	@Override
	public void init() {
		super.init();

		latestSymTab = latestPgm.getSymbolTable();
		mySymTab = myPgm.getSymbolTable();
		originalSymTab = originalPgm.getSymbolTable();
		resultSymTab = resultPgm.getSymbolTable();

		removes = new Hashtable<>(); // Maps address to list of symbolIDs with remove conflicts
		removeConflicts = new AddressSet();
		renames = new Hashtable<>();
		renameConflicts = new AddressSet();
//		comments = new Hashtable<Address, LongArrayList>();
//		commentConflicts = new AddressSet(resultAddressFactory);
		symbolAddressConflicts = new Hashtable<>();
		addressConflicts = new AddressSet();
		addComments = new Hashtable<>();
		addCommentConflicts = new AddressSet();
		primaryConflicts = new AddressSet();
		mySetPrimary = new AddressSet();
		latestSetPrimary = new AddressSet();

		deferredRemoveIDs = new LongHashSet();
		renamedConflictIDs = new LongHashSet();

		addEntryPts = new AddressSet();
		removeEntryPts = new AddressSet();

		originalHash = new LongLongHashtable();
		latestHash = new LongLongHashtable();
		myHash = new LongLongHashtable();

		externalTypeConflictHash = new LongLongHashtable();

		setResolveInformation();

		// Set up an empty panel to be used as a GUI place holder when a conflict
		// in another merger already made a choice that resolved the conflict.
		emptyConflictPanel = new VerticalChoicesPanel();
		emptyConflictPanel.clear();
	}

	/**
	 * Puts the LongLongHashtables, that map the symbol IDs from LATEST, MY, and
	 * ORIGINAL programs to the RESULT program symbol IDs, into the Merge Manager.
	 */
	private void setResolveInformation() {
		if (mergeManager != null) {// may be null in Junits
			mergeManager.setResolveInformation(MergeConstants.RESOLVED_LATEST_SYMBOLS, latestHash);
			mergeManager.setResolveInformation(MergeConstants.RESOLVED_MY_SYMBOLS, myHash);
			mergeManager.setResolveInformation(MergeConstants.RESOLVED_ORIGINAL_SYMBOLS,
				originalHash);
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#getConflictType()
	 */
	@Override
	public String getConflictType() {
		return "Symbol";
	}

	/**
	 * Gets the symbolID from the result program that is the equivalent symbol
	 * to the symbol whose ID and program are specified as parameters.
	 * @param pgm the program the symbol ID is coming from
	 * @param symbolID the ID of the symbol in pgm
	 * @return the ID of the corresponding symbol in the result program
	 * or -1 if there is no corresponding symbol in the result program.
	 */
	private long resolveSymbolID(Program pgm, long symbolID) {
		int pgmIndex = getProgramIndex(pgm);
		try {
			switch (pgmIndex) {
				case LATEST:
					return getResultIDFromLatestID(symbolID);
				case MY:
					return getResultIDFromMyID(symbolID);
				case ORIGINAL:
					return getResultIDFromOriginalID(symbolID);
				case RESULT:
					if (resultSymTab.getSymbol(symbolID) != null) {
						return symbolID;
					}
					break;
			}
		}
		catch (NoValueException e) {
			// Couldn't get a result ID so do nothing here and fall thru to return -1;
		}
		return -1;
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
		Namespace srcGlobalNs = srcProgram.getGlobalNamespace();
		if (srcNamespace == null) {
			return null;
		}
		if (srcNamespace.equals(srcGlobalNs)) {
			return resultPgm.getGlobalNamespace();
		}
		Namespace resolvedNamespace = null;
		SymbolTable resolveSymTab = resultPgm.getSymbolTable();
		Symbol srcNsSymbol = srcNamespace.getSymbol();
		long srcNsID = srcNsSymbol.getID();
		long resolveNsID = resolveSymbolID(srcProgram, srcNsID);
		if (resolveNsID >= 0) { // Found the corresponding namespace symbol ID in result program.
			Symbol resolveSym = resolveSymTab.getSymbol(resolveNsID);
			resolvedNamespace = (Namespace) resolveSym.getObject();
		}
		else { // Didn't find the corresponding namespace symbol ID in result program.
				// Try to resolve the parent's ID and use it to get/create a namespace.
			Namespace origParentNs = srcNamespace.getParentNamespace();
			Namespace resultParentNs = resolveNamespace(srcProgram, origParentNs);
			String name = srcNsSymbol.getName();
			SymbolType st = srcNsSymbol.getSymbolType();
			Address resultAddr = SimpleDiffUtility.getCompatibleAddress(srcProgram,
				srcNsSymbol.getAddress(), resultPgm);
			resolvedNamespace = createNamespace(resultPgm, name, st, resultAddr, resultParentNs,
				srcProgram, srcNsSymbol.getID(), srcNsSymbol.getSource());
		}
		return resolvedNamespace;
	}

	/**
	 * Get/create a uniquely named namespace. If the namespace's name can't
	 * be created because of a name conflict, it will be given a new conflict name.
	 * @param resultProgram the program where the namespace is to be found or created
	 * @param name the desired name for the namespace
	 * @param st the symbol type for this namespace
	 * @param resultAddr the address in the result program for this namespace
	 * @param resultParentNs the parent of this namespace in the result program
	 * @param origPgm the program this namespace originated from
	 * @param origSymID the ID of the namespace in the program it originated from
	 * @return an equivalent namespace that exists or was created.
	 * @throws DuplicateNameException if the namespace couldn't be created
	 * because of an unresolvable name conflict.
	 * @throws InvalidInputException if the namespace couldn't be created
	 * because of an invalid name.
	 */
	private Namespace createNamespace(Program resultProgram, String name, SymbolType st,
			Address resultAddr, Namespace resultParentNs, Program srcPgm, long srcSymID,
			SourceType source) throws DuplicateNameException, InvalidInputException {
		SymbolTable symtab = resultProgram.getSymbolTable();
		// Need to create a unique named namespace that is equivalent to original.
		for (int i = 0; i < Integer.MAX_VALUE; i++) {
			String uniqueSymbolName =
				(i == 0) ? name : name + ProgramMerge.SYMBOL_CONFLICT_SUFFIX + i;

			Namespace ns = symtab.getNamespace(uniqueSymbolName, resultParentNs);
			if (ns != null) {
				Symbol s = ns.getSymbol();
				if (!s.getAddress().equals(resultAddr) || !s.getSymbolType().equals(st)) {
					continue; // Not the right one, so go to next conflict name.
				}
				// Found the equivalent namespace so return it.
				return ns;
			}
			// Create it, since nothing with this conflict name.
			Symbol uniqueSymbol = createSymbol(uniqueSymbolName, st, resultAddr, resultParentNs,
				srcPgm, srcSymID, source);
			if (uniqueSymbol != null) {
				Object obj = uniqueSymbol.getObject();
				if (obj instanceof Namespace) {
					if (!uniqueSymbolName.equals(name)) {
						renamedConflictIDs.add(uniqueSymbol.getID());
					}
					return (Namespace) obj;
				}
			}
			break; // Otherwise throw exception
		}
		throw new DuplicateNameException("Couldn't create namespace '" + name + "' in namespace '" +
			resultParentNs.getName(true) + "'.");
	}

	/**
	 * Determine the type of changes to the symbols in the LATEST and MY (CheckedOut) program.
	 * Changes can be symbol removed, added, changed, renamed, and set to primary.
	 * @param monitor task monitor for displaying progress to the user
	 * @throws CancelledException if the user cancels the merge.
	 */
	private void setupSymbolChanges(TaskMonitor monitor) throws CancelledException {

		long[] tempMyAddIDs = listingMergeMgr.myChanges.getSymbolAdditions();
		long[] tempMyChangeIDs = listingMergeMgr.myChanges.getSymbolChanges();
		long[] tempLatestAddIDs = listingMergeMgr.latestChanges.getSymbolAdditions();
		long[] tempLatestChangeIDs = listingMergeMgr.latestChanges.getSymbolChanges();

		int max = tempMyAddIDs.length + tempMyChangeIDs.length + tempLatestAddIDs.length +
			tempLatestChangeIDs.length + 5;
		monitor.setMessage("Symbol Merge: Pre-processing symbol changes...");
		monitor.initialize(max);
//		tempMyAddIDs = getNonMatchingIDsInFirst(tempMyAddIDs, tempMyChangeIDs, monitor);
//		tempMyChangeIDs = getNonMatchingIDsInFirst(tempMyChangeIDs, tempMyAddIDs, monitor);
//		tempLatestAddIDs = getNonMatchingIDsInFirst(tempLatestAddIDs, tempLatestChangeIDs, monitor);
//		tempLatestChangeIDs = getNonMatchingIDsInFirst(tempLatestChangeIDs, tempLatestAddIDs, monitor);

		// AddIDs now have added symbols that are still there.
		// ChangeIDs has symbols changed or removed.
		myPrimaryAddIDs = new LongHashSet();
		latestPrimaryAddIDs = new LongHashSet();

		monitor.setProgress(monitor.getProgress() + 1);
		this.myAddIDs = new long[tempMyAddIDs.length];
		System.arraycopy(tempMyAddIDs, 0, this.myAddIDs, 0, tempMyAddIDs.length);
		Arrays.sort(this.myAddIDs);

		monitor.setProgress(monitor.getProgress() + 1);
		this.latestAddIDs = new long[tempLatestAddIDs.length];
		System.arraycopy(tempLatestAddIDs, 0, this.latestAddIDs, 0, tempLatestAddIDs.length);
		Arrays.sort(this.latestAddIDs);

		monitor.setProgress(monitor.getProgress() + 1);
		this.myChangeIDs = new long[tempMyChangeIDs.length];
		System.arraycopy(tempMyChangeIDs, 0, this.myChangeIDs, 0, tempMyChangeIDs.length);
		Arrays.sort(this.myChangeIDs);

		monitor.setProgress(monitor.getProgress() + 1);
		this.latestChangeIDs = new long[tempLatestChangeIDs.length];
		System.arraycopy(tempLatestChangeIDs, 0, this.latestChangeIDs, 0,
			tempLatestChangeIDs.length);
		Arrays.sort(this.latestChangeIDs);

		monitor.checkCanceled();
		monitor.setProgress(monitor.getProgress() + 1);
		getPrimariesAdded(this.myAddIDs, mySymTab, myPrimaryAddIDs, mySetPrimary);
		getPrimariesAdded(this.latestAddIDs, latestSymTab, latestPrimaryAddIDs, latestSetPrimary);
		getChanges(mySymTab);
		getChanges(latestSymTab);
		// the calls to getChanges() may change some IDs in the add arrays to -1.
		// So find the -1 elements and remove them from the arrays.
		this.myAddIDs = getNonMatchingIDsInFirst(this.myAddIDs, new long[] { -1L }, monitor);
		this.latestAddIDs =
			getNonMatchingIDsInFirst(this.latestAddIDs, new long[] { -1L }, monitor);

		monitor.setProgress(max);
	}

	private long[] getNonMatchingIDsInFirst(long[] first, long[] second, TaskMonitor monitor)
			throws CancelledException {
		long[] uniqueIDs = new long[first.length];
		int u = 0;
		for (long element : first) {
			monitor.checkCanceled();
			monitor.setProgress(monitor.getProgress() + 1);
			boolean matched = false;
			for (long element2 : second) {
				if (element2 == element) {
					matched = true;
					break;
				}
			}
			if (!matched) {
				uniqueIDs[u++] = element;
			}
		}
		long[] results = new long[u];
		System.arraycopy(uniqueIDs, 0, results, 0, u);
		return results;
	}

	private void getPrimariesAdded(long[] symbolAddIDs, SymbolTable symTab, LongHashSet primaryAdds,
			AddressSet setPrimary) {
		for (long id : symbolAddIDs) {
			Symbol sym = symTab.getSymbol(id);
			if (sym != null && sym.isPrimary()) {
				SymbolType symType = sym.getSymbolType();
				if (((symType == SymbolType.LABEL) || (symType == SymbolType.FUNCTION)) &&
					!sym.isExternal()) {
					primaryAdds.add(id);
					Address addr = sym.getAddress();
					setPrimary.addRange(addr, addr);
				}
			}
		}
	}

	private void getChanges(SymbolTable newSymTab) {
		long[] symbolAddIDs;
		long[] symbolChangeIDs;
		AddressSet setPrimary;

		if (newSymTab == latestSymTab) {
			symbolAddIDs = this.latestAddIDs;
			symbolChangeIDs = this.latestChangeIDs;
			setPrimary = this.latestSetPrimary;
		}
		else if (newSymTab == mySymTab) {
			symbolAddIDs = this.myAddIDs;
			symbolChangeIDs = this.myChangeIDs;
			setPrimary = this.mySetPrimary;
		}
		else {
			return;
		}

		LongArrayList tempRemoves = new LongArrayList();
		LongArrayList modifies = new LongArrayList();
		LongArrayList renameChanges = new LongArrayList();
		LongArrayList primaryChanges = new LongArrayList();
//		LongArrayList commentChanges = new LongArrayList();
		LongArrayList sourceChanges = new LongArrayList();
		LongArrayList anchorChanges = new LongArrayList();

		boolean changeSymbolErrorOccurred = false;
		for (long id : symbolChangeIDs) {
			Symbol newSym = newSymTab.getSymbol(id);
			int index = indexOf(symbolAddIDs, id);
			if (index >= 0 && index < symbolAddIDs.length) {
				if (newSym == null) {
					// If it was added and then removed, it's like it was never added or removed.
					symbolAddIDs[index] = -1L; // Put -1 in the array to indicate to remove it.
				}
				// Else added and changed; all we care about is added, so ignore changed.
				continue;
			}
			Symbol oldSym = originalSymTab.getSymbol(id);
			if (newSym == null) {
				if (oldSym != null) {
					// Symbol was removed.
					tempRemoves.add(id);
				}
				// The following check for the id < 400000000L is to ignore default symbols
				// incorrectly being put in the change set for the 4.3 thru 4.3.2 versions.
				else if (id < 400000000L) {
					Msg.warn(this,
						"Symbol Merge Error: Could not find removed symbol in original program.\n" +
							"  Symbol ID = " + id);
					changeSymbolErrorOccurred = true;
				}
				continue;
			}
			if (oldSym == null) {
				Msg.warn(this,
					"Symbol Merge Error: Could not find changed symbol in original program.\n" +
						"  Symbol ID = " + id + "  Symbol Name = " + newSym.getName(true) +
						"  Address = " + newSym.getAddress().toString());
				changeSymbolErrorOccurred = true;
				continue;
			}
			boolean renamed = false;
			if (!newSym.getName().equals(oldSym.getName())) {
				renameChanges.add(id);
				renamed = true;
			}
			else if (!newSym.getParentNamespace().equals(oldSym.getParentNamespace())) {
				renameChanges.add(id);
				renamed = true;
			}
//			boolean commentChanged =
//				!SystemUtilities.isEqual(newSym.getSymbolStringData(), oldSym.getSymbolStringData());
			boolean sourceChanged = newSym.getSource() != oldSym.getSource();
//			if (commentChanged) {
//				commentChanges.add(id);
//			}
			if (sourceChanged) {
				sourceChanges.add(id);
			}
			if (renamed || sourceChanged) { // if (renamed || commentChanged || sourceChanged) {
				modifies.add(id);
			}
			if (newSym.isPinned() != oldSym.isPinned()) {
				anchorChanges.add(id);
			}
			if (newSym.isPrimary() && !oldSym.isPrimary()) {
				primaryChanges.add(id);
				Address addr = newSym.getAddress();
				setPrimary.addRange(addr, addr);
			}
		}
		if (newSymTab == latestSymTab) {
			latestRemoveIDs = tempRemoves.toLongArray();
			latestModifiedIDs = modifies.toLongArray();
			latestRenameIDs = renameChanges.toLongArray();
//			latestCommentChangeIDs = commentChanges.toLongArray();
			latestSourceChangeIDs = sourceChanges.toLongArray();
			latestAnchorChangeIDs = anchorChanges.toLongArray();
			latestPrimaryChangeIDs = primaryChanges.toLongArray();
		}
		else if (newSymTab == mySymTab) {
			myRemoveIDs = tempRemoves.toLongArray();
			myModifiedIDs = modifies.toLongArray();
			myRenameIDs = renameChanges.toLongArray();
//			myCommentChangeIDs = commentChanges.toLongArray();
			mySourceChangeIDs = sourceChanges.toLongArray();
			myAnchorChangeIDs = anchorChanges.toLongArray();
			myPrimaryChangeIDs = primaryChanges.toLongArray();
		}
		// Only pop up one error dialog due to bad IDs in the symbol change set.
		if (changeSymbolErrorOccurred) {
			Msg.error(this,
				"Symbol Merge Error: Could not find changed symbol in original program.\n" +
					"  See log for more details.");
		}
	}

	private int indexOf(long[] symbolAddIDs, long id) {
		// FIXME This does a brute force search of the array currently. Need to do this more efficiently.
		for (int index = 0; index < symbolAddIDs.length; index++) {
			if (id == symbolAddIDs[index]) {
				return index;
			}
		}
		return -1; // Couldn't find it.
	}

	@Override
	public boolean apply() {
		conflictOption = conflictPanel.getSelectedOptions();

		// If the "Use For All" check box is selected
		// then save the option chosen for this conflict type.
		if (conflictPanel.getUseForAll()) {
			setChoiceForSymbolConflictType(currentConflictType, conflictOption);
		}

		return super.apply();
	}

	private void setChoiceForSymbolConflictType(SymbolConflictType symbolConflictType,
			int choiceForSymbolConflict) {
		switch (symbolConflictType) {
			case ADDRESS_SYMBOL_CONFLICT:
				addressSymbolChoice = choiceForSymbolConflict;
				break;
			case PRIMARY_SYMBOL_CONFLICT:
				primarySymbolChoice = choiceForSymbolConflict;
				break;
			case REMOVE_SYMBOL_CONFLICT:
				removeSymbolChoice = choiceForSymbolConflict;
				break;
			case RENAME_SYMBOL_CONFLICT:
				renameSymbolChoice = choiceForSymbolConflict;
				break;
			default:
				Msg.showError(this, listingMergePanel, "Unrecognized Symbol Conflict Type",
					"Unrecognized indicator (" + symbolConflictType +
						") for symbol conflict type to merge.");
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#autoMerge(ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void autoMerge(int progressMinimum, int progressMaximum, TaskMonitor monitor)
			throws ProgramConflictException, MemoryAccessException, CancelledException {

		initializeAutoMerge("Auto-merging Symbols and determining conflicts.", progressMinimum,
			progressMaximum, monitor);

		// The ExternalFunctionMerger has external symbols that have been mapped so add them
		// to what the SymbolMerger already may have from calls to its resolve methods.
		if (mergeManager != null) {
			// Get the symbols that have already been resolved by the ExternalFunctionMerger.
			loadSymbolMapInfo(MergeConstants.RESOLVED_LATEST_SYMBOLS, latestHash);
			loadSymbolMapInfo(MergeConstants.RESOLVED_MY_SYMBOLS, myHash);
			loadSymbolMapInfo(MergeConstants.RESOLVED_ORIGINAL_SYMBOLS, originalHash);
		}

		if (currentMonitor != monitor) {
			currentMonitor = monitor;
		}
		monitor.checkCanceled();

		setupSymbolChanges(monitor); // Creates ID arrays used by processing methods.

		totalChanges =
			myRemoveIDs.length + myModifiedIDs.length + myAddIDs.length + myAnchorChangeIDs.length +
				mySetPrimary.getNumAddresses() + removeEntryPts.getNumAddresses() +
				addEntryPts.getNumAddresses() + deferredRemoveIDs.size();

		getEntryPtChanges(monitor);
		processRemoves(monitor);
		processModifies(monitor);
		processAdds(monitor);
		processAnchorChanges(monitor);
		processPrimaryChanges(monitor);
		updateEntryPtChanges(monitor);
		processDeferredRemoves(monitor);

		updateProgress(100, "Done auto-merging Symbols and determining conflicts.");
		cleanupIdArrays(); // Removes ID arrays used by processing methods.

		monitor.setMessage("Auto-merging Symbols completed.");
		monitor.setProgress(0);
	}

	private void loadSymbolMapInfo(String symbolMapIdentifier, LongLongHashtable mapToLoadInto) {
		LongLongHashtable resolvedSymbols =
			(LongLongHashtable) mergeManager.getResolveInformation(symbolMapIdentifier);
		long[] symbolKeys = resolvedSymbols.getKeys();
		for (long key : symbolKeys) {
			try {
				mapToLoadInto.put(key, resolvedSymbols.get(key));
			}
			catch (NoValueException e) {
				continue;
			}
		}
		symbolKeys = null;
		resolvedSymbols = null;
	}

	private void cleanupIdArrays() {
		latestRemoveIDs = null;
		latestModifiedIDs = null;
		latestRenameIDs = null;
//		latestCommentChangeIDs = null;
		latestSourceChangeIDs = null;
		latestAnchorChangeIDs = null;
		latestPrimaryChangeIDs = null;
		myRemoveIDs = null;
		myModifiedIDs = null;
		myRenameIDs = null;
//		myCommentChangeIDs = null;
		mySourceChangeIDs = null;
		myAnchorChangeIDs = null;
		myPrimaryChangeIDs = null;
	}

	private StringBuffer getRenamedConflictsInfo() {
		StringBuffer buf = new StringBuffer();
		Iterator<Long> iter = renamedConflictIDs.iterator();
		boolean hasSome = iter.hasNext();
		if (hasSome) {
			buf.append("The following symbols were renamed to avoid conflicts: \n");
		}
		while (iter.hasNext()) {
			long id = iter.next().longValue();
			Symbol s = resultSymTab.getSymbol(id);
			buf.append(s.getName(true) + "\n");
		}
		if (hasSome) {
			buf.append("\n");
		}
		return buf;
	}

	private StringBuffer getDeferredRemovesInfo() {
		StringBuffer buf = new StringBuffer();
		Iterator<Long> iter = deferredRemoveIDs.iterator();
		boolean hasSome = iter.hasNext();
		if (hasSome) {
			buf.append("The following namespaces were not removed since they were not empty: \n");
		}
		while (iter.hasNext()) {
			long id = iter.next().longValue();
			Symbol s = resultSymTab.getSymbol(id);
			buf.append(s.getName(true) + "\n");
		}
		if (hasSome) {
			buf.append("\n");
		}
		return buf;
	}

	private void processDeferredRemoves(TaskMonitor monitor) throws CancelledException {
		updateProgressMessage("Removing symbols that had been deferred...");
		monitor.setMessage("Symbol Merge: Processing removal of deferred symbols...");
		monitor.setProgress(0);

		// Save IDs to list since removal may mess up iterator.
		LongArrayList list = new LongArrayList();
		Iterator<Long> iter = deferredRemoveIDs.iterator();
		while (iter.hasNext()) {
			long id = iter.next().longValue();
			list.add(id);
		}
		// Loop and retry removing if some were removed since this may have
		// created empty namespaces that previously weren't empty.
		boolean removedSome;
		do {
			removedSome = false;
			// Check each deferred symbol still in the list.
			monitor.initialize(list.size());
			for (int i = 0; i < list.size(); i++) {
				monitor.setProgress(i);
				monitor.checkCanceled();
				long id = list.get(i);
				Symbol resultSymbol = resultSymTab.getSymbol(id);
				if (resultSymbol == null) {
					updateResolveIDs(originalPgm, id, -1);
					deferredRemoveIDs.remove(id);
					incrementProgress(1);
					continue;
				}
				Object obj = resultSymbol.getObject();
				if (obj instanceof Namespace) {
					SymbolIterator symIter = resultSymTab.getChildren(resultSymbol);
					if (!symIter.hasNext()) {
						// No longer has children so remove.
						resultSymbol.delete();
						updateResolveIDs(originalPgm, id, -1);
						deferredRemoveIDs.remove(id);
						list.remove(i--);
						removedSome |= true;
						incrementProgress(1);
					}
				}
			}
		}
		while (removedSome);
		monitor.setProgress(list.size());
	}

	private void processRemoves(TaskMonitor monitor) throws CancelledException {
		updateProgressMessage("Processing removed symbols...");
		monitor.setMessage("Symbol Merge: Processing removed symbols...");

		int len = myRemoveIDs.length;
		monitor.initialize(len);
		for (int i = 0; i < len; i++) {
			monitor.setProgress(i);
			monitor.checkCanceled();
			long id = myRemoveIDs[i];
			Symbol originalSym = originalSymTab.getSymbol(id);
			SymbolType originalType = originalSym.getSymbolType();
			// CODE, CLASS, EXTERNAL, FUNCTION, GLOBAL, GLOBAL_VAR, LIBRARY,
			// LOCAL_VAR, NAMESPACE, PARAMETER
			if ((originalType == SymbolType.LABEL && !originalSym.isExternal()) ||
				(originalType == SymbolType.CLASS) || (originalType == SymbolType.NAMESPACE)) {
				processSingleRemove(id, originalSym);
			}
		}
		monitor.setProgress(len);
	}

	private void processSingleRemove(long id, Symbol originalSym) {
		Symbol resultSym = resultSymTab.getSymbol(id);
		int index = Arrays.binarySearch(latestChangeIDs, id);
		if (index >= 0) {
			int removeIndex = Arrays.binarySearch(latestRemoveIDs, id);
			if (removeIndex < 0) {
				// My removed it and latest changed it.
				saveRemoveConflict(originalSym);
			}
			// else both removed it.
		}
		else if (resultSym != null) {
			// Remove the symbol. (AUTO_MERGE)
			removeSymbol(resultSym, id);
		}
	}

	private void processModifies(TaskMonitor monitor) throws CancelledException {
		updateProgressMessage("Processing modified symbols...");
		monitor.setMessage("Symbol Merge: Processing modified symbols...");

		int len = myModifiedIDs.length;
		monitor.initialize(len);
		for (int i = 0; i < len; i++) {
			monitor.setProgress(i);
			monitor.checkCanceled();
			incrementProgress(1);
			long id = myModifiedIDs[i];
			Symbol mySym = mySymTab.getSymbol(id);
			SymbolType myType = mySym.getSymbolType();
			Symbol resultSym = getResultSymbolFromMySymbol(mySym);
			// Symbol types are:
			// CLASS, EXTERNAL, FUNCTION, GLOBAL, GLOBAL_VAR, LIBRARY,
			// LOCAL_VAR, NAMESPACE, PARAMETER
			if (myType == SymbolType.FUNCTION) {
				if (resultSym != null) { // Function still exists.
					processModifiedFunctionNamespace(id, mySym, resultSym);
					// Functions were already handled by function merging, but
					// the associated symbol's comment and source was not.
					// If the symbol still exists then automatically handle the source and check
					// for comment conflicts.
					processModifiedFunctionSymbol(id, resultSym, mySym);
				}
				continue;
			}
			else if ((myType != SymbolType.LABEL) && (myType != SymbolType.CLASS) &&
				(myType != SymbolType.NAMESPACE)) {
				continue;
			}
			// Skip external labels since they should have already been handled by ExternalFunctionMerger.
			if (myType == SymbolType.LABEL && mySym.isExternal()) {
				continue;
			}

//			boolean modifiedInLatest = Arrays.binarySearch(latestModifiedIDs, id) >= 0;
			boolean removedInLatest = Arrays.binarySearch(latestRemoveIDs, id) >= 0;

			boolean renamedInMy = Arrays.binarySearch(myRenameIDs, id) >= 0;
//			boolean commentChangedInMy = Arrays.binarySearch(myCommentChangeIDs, id) >= 0;
			boolean sourceChangedInMy = Arrays.binarySearch(mySourceChangeIDs, id) >= 0;
			boolean renamedInLatest = Arrays.binarySearch(latestRenameIDs, id) >= 0;
//			boolean commentChangedInLatest = Arrays.binarySearch(latestCommentChangeIDs, id) >= 0;
			boolean sourceChangedInLatest = Arrays.binarySearch(latestSourceChangeIDs, id) >= 0;

			if (removedInLatest) {
				// Comment and source changes alone won't result in conflict.
				// Instead the remove wins out over symbol comment and source changes.
				if (renamedInMy) {
					saveRemoveConflict(mySym); // Rename My vs Remove Latest
				}
				continue;
			}
			if (renamedInMy) {
				if (renamedInLatest) {
					Symbol latestSym = latestSymTab.getSymbol(id);
					String myName = mySym.getName();
					Namespace myNamespace = mySym.getParentNamespace();
					String latestName = latestSym.getName();
					Namespace latestNamespace = latestSym.getParentNamespace();
					Namespace equivNamespace = DiffUtility.getNamespace(latestNamespace, myPgm);
					if (!myName.equals(latestName) || (myNamespace != equivNamespace)) {
						saveRenameConflict(id);
						continue;
					}
				}
				// Otherwise, auto merge the rename. (AUTO_MERGE)
				try {
					// Try to rename
					renameResultSymbol(mySym);
				}
				catch (Exception e) {
					String msg = "Failed to rename '" + mySym.getName(true) + "'.";
					Msg.showError(this, null, "Rename Symbol Error", msg, e);
				}
			}
			else {
				// Handle Symbol source if it wasn't done as part of a rename.
				if (resultSym != null) {
					if (sourceChangedInMy) {
						if (!sourceChangedInLatest) {
							try {
								// Use My version's source since Latest didn't change it.
								resultSym.setSource(mySym.getSource());
							}
							catch (IllegalArgumentException e) {
								Msg.warn(this, e.getMessage());
							}
						}
						// For now if symbol source conflict, Latest program (first in) wins.
					}
				}
			}
			// Handle Symbol comments.
//			if (commentChangedInMy) {
//				if (!commentChangedInLatest) {
//					if (resultSym != null) {
//						resultSym.setSymbolStringData(mySym.getSymbolStringData());
//					}
//				}
//				else {
//					Symbol latestSym = latestSymTab.getSymbol(id);
//					if (!SystemUtilities.isEqual(latestSym.getSymbolStringData(), mySym.getSymbolStringData())) {
//						saveCommentConflict(id);
//					}
//				}
//			}
		}
		monitor.setProgress(len);
	}

	private static boolean isDefaultThunk(Symbol s) {
		if (s.getSource() != SourceType.DEFAULT || s.getSymbolType() != SymbolType.FUNCTION) {
			return false;
		}
		Function f = (Function) s.getObject();
		return f.isThunk();
	}

	private void processModifiedFunctionNamespace(long id, Symbol mySym, Symbol resultSym) {
		Namespace myNs = // default thunks may lie about their namespace
			isDefaultThunk(mySym) ? mySym.getProgram().getGlobalNamespace()
					: mySym.getParentNamespace();
		Namespace resultNs = // default thunks may lie about their namespace
			isDefaultThunk(resultSym) ? resultSym.getProgram().getGlobalNamespace()
					: resultSym.getParentNamespace();
		try {
			Namespace desiredNs = resolveNamespace(myPgm, myNs);
			// Is the result namespace the one we actually want it to be?
			if (desiredNs != null && (desiredNs != resultNs)) {
				// Check to see if latest and my both changed the namespace.
				boolean renamedInMy = Arrays.binarySearch(myRenameIDs, id) >= 0;
				boolean renamedInLatest = Arrays.binarySearch(latestRenameIDs, id) >= 0;
				if (renamedInMy && renamedInLatest) {
					Symbol latestSym = latestSymTab.getSymbol(id);
					Namespace myNamespace = mySym.getParentNamespace();
					Namespace latestNamespace = latestSym.getParentNamespace();
					Namespace equivNamespace = DiffUtility.getNamespace(latestNamespace, myPgm);
					if (myNamespace != equivNamespace) {
						saveRenameConflict(id); // Both Latest and My put function in new namespace.
					}
					// Else Latest already moved to the same namespace as My.
				}
				else {
					resultSym.setNamespace(desiredNs); // Moved to new namespace only in My.
				}
			}
		}
		catch (UsrException e1) {
			String msg = "Failed to set namespace to '" + myNs.getName(true) + "' for function '" +
				resultSym.getName(true) + "'.";
			Msg.showError(this, null, "Rename Function Symbol Error", msg);
		}
	}

	private void processModifiedFunctionSymbol(long id, Symbol resultSym, Symbol mySym) {
		boolean renamedInMy = Arrays.binarySearch(myRenameIDs, id) >= 0;
//		boolean commentChangedInMy = Arrays.binarySearch(myCommentChangeIDs, id) >= 0;
		boolean sourceChangedInMy = Arrays.binarySearch(mySourceChangeIDs, id) >= 0;
		boolean renamedInLatest = Arrays.binarySearch(latestRenameIDs, id) >= 0;
//		boolean commentChangedInLatest = Arrays.binarySearch(latestCommentChangeIDs, id) >= 0;
		boolean sourceChangedInLatest = Arrays.binarySearch(latestSourceChangeIDs, id) >= 0;

		boolean renamed = renamedInMy || renamedInLatest;
		if (!renamed) {
			// Handle Symbol source if it wasn't done as part of a rename.
			if (sourceChangedInMy) {
				if (!sourceChangedInLatest) {
					try {
						// Use My version's source since Latest didn't change it.
						resultSym.setSource(mySym.getSource());
					}
					catch (IllegalArgumentException e) {
						Msg.warn(this, e.getMessage());
					}
				}
				// For now if symbol source conflict, Latest program (first in) wins.
			}
		}
		// Handle Symbol comments.
		// Function comment handle via listing plate comment
		// Symbol comment not supported
//		if (commentChangedInMy) {
//			if (!commentChangedInLatest) {
//				// Use My version's comment since Latest didn't change it.
//				resultSym.setSymbolStringData(mySym.getSymbolStringData());
//			}
//			else {
//				Symbol latestSym = latestSymTab.getSymbol(id);
//				if (!SystemUtilities.isEqual(latestSym.getSymbolStringData(), mySym.getSymbolStringData())) {
//					saveFunctionCommentConflict(id); // My & Latest changed comment differently.
//				}
//			}
//		}
	}

	private void processAnchorChanges(TaskMonitor monitor) throws CancelledException {
		updateProgressMessage("Processing symbol flag changes...");
		monitor.setMessage("Symbol Merge: Processing symbol flag changes...");

		int len = myAnchorChangeIDs.length;
		monitor.initialize(len);
		for (int i = 0; i < len; i++) {
			monitor.setProgress(i);
			monitor.checkCanceled();
			incrementProgress(1);
			long id = myAnchorChangeIDs[i];
			Symbol mySym = mySymTab.getSymbol(id);
			boolean removedInLatest = Arrays.binarySearch(latestRemoveIDs, id) >= 0;
			if (removedInLatest) {
				continue;
			}
			// Otherwise, auto merge the anchor flag change. (AUTO_MERGE)
			Symbol resultSym = resultSymTab.getSymbol(id);
			resultSym.setPinned(mySym.isPinned());
			incrementProgress(1);
		}
		monitor.setProgress(len);
	}

	private void processPrimaryChanges(TaskMonitor monitor) throws CancelledException {
		updateProgressMessage("Processing change of primary symbols...");
		monitor.setMessage("Symbol Merge: Processing change of primary symbols...");
		monitor.initialize(mySetPrimary.getNumAddresses());

		AddressIterator iter = mySetPrimary.getAddresses(true);
		while (iter.hasNext()) {
			monitor.incrementProgress(1);
			monitor.checkCanceled();
			incrementProgress(1);
			Address addr = iter.next();
			Symbol myPrimary = mySymTab.getPrimarySymbol(addr);
			if (myPrimary == null) {
				continue;
			}
			long myID = myPrimary.getID();
			int removeIndex = Arrays.binarySearch(latestRemoveIDs, myID);
			if (removeIndex >= 0) {
				Symbol originalSymbol = originalSymTab.getSymbol(myID);
				if (originalSymbol != null) {
					saveRemoveConflict(originalSymbol);
				}
			}
			if (latestSetPrimary.contains(addr)) {
				// Both changed primary so check for conflict.
				Symbol latestPrimary = latestSymTab.getPrimarySymbol(addr);
				Symbol latestSameAsMy = SimpleDiffUtility.getSymbol(myPrimary, latestPgm);
				if (!same(latestPrimary, latestSameAsMy)) {
					savePrimaryConflict(addr);
				}
			}
			else {
				// Only MY changed primary so try to set it.
				// THe symbol may not have been added yet and will get set later on add.
				Symbol resultSym = getResultSymbolFromMySymbol(myPrimary);
				if (resultSym != null) {
					resultSym.setPrimary();
				}
			}
		}
	}

	private void processAdds(TaskMonitor monitor) throws CancelledException {
		updateProgressMessage("Processing added symbols...");
		monitor.setMessage("Symbol Merge: Processing added symbols...");

		int len = myAddIDs.length;
		monitor.initialize(len);
		for (int i = 0; i < len; i++) {
			monitor.checkCanceled();
			incrementProgress(1);
			monitor.incrementProgress(1);
			long id = myAddIDs[i];
			Symbol mySym = mySymTab.getSymbol(id);
			if (myHash.contains(id)) {
				continue; // It's already resolved
			}
			if (mySym == null) {
				continue;
			}
			SymbolType myType = mySym.getSymbolType();
			// Symbol types.
			// CLASS, EXTERNAL, FUNCTION, GLOBAL, GLOBAL_VAR, LIBRARY,
			// LOCAL_VAR, NAMESPACE, PARAMETER
			if (!mySym.isExternal() && ((myType == SymbolType.FUNCTION) ||
				(myType == SymbolType.LOCAL_VAR) || (myType == SymbolType.PARAMETER))) {
				// Try to add
				processAddedFunctionSymbol(mySym);
			}
			else if ((myType != SymbolType.LABEL) && (myType != SymbolType.CLASS) &&
				(myType != SymbolType.NAMESPACE)) {
				continue;
			}
			// Otherwise, auto merge the add. (AUTO_MERGE)
			try {
				// Try to add
				SymbolType mySymbolType = mySym.getSymbolType();
				if (mySym.isExternal() && mySymbolType == SymbolType.LABEL) {
					continue; // External should have already been handled in ExternalMerger.
				}
				addSymbol(mySym);
				updateProgressMessage("Adding symbol: " + mySym.getName(true));
				monitor.setMessage("Symbol Merge: Added symbol " + i + " of " + len + "...");
			}
			catch (UsrException e) {
				String msg = "Failed to add '" + mySym.getName(true) + "'.";
				Msg.showError(this, null, "Add Symbol Error", msg);
			}
		}
		monitor.setProgress(len);
		updateProgressMessage(DEFAULT_PROGRESS_MESSAGE);
	}

	private void processAddedFunctionSymbol(Symbol mySym) {

		long id = mySym.getID();
		Symbol resultSym;
		if (myHash.contains(id)) {
			resultSym = getResultSymbolFromMyID(id); // Already merged in.
		}
		else {
			resultSym = SimpleDiffUtility.getSymbol(mySym, resultPgm);
//			String name = mySym.getName();
//			Namespace namespace = mySym.getParentNamespace();
//			Namespace resultNamespace = resolveNamespace(myPgm, namespace);
//			// FUTURE? May want to do something else for exceptions out of resolveNamespace().
//			if (resultNamespace == null) {
//				resultNamespace = DiffUtility.createNamespace(myPgm, namespace, resultPgm);
//			}
//			resultSym = resultSymTab.getSymbol(name, resultNamespace);
		}
		if (resultSym != null) {
			boolean renamedInMy = Arrays.binarySearch(myRenameIDs, id) >= 0;
//			boolean commentChangedInMy = Arrays.binarySearch(myCommentChangeIDs, id) >= 0;
			boolean sourceChangedInMy = Arrays.binarySearch(mySourceChangeIDs, id) >= 0;
			boolean renamedInLatest = Arrays.binarySearch(latestRenameIDs, id) >= 0;
//			boolean commentChangedInLatest = Arrays.binarySearch(latestCommentChangeIDs, id) >= 0;
			boolean sourceChangedInLatest = Arrays.binarySearch(latestSourceChangeIDs, id) >= 0;

			boolean renamed = renamedInMy || renamedInLatest;
			if (!renamed) {
				// Handle Symbol source if it wasn't done as part of a rename.
				if (sourceChangedInMy) {
					if (!sourceChangedInLatest) {
						try {
							// Use My version's source since Latest didn't change it.
							resultSym.setSource(mySym.getSource());
						}
						catch (IllegalArgumentException e) {
							Msg.warn(this, e.getMessage());
						}
					}
					// For now if symbol source conflict, Latest program (first in) wins.
				}
			}
			// Handle Symbol comments.
//			if (commentChangedInMy) {
//				if (!commentChangedInLatest) {
//					resultSym.setSymbolStringData(mySym.getSymbolStringData()); // Use My version's comment since Latest didn't change it.
//				}
//				else {
//					Symbol latestSym = latestSymTab.getSymbol(id);
//					if (!SystemUtilities.isEqual(latestSym.getSymbolStringData(), mySym.getSymbolStringData())) {
//						saveAddFunctionCommentConflict(id); // My & Latest changed comment differently.
//					}
//				}
//			}
		}
	}

	private void getEntryPtChanges(TaskMonitor monitor) throws CancelledException {
		AddressIterator originalIter = originalSymTab.getExternalEntryPointIterator();
		AddressIterator latestIter = latestSymTab.getExternalEntryPointIterator();
		AddressIterator myIter = mySymTab.getExternalEntryPointIterator();

		updateProgressMessage("Finding entry point changes...");
		monitor.setMessage("Symbol Merge: Finding entry point changes...");
		monitor.setProgress(0);

		MultiAddressIterator multiIter =
			new MultiAddressIterator(new AddressIterator[] { originalIter, latestIter, myIter });
		while (multiIter.hasNext()) {
			monitor.checkCanceled();
			Address[] addrs = multiIter.nextAddresses();
			if (addrs[0] != null) {
				if (addrs[1] == null || addrs[2] == null) {
					removeEntryPts.addRange(addrs[0], addrs[0]);
				}
			}
			else {
				if (addrs[1] != null) {
					addEntryPts.addRange(addrs[1], addrs[1]);
				}
				else if (addrs[2] != null) {
					addEntryPts.addRange(addrs[2], addrs[2]);
				}
			}
		}
	}

	private void updateEntryPtChanges(TaskMonitor monitor) throws CancelledException {
		updateProgressMessage("Updating entry point changes...");
		monitor.setMessage("Symbol Merge: Updating entry point changes...");
		monitor.setProgress(0);

		SymbolTable tempResultSymTab = resultPgm.getSymbolTable();
		// Remove entry points if possible.
		AddressIterator iter = removeEntryPts.getAddresses(true);
		while (iter.hasNext()) {
			monitor.checkCanceled();
			Address addr = iter.next();
			tempResultSymTab.removeExternalEntryPoint(addr);
			incrementProgress(1);
		}
		// Add entry points if possible.
		iter = addEntryPts.getAddresses(true);
		while (iter.hasNext()) {
			monitor.checkCanceled();
			Address addr = iter.next();
			tempResultSymTab.addExternalEntryPoint(addr);
			incrementProgress(1);
		}
	}

	private void renameResultSymbol(Symbol mySym)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		long id = mySym.getID();
		String name = mySym.getName();
		Address addr = mySym.getAddress();
		SourceType source = mySym.getSource();
		Namespace myNamespace = mySym.getParentNamespace();
		Namespace resultNamespace = DiffUtility.getNamespace(myNamespace, resultPgm);
		if (resultNamespace == null) {
			resultNamespace = DiffUtility.createNamespace(myPgm, myNamespace, resultPgm);
		}
		Symbol resultSym = resultSymTab.getSymbol(id);
		if (mySym.isDynamic() && resultSym.isDynamic()) {
			return;
		}
		// See if name exists in namespace already.
		Symbol addressSymbol = resultSymTab.getSymbol(name, addr, resultNamespace);
		if (addressSymbol != null) {
			if (addressSymbol != resultSym) {
				saveAddressConflict(addr, mySym);
			}
		}
		List<Symbol> symbols = resultSymTab.getSymbols(name, resultNamespace);
		for (Symbol symbol : symbols) {
			if (symbol == resultSym) {
				return;
			}
		}

		// rename and then set namespace.
		boolean nameChanged = !name.equals(resultSym.getName());
		boolean scopeChanged = resultSym.getParentNamespace() != resultNamespace;
		String tempName = null;
		if (nameChanged) {
			try {
				resultSym.setName(name, source);
			}
			catch (DuplicateNameException e) {
				if (scopeChanged) {
					// Just transitioning so use a temporary name.
					tempName = ProgramMerge.getUniqueName(resultSymTab, name, addr,
						resultSym.getParentNamespace(), resultNamespace, resultSym.getSymbolType());
					if (tempName == null) {
						throw e;
					}
					resultSym.setName(tempName, source);
				}
				else {
					String uniqueResultName = ProgramMerge.getUniqueName(resultSymTab, name, addr,
						resultSym.getParentNamespace(), resultNamespace, resultSym.getSymbolType());
					if (uniqueResultName == null) {
						throw e;
					}
					resultSym.setName(uniqueResultName, source);
					renamedConflictIDs.add(resultSym.getID());
				}
			}
		}
		if (scopeChanged) {
			resultSym.setNamespace(resultNamespace);
		}
		// Fix the name back up.
		if (tempName != null) {
			try {
				resultSym.setName(name, source);
			}
			catch (DuplicateNameException e) {
				renamedConflictIDs.add(resultSym.getID());
			}
		}
	}

	private void addSymbol(Symbol mySym) throws DuplicateNameException, InvalidInputException {
		long id = mySym.getID();
		if (myHash.contains(id)) {
			return; // Already merged in.
		}
		String name = mySym.getName();
		SymbolType myType = mySym.getSymbolType();
		if (myType == SymbolType.LOCAL_VAR || myType == SymbolType.PARAMETER) {
			return; // handled by function merger I think ? the code below won't properly handle variables
		}

		Address resultAddr =
			SimpleDiffUtility.getCompatibleAddress(myPgm, mySym.getAddress(), resultPgm);
		Namespace namespace = mySym.getParentNamespace();
		Namespace resultNamespace = resolveNamespace(myPgm, namespace);
		// FUTURE? May want to do something else for exceptions out of resolveNamespace().
		if (resultNamespace == null) {
			resultNamespace = DiffUtility.createNamespace(myPgm, namespace, resultPgm);
		}

		Symbol resultSym = resultSymTab.getSymbol(name, resultAddr, resultNamespace);

		if (resultSym != null) {
			// if the symbol we want to add is already there, map it and get out
			if (resultSym.getSymbolType() == myType) {
				long resultID = resultSym.getID();
				if (resultID != id) {
					myHash.put(id, resultID);
				}
				return;
			}
		}

		String newName = name;
		for (int i = 1; i < Integer.MAX_VALUE; i++) {
			try {
				resultSym = createSymbol(newName, myType, resultAddr, resultNamespace, myPgm, id,
					mySym.getSource());
				if (resultSym != null && i > 1) {
					renamedConflictIDs.add(resultSym.getID());
				}
				return;
			}
			catch (DuplicateNameException e) {
				// try again
			}
			newName = name + ProgramMerge.SYMBOL_CONFLICT_SUFFIX + i;
		}
		throw new DuplicateNameException("Couldn't create symbol '" + mySym.getName(true) + "'.");
	}

//	private void processAddedSymbolComment(Symbol resultSym, Symbol mySym) {
//		// My version added a symbol that matches on in the result version.
//		String resultComment = resultSym.getSymbolStringData();
//		String myComment = mySym.getSymbolStringData();
//		if (SystemUtilities.isEqual(resultComment, myComment)) {
//			return; // Already has My symbol comment.
//		}
//		if (myComment == null) {
//			return; // My version isn't setting a symbol comment.
//		}
//		if (resultComment == null) {
//			resultSym.setSymbolStringData(myComment); // Latest didn't set a comment, but My did so use My symbol comment.
//		}
//		else if (!myComment.equals(resultComment)) {
//			saveAddCommentConflict(mySym.getID()); // Both set a different symbol comment, so conflict
//		}
//	}

	private void saveRemoveConflict(Symbol originalSymbol) {
		Address addr = originalSymbol.getAddress();
		LongArrayList list = removes.get(addr);
		if (list == null) {
			list = new LongArrayList();
			removes.put(addr, list);
		}
		list.add(originalSymbol.getID());
		removeConflicts.addRange(addr, addr);
	}

	private void saveRenameConflict(long symbolID) {
		Address addr = originalSymTab.getSymbol(symbolID).getAddress();
		LongArrayList list = renames.get(addr);
		if (list == null) {
			list = new LongArrayList();
			renames.put(addr, list);
		}
		list.add(symbolID);
		renameConflicts.addRange(addr, addr);
	}

	private void saveAddressConflict(Address addr, Symbol symbol) {
		ArrayList<SymbolPath> list = symbolAddressConflicts.get(addr);
		if (list == null) {
			list = new ArrayList<>(1);
			symbolAddressConflicts.put(addr, list);
		}
		SymbolPath symbolPath = new SymbolPath(symbol.getPath());
		if (!list.contains(symbolPath)) {
			list.add(symbolPath);
		}
		addressConflicts.addRange(addr, addr);
	}

	private void savePrimaryConflict(Address addr) {
		primaryConflicts.addRange(addr, addr);
	}

	private int getIDCount(Hashtable<Address, LongArrayList> conflictHashtable, Address addr) {
		LongArrayList list = conflictHashtable.get(addr);
		if (list == null) {
			return 0;
		}
		return list.size();
	}

	@Override
	public boolean hasConflict(Address addr) {
		return removeConflicts.contains(addr) || renameConflicts.contains(addr) ||
			addressConflicts.contains(addr) || // commentConflicts.contains(addr) ||
			addCommentConflicts.contains(addr) || primaryConflicts.contains(addr);
	}

	@Override
	public int getConflictCount(Address addr) {
		return getIDCount(removes, addr) + getIDCount(renames, addr) +
			// getIDCount(comments, addr) +
			getConflictCountFromConflicts(addr) + getIDCount(addComments, addr) +
			(primaryConflicts.contains(addr) ? 1 : 0);
	}

	private int getConflictCountFromConflicts(Address addr) {
		ArrayList<SymbolPath> list = symbolAddressConflicts.get(addr);
		if (list == null) {
			return 0;
		}
		return list.size();
	}

	@Override
	public AddressSetView getConflicts() {
		AddressSet conflicts = new AddressSet();
		conflicts.add(removeConflicts);
		conflicts.add(renameConflicts);
//		conflicts.add(commentConflicts);
		conflicts.add(addressConflicts);
		conflicts.add(addCommentConflicts);
		conflicts.add(primaryConflicts);
		return conflicts;
	}

	@Override
	public void mergeConflicts(ListingMergePanel listingPanel, Address addr,
			int chosenConflictOption, TaskMonitor monitor)
			throws CancelledException, MemoryAccessException {
		if (!hasConflict(addr)) {
			return;
		}
		if (currentMonitor != monitor) {
			currentMonitor = monitor;
		}
		monitor.setMessage("Resolving Symbol conflicts.");
		handleRemoveConflict(listingPanel, addr, chosenConflictOption);
		handleRenameConflict(listingPanel, addr, chosenConflictOption);
//		handleCommentConflict(listingPanel, addr, chosenConflictOption);
		handleAddressConflict(listingPanel, addr, chosenConflictOption);
//		handleAddCommentConflict(listingPanel, addr, chosenConflictOption);
		handlePrimaryConflict(listingPanel, addr, chosenConflictOption);
		updateEntryPtChanges(monitor);
	}

	private void mergeConflicts(TaskMonitor monitor)
			throws MemoryAccessException, CancelledException {
		try {
			mergeManager.showProgressIcon(false);
			int originalConflictOption = conflictOption;
			AddressSetView listingConflictSet = getConflicts();
			long totalAddresses = listingConflictSet.getNumAddresses();
			AddressIterator iter = listingConflictSet.getAddresses(true);
			for (int addressNum = 1; iter.hasNext(); addressNum++) {
				Address addr = iter.next();
				conflictNum = 1;
				totalConflicts = getConflictCount(addr);
				if (listingMergePanel != null) {
					conflictInfoPanel.setAddressInfo(addr, addressNum, totalAddresses);
				}
				mergeConflicts(listingMergePanel, addr, originalConflictOption, monitor);
			}
		}
		finally {
			mergeManager.showProgressIcon(true);
		}
	}

	public void merge(int progressMinimum, int progressMaximum, TaskMonitor monitor)
			throws ProgramConflictException, MemoryAccessException, CancelledException {
		monitor.checkCanceled();
		monitor.setProgress(0);
		clearResolveInfo();
		autoMerge(progressMinimum, progressMaximum, monitor);
		monitor.checkCanceled();
		mergeConflicts(monitor);
		monitor.checkCanceled();
		processDeferredRemoves(monitor);
		monitor.checkCanceled();
		infoBuf.append(getDeferredRemovesInfo());
		infoBuf.append(getRenamedConflictsInfo());
		monitor.checkCanceled();
		showResolveInfo();
	}

	private void handlePrimaryConflict(ListingMergePanel listingPanel, Address addr,
			int chosenConflictOption) throws CancelledException {
		currentConflictType = SymbolConflictType.PRIMARY_SYMBOL_CONFLICT;
		boolean askUser = (primarySymbolChoice == ASK_USER) && (chosenConflictOption == ASK_USER);
		// Deal with primary conflicts (May or may not still be in conflict).
		if (primaryConflicts.contains(addr)) {
			Symbol latestPrimary = latestSymTab.getPrimarySymbol(addr);
			Symbol latestResultSymbol = getResultSymbolFromLatestSymbol(latestPrimary);
			Symbol myPrimary = mySymTab.getPrimarySymbol(addr);
			Symbol myResultSymbol = getResultSymbolFromMySymbol(myPrimary);
			if (myResultSymbol == null || same(myResultSymbol, latestResultSymbol)) {
				return;
			}
			currentAddress = addr;
			currentBackgroundSet = new AddressSet(addr, addr);
			if (askUser && mergeManager != null) {
				showConflictPanel(listingPanel, PRIMARY_CONFLICT, primarySymbolChoice,
					"Primary Symbol");
			}
			else {
				int optionToUse =
					(primarySymbolChoice == ASK_USER) ? chosenConflictOption : primarySymbolChoice;
				setPrimary(addr, optionToUse);
			}
		}
	}

	private void handleAddressConflict(ListingMergePanel listingPanel, Address addr,
			int chosenConflictOption) throws CancelledException {
		currentConflictType = SymbolConflictType.ADDRESS_SYMBOL_CONFLICT;
		boolean askUser = (addressSymbolChoice == ASK_USER) && (chosenConflictOption == ASK_USER);
		// At address get the symbol name ArrayList for each address conflict.
		if (addressConflicts.contains(addr)) {
			ArrayList<SymbolPath> addressConflictList = symbolAddressConflicts.get(addr);
			for (SymbolPath symbolPath : addressConflictList) {
				Symbol mySymbol = getSymbol(myPgm, symbolPath, addr);
				currentAddress = addr;
				currentSymbol = mySymbol;
				currentNamespace = mySymbol.getParentNamespace();
				currentSymbolName = mySymbol.getName();
				Namespace resultNamespace = DiffUtility.getNamespace(currentNamespace, resultPgm);
				uniqueName = ProgramMerge.getUniqueName(resultSymTab, currentSymbolName,
					currentAddress, resultNamespace, mySymbol.getSymbolType());
				currentBackgroundSet = new AddressSet(addr, addr);
				if (askUser && mergeManager != null) {
					showConflictPanel(listingPanel, ADDRESS_CONFLICT, addressSymbolChoice,
						"Symbol Address");
				}
				else {
					int optionToUse = (addressSymbolChoice == ASK_USER) ? chosenConflictOption
							: addressSymbolChoice;
					mergeSymbol(currentSymbol, optionToUse);
				}
			}
		}
	}

	private Symbol getSymbol(Program program, SymbolPath symbolPath, Address address) {
		List<Symbol> symbols = NamespaceUtils.getSymbols(symbolPath.getPath(), program);
		// There can be multiples because function namespaces are not unique, but for a given
		// address, there can only be symbol with that path since addresses can only be in one
		// program
		for (Symbol symbol : symbols) {
			if (symbol.getAddress().equals(address)) {
				return symbol;
			}
		}
		throw new AssertException("Expected a matching symbol when handling address conflicts");
	}

	private void handleRemoveConflict(ListingMergePanel listingPanel, Address addr,
			int chosenConflictOption) throws CancelledException {
		currentConflictType = SymbolConflictType.REMOVE_SYMBOL_CONFLICT;
		boolean askUser = (removeSymbolChoice == ASK_USER) && (chosenConflictOption == ASK_USER);
		// At address get the symbol name ArrayList for each remove conflict.
		if (removeConflicts.contains(addr)) {
			long[] removeIDs = removes.get(addr).toLongArray();
			for (long removeID : removeIDs) {
				if (isUnresolvableChange(removeID)) {
					continue;
				}

				Symbol originalSym = originalSymTab.getSymbol(removeID);
				currentAddress = addr;
				currentSymbol = originalSym;
				currentSymbolName = originalSym.getName();
				currentNamespace = originalSym.getParentNamespace();
				currentBackgroundSet = new AddressSet(addr, addr);
				if (askUser && mergeManager != null) {
					showConflictPanel(listingPanel, REMOVE_CONFLICT, removeSymbolChoice,
						"Remove Symbol");
				}
				else {
					try {
						int optionToUse = (removeSymbolChoice == ASK_USER) ? chosenConflictOption
								: removeSymbolChoice;
						resolveRemoveVsChange(removeID, optionToUse);
					}
					catch (Exception e) {
						String msg =
							"Failed to resolve symbol '" + originalSym.getName(true) + "'.";
						Msg.showError(this, null, "Remove vs Change Symbol Error", msg, e);
					}
				}
			}
		}
	}

	private void handleRenameConflict(ListingMergePanel listingPanel, Address addr,
			int chosenConflictOption) throws CancelledException {
		currentConflictType = SymbolConflictType.RENAME_SYMBOL_CONFLICT;
		boolean askUser = (renameSymbolChoice == ASK_USER) && (chosenConflictOption == ASK_USER);
		// At address get the symbol id LongArrayList for each rename conflict.
		if (renameConflicts.contains(addr)) {
			long[] renameIDs = renames.get(addr).toLongArray();
			for (long renameID : renameIDs) {
				Symbol originalSym = originalSymTab.getSymbol(renameID);
				currentAddress = addr;
				currentSymbol = originalSym;
				currentBackgroundSet = new AddressSet(addr, addr);
				if (askUser && mergeManager != null) {
					showConflictPanel(listingPanel, RENAME_CONFLICT, renameSymbolChoice,
						"Rename Symbol");
				}
				else {
					try {
						int optionToUse = (renameSymbolChoice == ASK_USER) ? chosenConflictOption
								: renameSymbolChoice;
						resolveRename(renameID, optionToUse);
					}
					catch (Exception e) {
						String msg = "Failed to rename symbol '" + originalSym.getName(true) + "'.";
						Msg.showError(this, null, "Rename Symbol Error", msg, e);
					}
				}
			}
		}
	}

//	private void handleCommentConflict(ListingMergePanel listingPanel, Address addr,
//			int chosenConflictOption) throws CancelledException {
//		boolean askUser = (symbolCommentChoice == ASK_USER) && (chosenConflictOption == ASK_USER);
//		// At address get the symbol id LongArrayList for each comment conflict.
//		if (commentConflicts.contains(addr)) {
//			long[] commentIDs = comments.get(addr).toLongArray();
//			for (int i = 0; i < commentIDs.length; i++) {
//				Symbol originalSym = originalSymTab.getSymbol(commentIDs[i]);
//				currentAddress = addr;
//				currentSymbol = originalSym;
//				currentBackgroundSet = new AddressSet(resultAddressFactory, addr, addr);
//				if (askUser && mergeManager != null) {
//					showConflictPanel(listingPanel, COMMENT_CONFLICT, symbolCommentChoice, "Symbol Comment");
//				}
//				else {
//					try {
//						int optionToUse = (symbolCommentChoice == ASK_USER) ?
//								chosenConflictOption : symbolCommentChoice;
//						resolveComment(commentIDs[i], optionToUse);
//					}
//					catch (Exception e) {
//						String msg =
//							"Failed to update comment for symbol '" + originalSym.getName(true) +
//								"'.";
//						Msg.showError(this, null, "Update Symbol Comment Error", msg, e);
//					}
//				}
//			}
//		}
//	}

//	private void handleAddCommentConflict(ListingMergePanel listingPanel, Address addr,
//			int chosenConflictOption) throws CancelledException {
//		boolean askUser = (symbolAddCommentChoice == ASK_USER) && (chosenConflictOption == ASK_USER);
//		// At address get the symbol id LongArrayList for each comment conflict.
//		if (addCommentConflicts.contains(addr)) {
//			long[] addCommentIDs = addComments.get(addr).toLongArray();
//			for (int i = 0; i < addCommentIDs.length; i++) {
//				Symbol mySym = mySymTab.getSymbol(addCommentIDs[i]);
//				currentAddress = addr;
//				currentSymbol = mySym;
//				Symbol resultSym = getResultSymbolFromMySymbol(mySym);
//				currentSymbolComment = (resultSym != null) ? resultSym.getSymbolStringData() : "";
//				currentBackgroundSet = new AddressSet(resultAddressFactory, addr, addr);
//				if (askUser && mergeManager != null) {
//					boolean useForAll = (symbolAddCommentChoice != ASK_USER);
//					conflictPanel.setUseForAll(useForAll);
//					conflictPanel.setConflictType("Symbol Add Comment");
//
//					showConflictPanel(listingPanel, ADD_COMMENT_CONFLICT,
//                      symbolAddCommentChoice, "Symbol Add Comment");
//				}
//				else {
//					try {
//						int optionToUse = (symbolAddCommentChoice == ASK_USER) ?
//							chosenConflictOption : symbolAddCommentChoice;
//						resolveAddComment(addCommentIDs[i], optionToUse);
//					}
//					catch (Exception e) {
//						String msg =
//							"Failed to update comment for symbol '" + mySym.getName(true) + "'.";
//						Msg.showError(this, null, "Update Symbol Comment Error", msg, e);
//					}
//				}
//			}
//		}
//	}

	private boolean isUnresolvableChange(long id) {
		Symbol original = originalSymTab.getSymbol(id);
		Symbol latest = latestSymTab.getSymbol(id);
		Symbol my = mySymTab.getSymbol(id);
		if (original != null) {
			if (latest != null && my == null) { // ID was removed from my program
				return hasSymbolWithNameConflict(latestPgm, latest, myPgm, true);
			}
			if (my != null && latest == null) { // ID was removed from latest program.
				return hasSymbolWithNameConflict(myPgm, my, latestPgm, true);
			}
		}
		return false; // ID wasn't in original program or was removed from latest and my.
	}

	/**
	 * Checks to see if there is a symbol in the otherProgram that conflicts
	 * with the indicated symbol. A conflict can be one of these types:
	 * 1) a symbol other than label or function that has the same name and 
	 * namespace as another non label or function.
	 * 2) a symbol at the same address with the same name and namespace.
	 *
	 * @param program the program that contains the specified symbol
	 * @param symbol the symbol (Can be original, latest, or my.)
	 * @param otherProgram the program to be checked for a conflicting symbol
	 * @param saveConflict if true this will also save the conflict for processing or in
	 * some cases automatically process the conflict.
	 * @return true if there is a symbol name conflict
	 */
	private boolean hasSymbolWithNameConflict(Program program, Symbol symbol, Program otherProgram,
			boolean saveConflict) {
		Symbol s = SimpleDiffUtility.getSymbol(symbol, otherProgram);
		if (s != null) {
			return false;
		}
		String name = symbol.getName();
		Namespace namespace = DiffUtility.getNamespace(symbol.getParentNamespace(), otherProgram);
		SymbolTable otherSymTab = otherProgram.getSymbolTable();
		Address address =
			SimpleDiffUtility.getCompatibleAddress(program, symbol.getAddress(), otherProgram);
		Symbol addressSymbol =
			(address != null) ? otherSymTab.getSymbol(name, address, namespace) : null;

		List<Symbol> sameNamespaceSymbols = otherSymTab.getSymbols(name, namespace);
		boolean addressConflict = isAddressConflict(addressSymbol);
		boolean namespaceConflict = isNamespaceConflict(sameNamespaceSymbols, symbol);
		if (saveConflict) {
			// There could be multiple types of conflicts for this symbol.
			if (addressConflict) {  // (example: changed vs removed)
				saveAddressConflict(address, symbol);	// this might be the wrong type of symbol
			}
			if (namespaceConflict) {  // (example: namespace vs library)
				// Symbol could be latest, my, or original. 
				// Only check namespace if it is my symbol that has a namespace conflict and rename it.
				if (program == myPgm) {
					Address myAddr = symbol.getAddress();
					Namespace myNs = symbol.getParentNamespace();
					String myName = symbol.getName();
					Namespace resultNs = DiffUtility.getNamespace(myNs, resultPgm);
					uniqueName = ProgramMerge.getUniqueName(resultSymTab, myName, myAddr, resultNs,
						symbol.getSymbolType());
					mergeSymbol(symbol, RENAME_MY);
				}
			}
		}
		return addressConflict || namespaceConflict;
	}

	private boolean isAddressConflict(Symbol addressSymbol) {
		return addressSymbol != null;
	}

	private boolean isNamespaceConflict(List<Symbol> sameNamespaceSymbols, Symbol symbol) {
		if (symbol.getSymbolType().allowsDuplicates()) {
			return false;
		}
		for (Symbol namespaceSymbol : sameNamespaceSymbols) {
			if (!namespaceSymbol.getSymbolType().allowsDuplicates()) {
				return true;
			}
		}
		return false;
	}

	private void resolveRemoveVsChange(long originalSymbolID, int chosenConflictOption)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		Symbol latest = latestSymTab.getSymbol(originalSymbolID);
		Symbol my = mySymTab.getSymbol(originalSymbolID);
		long resultID;
		Symbol result = null;
		try {
			resultID = getResultIDFromOriginalID(originalSymbolID);
			if (resultID != -1) {
				result = resultSymTab.getSymbol(resultID);
			}
		}
		catch (NoValueException e) {
			// Leave the result = null to indicate nothing to do if a remove
		}
		boolean latestRemoved = (latest == null);
		boolean myRemoved = (my == null);
		if ((chosenConflictOption & KEEP_LATEST) != 0) {
			if (!latestRemoved) {
				// Changed in LATEST
				if (result == null) {
					Symbol s = createSymbol(resultPgm, latestPgm, latest);
					long newID = s.getID();
					originalHash.put(originalSymbolID, newID);
					latestHash.put(originalSymbolID, newID);
				}
				else {
					replaceSymbol(resultPgm, result, latestPgm, latest);
				}
			}
			else if (result != null) {
				removeSymbol(result, originalSymbolID);
			}
		}
		else if ((chosenConflictOption & KEEP_MY) != 0) {
			if (!myRemoved) {
				if (result == null) {
					Symbol s = createSymbol(resultPgm, myPgm, my);
					long newID = s.getID();
					originalHash.put(originalSymbolID, newID);
					myHash.put(originalSymbolID, newID);
				}
				else {
					replaceSymbol(resultPgm, result, myPgm, my);
				}
			}
			else if (result != null) {
				removeSymbol(result, originalSymbolID);
			}
		}
	}

	private void resolveRename(long originalSymbolID, int chosenConflictOption)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		Symbol original = originalSymTab.getSymbol(originalSymbolID);
		Symbol latest = latestSymTab.getSymbol(originalSymbolID);
		Symbol my = mySymTab.getSymbol(originalSymbolID);
		long resultID;
		Symbol result = null;
		try {
			resultID = getResultIDFromOriginalID(originalSymbolID);
			result = resultSymTab.getSymbol(resultID);
		}
		catch (NoValueException e) {
			String msg = "Failed to rename symbol '" + original.getName(true) + "'.";
			Msg.showError(this, null, "Rename Symbol Error", msg);
		}
		if ((chosenConflictOption & KEEP_LATEST) != 0) {
			renameSymbol(resultPgm, result, latestPgm, latest);
		}
		else if ((chosenConflictOption & KEEP_MY) != 0) {
			renameSymbol(resultPgm, result, myPgm, my);
		}
	}

//	private void resolveComment(long originalSymbolID, int chosenConflictOption) {
//		Symbol original = originalSymTab.getSymbol(originalSymbolID);
//		Symbol latest = latestSymTab.getSymbol(originalSymbolID);
//		Symbol my = mySymTab.getSymbol(originalSymbolID);
//		long resultID;
//		Symbol result = null;
//		try {
//			resultID = getResultIDFromOriginalID(originalSymbolID);
//			result = resultSymTab.getSymbol(resultID);
//		}
//		catch (NoValueException e) {
//			String msg = "Failed to update comment for symbol '" + original.getName(true) + "'.";
//			Msg.showError(this, null, "Update Symbol Comment Error", msg);
//			return;
//		}
//		if ((chosenConflictOption & KEEP_LATEST) != 0) {
//			result.setSymbolStringData(latest.getSymbolStringData());
//		}
//		else if ((chosenConflictOption & KEEP_MY) != 0) {
//			result.setSymbolStringData(my.getSymbolStringData());
//		}
//	}

//	private void resolveAddComment(long mySymbolID, int chosenConflictOption) {
//		Symbol my = mySymTab.getSymbol(mySymbolID);
//		long resultID;
//		Symbol result = null;
//		try {
//			resultID = getResultIDFromMyID(mySymbolID);
//			result = resultSymTab.getSymbol(resultID);
//		}
//		catch (NoValueException e) {
//			String msg = "Failed to update comment for symbol '" + my.getName(true) + "'.";
//			Msg.showError(this, null, "Update Symbol Comment Error", msg);
//			return;
//		}
//		if ((chosenConflictOption & KEEP_RESULT) != 0) {
//			result.setSymbolStringData(currentSymbolComment);
//		}
//		else if ((chosenConflictOption & KEEP_MY) != 0) {
//			result.setSymbolStringData(my.getSymbolStringData());
//		}
//	}

	private long getResultIDFromOriginalID(long originalSymbolID) throws NoValueException {
		if (resultSymTab.getSymbol(originalSymbolID) != null) {
			return originalSymbolID;
		}
		return originalHash.get(originalSymbolID);
	}

	private Symbol getResultSymbolFromMySymbol(Symbol s) {
		if (s == null) {
			return null;
		}
		try {
			return resultSymTab.getSymbol(getResultIDFromMyID(s.getID()));
		}
		catch (NoValueException e) {
			return null;
		}
	}

	private Symbol getResultSymbolFromMyID(long symbolID) {
		try {
			return resultSymTab.getSymbol(getResultIDFromMyID(symbolID));
		}
		catch (NoValueException e) {
			return null;
		}
	}

	private long getResultIDFromMyID(long mySymbolID) throws NoValueException {
		try {
			return myHash.get(mySymbolID);
		}
		catch (NoValueException e) {
			Symbol mySymbol = mySymTab.getSymbol(mySymbolID);
			Symbol originalSymbol = originalSymTab.getSymbol(mySymbolID);
			SymbolType mySymbolType = (mySymbol != null) ? mySymbol.getSymbolType() : null;
			SymbolType originalSymbolType =
				(originalSymbol != null) ? originalSymbol.getSymbolType() : null;
			if ((originalSymbolType != null) && (originalSymbolType == mySymbolType)) {
				Symbol resultSymbol = resultSymTab.getSymbol(mySymbolID);
				SymbolType resultSymbolType =
					(resultSymbol != null) ? resultSymbol.getSymbolType() : null;
				if (originalSymbolType == resultSymbolType) {
					return mySymbolID;
				}
			}
			if (mySymbol != null) {
				Symbol resultSymbol = SimpleDiffUtility.getSymbol(mySymbol, resultPgm);
				if (resultSymbol != null) {
					return resultSymbol.getID();
				}
			}
			throw e;
		}
	}

	private Symbol getResultSymbolFromLatestSymbol(Symbol s) {
		if (s == null) {
			return null;
		}
		try {
			return resultSymTab.getSymbol(getResultIDFromLatestID(s.getID()));
		}
		catch (NoValueException e) {
			return null;
		}
	}

	private Symbol getResultSymbolFromOriginalSymbol(Symbol s) {
		if (s == null) {
			return null;
		}
		try {
			return resultSymTab.getSymbol(getResultIDFromOriginalID(s.getID()));
		}
		catch (NoValueException e) {
			return null;
		}
	}

	private long getResultIDFromLatestID(long latestSymbolID) throws NoValueException {
		try {
			return latestHash.get(latestSymbolID);
		}
		catch (NoValueException e) {
			if (resultSymTab.getSymbol(latestSymbolID) != null) {
				return latestSymbolID;
			}
			Symbol latestSymbol = mySymTab.getSymbol(latestSymbolID);
			if (latestSymbol != null) {
				Symbol resultSymbol = SimpleDiffUtility.getSymbol(latestSymbol, resultPgm);
				if (resultSymbol != null) {
					return resultSymbol.getID();
				}
			}
			throw e;
		}
	}

	private void showConflictPanel(final ListingMergePanel listingPanel, final int conflictType,
			final int choice, final String conflictTypeText) throws CancelledException {

		try {
			final ChangeListener changeListener = new ChangeListener() {
				@Override
				public void stateChanged(ChangeEvent e) {
					clearResolveInfo();
					int chosenConflictOption = SymbolMerger.this.conflictPanel.getSelectedOptions();
					if (chosenConflictOption == ASK_USER) {
						if (mergeManager != null) {
							mergeManager.setApplyEnabled(false);
						}
						return;
					}
					if (mergeManager != null) {
						mergeManager.clearStatusText();
					}
					try {
						mergeConflict(conflictType, chosenConflictOption);
						if (mergeManager != null) {
							mergeManager.setApplyEnabled(true);
						}
					}
					catch (Exception e1) {
						String msg = "Failed to resolve symbol '" +
							((currentSymbol != null) ? currentSymbol.getName(true) : "") + "'.";
						Msg.showError(this, null, "Resolve Symbol Error", msg, e1);
					}
					showResolveInfo();
				}
			};
			SwingUtilities.invokeAndWait(new Runnable() {
				@Override
				public void run() {
					getConflictPanel(conflictType, changeListener);
					if (conflictPanel != null) {
						listingPanel.setBottomComponent(conflictPanel);
					}
					else {
						listingPanel.setBottomComponent(emptyConflictPanel);
					}
				}
			});
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					listingPanel.clearAllBackgrounds();
					if (SymbolMerger.this.currentBackgroundSet != null) {
						listingPanel.paintAllBackgrounds(SymbolMerger.this.currentBackgroundSet);
					}
				}
			});
		}
		catch (InterruptedException e) {
			Msg.error(this, "Couldn't display Symbol Merger conflict panel. " + e.getMessage());
			return;
		}
		catch (InvocationTargetException e) {
			Msg.error(this, "Couldn't display Symbol Merger conflict panel. " + e.getMessage());
			return;
		}
		if (listingMergePanel != null) {
			conflictInfoPanel.setConflictInfo(conflictNum, totalConflicts);
		}
		if (mergeManager != null) {
			if (conflictPanel == null) {
				// conflict no longer exists.
				return;
			}
			mergeManager.setApplyEnabled(false);

			boolean useForAll = (choice != ASK_USER);
			conflictPanel.setUseForAll(useForAll);
			conflictPanel.setConflictType(conflictTypeText);

			mergeManager.showListingMergePanel(currentAddress);
		}
		// block until the user either cancels or hits the "Apply" button
		// on the merge dialog...
		// when the "Apply" button is hit, get the user's selection
		// and continue.

		conflictOption = conflictPanel.getSelectedOptions();
		if (conflictOption == CANCELED) {
			throw new CancelledException();
		}
		processDeferredRemoves(currentMonitor);
	}

	protected VerticalChoicesPanel getConflictPanel(int conflictType, ChangeListener listener) {
		// Re-use the same conflict panel
		if (conflictPanel == null) {
			conflictPanel = new VerticalChoicesPanel();
			currentConflictPanel = conflictPanel;
			conflictPanel.setTitle("Symbol");
		}
		switch (conflictType) {
			case REMOVE_CONFLICT:
				return getRemoveConflictPanel(currentSymbol, listener);
			case RENAME_CONFLICT:
				return getRenameConflictPanel(currentSymbol, listener);
//			case COMMENT_CONFLICT:
//				return getCommentConflictPanel(currentSymbol, listener);
//			case ADD_COMMENT_CONFLICT:
//				return getAddCommentConflictPanel(currentSymbol, listener);
			case NAMESPACE_CONFLICT:
				return getNamespaceConflictPanel(currentNamespace, currentSymbolName, listener);
			case ADDRESS_CONFLICT:
				return getAddressConflictPanel(currentAddress, currentSymbolName, listener);
			case PRIMARY_CONFLICT:
				return getPrimaryConflictPanel(currentAddress, listener);
			default:
				return null;
		}
	}

	private void mergeConflict(int conflictType, int chosenConflictOption)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {

		// currentSymbol is either original or my symbol.
		switch (conflictType) {
			case REMOVE_CONFLICT:
				resolveRemoveVsChange(currentSymbol.getID(), chosenConflictOption);
				break;
			case RENAME_CONFLICT:
				resolveRename(currentSymbol.getID(), chosenConflictOption);
				break;
//			case COMMENT_CONFLICT:
//				resolveComment(currentSymbol.getID(), chosenConflictOption);
//				break;
//			case ADD_COMMENT_CONFLICT:
//				resolveAddComment(currentSymbol.getID(), chosenConflictOption);
//				break;
			case NAMESPACE_CONFLICT:
			case ADDRESS_CONFLICT:
				// currentSymbol needs to be MY symbol.
				mergeSymbol(currentSymbol, chosenConflictOption);
				break;
			case PRIMARY_CONFLICT:
				setPrimary(currentAddress, chosenConflictOption);
				break;
		}
	}

	private Symbol createSymbol(Program resultProgram, Program sourceProgram, Symbol sourceSymbol)
			throws DuplicateNameException, InvalidInputException {
		SymbolTable resultSymbolTable = resultProgram.getSymbolTable();
		String resultName = sourceSymbol.getName();
		Address sourceAddress = sourceSymbol.getAddress();
		Namespace resultNamespace = getResultNamespace(resultProgram, sourceProgram, sourceSymbol);

		// FIXME
		Address resultAddress = null;
		if (!sourceSymbol.isExternal() || sourceAddress == Address.NO_ADDRESS) {
			// Don't try to use the external space address to get the symbol.
			resultAddress =
				SimpleDiffUtility.getCompatibleAddress(sourceProgram, sourceAddress, resultProgram);
		}

		Symbol resultSymbol = null;
		if (resultAddress != null) {
			resultSymbol = resultSymbolTable.getSymbol(resultName, resultAddress, resultNamespace);
		}
		else {
			Namespace namespace = resultSymbolTable.getNamespace(resultName, resultNamespace);
			if (namespace != null) {
				resultSymbol = namespace.getSymbol();
			}
		}

		if (resultSymbol == null) {
			resultSymbol = createResultSymbol(sourceSymbol, resultAddress, resultNamespace);
			// Handle primary.
			if (resultSymbol != null && sourceSymbol.isPrimary() && !resultSymbol.isPrimary()) {
				resultSymbol.setPrimary();
			}
		}
		return resultSymbol;
	}

	private Namespace getResultNamespace(Program resultProgram, Program sourceProgram,
			Symbol sourceSymbol) throws DuplicateNameException, InvalidInputException {
		Symbol resultNsSymbol = null;
		Namespace resultNamespace;
		Namespace sourceNamespace = sourceSymbol.getParentNamespace();
		Symbol sourceNsSymbol = sourceNamespace.getSymbol();

		if (sourceProgram == myPgm) {
			resultNsSymbol = getResultSymbolFromMySymbol(sourceNsSymbol);
		}
		else if (sourceProgram == latestPgm) {
			resultNsSymbol = getResultSymbolFromLatestSymbol(sourceNsSymbol);
		}
		else if (sourceProgram == originalPgm) {
			resultNsSymbol = getResultSymbolFromOriginalSymbol(sourceNsSymbol);
		}
		if (resultNsSymbol == null) {
			resultNamespace =
				DiffUtility.getNamespace(sourceSymbol.getParentNamespace(), resultProgram);
		}
		else {
			resultNamespace = (Namespace) resultNsSymbol.getObject();
		}
		if (resultNamespace == null) {
			resultNamespace = resolveNamespace(sourceProgram, sourceNamespace);
		}
		return resultNamespace;
	}

	private void replaceSymbol(Program oldProgram, Symbol oldSymbol, Program newProgram,
			Symbol newSymbol)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		renameSymbol(oldProgram, oldSymbol, newProgram, newSymbol);
//		oldSymbol.setSymbolStringData(newSymbol.getSymbolStringData());
		// Handle primary.
		if (newSymbol.isPrimary() && !oldSymbol.isPrimary()) {
			oldSymbol.setPrimary();
		}
	}

	/**
	 * Renames the oldSymbol to have a name and namespace equivalent to that of the newSymbol.
	 * @param oldProgram the program containing the old symbol
	 * @param oldSymbol the old symbol
	 * @param newProgram the program containing the new symbol
	 * @param newSymbol the new symbol
	 * @throws DuplicateNameException
	 * @throws InvalidInputException
	 * @throws CircularDependencyException
	 */
	private void renameSymbol(Program oldProgram, Symbol oldSymbol, Program newProgram,
			Symbol newSymbol)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		SourceType source = newSymbol.getSource();
		String newName = newSymbol.getName();
		Address addressInOldProgram =
			SimpleDiffUtility.getCompatibleAddress(newProgram, newSymbol.getAddress(), oldProgram);
		Namespace namespaceInOldProgram =
			DiffUtility.getNamespace(newSymbol.getParentNamespace(), oldProgram);
		if (namespaceInOldProgram == null) {
			throw new InvalidInputException("Couldn't get namespace '" +
				newSymbol.getParentNamespace().toString() + "' in result program.");
		}
		SymbolTable oldSymTab = oldProgram.getSymbolTable();
		Symbol existingSymbol =
			oldSymTab.getSymbol(newName, addressInOldProgram, namespaceInOldProgram);
		if (oldSymbol == existingSymbol) {
			return; // Already has correct name and scope.
		}

		// rename and then set namespace.
		String oldName = oldSymbol.getName();
		Namespace oldNamespace = oldSymbol.getParentNamespace();
		boolean nameChanged = !newName.equals(oldName);
		boolean scopeChanged = namespaceInOldProgram != oldNamespace;
		String tempName = null;
		if (nameChanged) {
			try {
				oldSymbol.setName(newName, source);
			}
			catch (DuplicateNameException e) {
				// Just transitioning so use a temporary name.
				tempName = ProgramMerge.getUniqueName(oldSymTab, newName, addressInOldProgram,
					oldNamespace, namespaceInOldProgram, oldSymbol.getSymbolType());
				if (tempName == null) {
					throw e;
				}
				oldSymbol.setName(tempName, source);
			}
		}
		if (scopeChanged) {
			oldSymbol.setNamespace(namespaceInOldProgram);
		}
		// Fix the name back up.
		if (tempName != null) {
			try {
				oldSymbol.setName(newName, source);
			}
			catch (DuplicateNameException e) {
				if (!tempName.equals(newName)) {
					renamedConflictIDs.add(oldSymbol.getID());
				}
			}
		}
	}

	private void removeMySymbol(Symbol resultSymbol, long myID) {
		if (resultSymbol == null) {
			return;
		}
		// If my symbol existed in original then defer to the removeSymbol(resultSymbol, originalID).
		Symbol originalSymbol = originalSymTab.getSymbol(myID);
		if (originalSymbol != null) {
			removeSymbol(resultSymbol, myID);
			return;
		}
		// Otherwise, this is my new symbol.
		resultSymbol.delete();
		myHash.remove(myID);
	}

	private void removeSymbol(Symbol resultSymbol, long originalID) {
		if (resultSymbol == null) {
			return;
		}
		Object obj = resultSymbol.getObject();
		if (obj instanceof Namespace) {
			SymbolIterator iter = resultSymTab.getChildren(resultSymbol);
			if (iter.hasNext()) {
				// Don't remove this namespace yet, since it has children.
				deferredRemoveIDs.add(originalID);
				return;
			}
		}
		resultSymbol.delete();
		updateResolveIDs(originalPgm, originalID, -1);
		incrementProgress(1);
	}

	private void mergeSymbol(Symbol originalOrMySymbol, int chosenConflictOption) {
		long myID = originalOrMySymbol.getID();
		if (chosenConflictOption == REMOVE_MY) {
			long resultID;
			try {
				resultID = myHash.get(myID);
			}
			catch (NoValueException e) {
				myHash.put(myID, -1); // Indicate my symbol was discarded.
				return;
			}
			Symbol resultSymbol = resultSymTab.getSymbol(resultID);
			if (resultSymbol != null) {
				removeMySymbol(resultSymbol, myID);
			}
		}
		else if (chosenConflictOption == RENAME_MY) {
			try {
				myHash.get(myID);
				Msg.error(this, "Error: My symbol '" + originalOrMySymbol.toString() +
					"' has already been merged.");
				return; // Already been merged.
			}
			catch (NoValueException e) {
				// Normally we shouldn't find a mapping of the symbol to be merged.
			}
			try {
				renameToMySymbol(originalOrMySymbol);
			}
			catch (Exception e1) {
				String msg = "Failed to rename '" + originalOrMySymbol.getName(true) + "'.";
				Msg.showError(this, null, "Rename Symbol Error", msg, e1);
			}
		}
	}

	private void renameToMySymbol(Symbol mySymbol)
			throws DuplicateNameException, InvalidInputException {
		long myID = mySymbol.getID();
		String myName = mySymbol.getName();
		Address myAddr = mySymbol.getAddress();
		Namespace myNamespace = mySymbol.getParentNamespace();
		SymbolType myType = mySymbol.getSymbolType();
		Object myObject = mySymbol.getObject();
		Address resultAddress = SimpleDiffUtility.getCompatibleAddress(myPgm, myAddr, resultPgm);
		Namespace resultNamespace = resolveNamespace(myPgm, myNamespace);
		String tempUniqueName = ProgramMerge.getUniqueName(resultSymTab, myName, resultAddress,
			resultNamespace, myType);
		Symbol resultSymbol = null;
		if (myType == SymbolType.FUNCTION) {
			Function myFunction = (Function) myObject;
			Function f = DiffUtility.getFunction(myFunction, resultPgm);
			if (f != null) {
				f.setName(tempUniqueName, mySymbol.getSource()); // This may have already been resolved by FunctionMerger.
				resultSymbol = f.getSymbol();
			}
		}
		else {
			// This actually creates a uniquely named symbol since this is typically the way
			// RENAME is used for conflicts within the SymbolMerger as opposed to changing
			// the name of whatever is already in the RESULT. (i.e. Rename My symbol being added.)
			resultSymbol = createSymbol(tempUniqueName, myType, resultAddress, resultNamespace,
				myPgm, myID, mySymbol.getSource());
		}
		if (resultSymbol != null) {
			myHash.put(myID, resultSymbol.getID());
		}
	}

	/**
	 * Gets an array of strings indicating what the full path  would be if a symbol with
	 * the indicated name were in the specified namespace.
	 * @param name the symbol name
	 * @param namespace the namespace
	 * @return the path as an array
	 */
	public String[] getPath(String name, Namespace namespace) {
		String[] namespacePath = namespace.getSymbol().getPath();
		String[] path = new String[namespacePath.length + 1];
		System.arraycopy(namespacePath, 0, path, 0, namespacePath.length);
		path[namespacePath.length] = name;
		return path;
	}

	private Symbol createSymbol(String name, SymbolType type, Address resultAddr,
			Namespace resultParentNs, Program srcPgm, long srcSymID, SourceType source)
			throws DuplicateNameException, InvalidInputException {
//		String comment = srcSymbol.getSymbolStringData();
		Symbol symbol = null;
		if (type == SymbolType.LABEL) {
			symbol = resultSymTab.createLabel(resultAddr, name, resultParentNs, source);
		}
		else if (type == SymbolType.CLASS) {
			GhidraClass newGhidraClass = resultSymTab.createClass(resultParentNs, name, source);
			symbol = newGhidraClass.getSymbol();
		}
		else if (type == SymbolType.NAMESPACE) {
			Namespace newNamespace = resultSymTab.createNameSpace(resultParentNs, name, source);
			symbol = newNamespace.getSymbol();
		}
		else if (type == SymbolType.LIBRARY) {
			ExternalManager srcExtMgr = srcPgm.getExternalManager();
			String path = srcExtMgr.getExternalLibraryPath(name);

			ExternalManagerDB extMgr = (ExternalManagerDB) resultPgm.getExternalManager();
			extMgr.setExternalPath(name, path, (source == SourceType.USER_DEFINED));
			symbol = resultSymTab.getLibrarySymbol(name);
		}
		if (symbol != null) {
//			symbol.setSymbolStringData(comment);
			if (symbol.getParentNamespace().equals(resultParentNs)) {
				long resolveSymID = symbol.getID();
				updateResolveIDs(srcPgm, srcSymID, resolveSymID);
			}
		}
		return symbol;
	}

	private void updateResolveIDs(Program srcPgm, long srcSymID, long resolveSymID) {
		// save the resolve info to the hash set
		int pgmIndex = getProgramIndex(srcPgm);
		if (originalSymTab.getSymbol(srcSymID) != null) {
			latestHash.put(srcSymID, resolveSymID);
			myHash.put(srcSymID, resolveSymID);
			originalHash.put(srcSymID, resolveSymID);
		}
		else {
			switch (pgmIndex) {
				case LATEST:
					latestHash.put(srcSymID, resolveSymID);
					break;
				case MY:
					myHash.put(srcSymID, resolveSymID);
					break;
			}
		}
	}

	private Symbol createResultSymbol(Symbol originalSymbol, Address address, Namespace namespace)
			throws DuplicateNameException, InvalidInputException {
		Symbol resultSymbol = null;
		SymbolType symType = originalSymbol.getSymbolType();
		String symbolName = originalSymbol.getName();
		SourceType source = originalSymbol.getSource();
		if (symType == SymbolType.LABEL) {
			if (originalSymbol.isExternal()) {
				ExternalManager resultExternalManager = resultPgm.getExternalManager();
				ExternalLocation resultExtLocation =
					resultExternalManager.addExtLocation(namespace, symbolName, address, source);
				resultSymbol = resultExtLocation.getSymbol();
			}
			else {
				resultSymbol = resultSymTab.createLabel(address, symbolName, namespace, source);
			}
		}
		else if (symType == SymbolType.CLASS) {
			GhidraClass newGhidraClass = resultSymTab.createClass(namespace, symbolName, source);
			resultSymbol = newGhidraClass.getSymbol();
		}
		else if (symType == SymbolType.LIBRARY) {
			resultSymTab.createExternalLibrary(symbolName, source);
		}
		else if (symType == SymbolType.NAMESPACE) {
			Namespace newNamespace = resultSymTab.createNameSpace(namespace, symbolName, source);
			resultSymbol = newNamespace.getSymbol();
		}
		return resultSymbol;
	}

	/**
	 * Sets the primary symbol at the indicated address to be the one that is
	 * primary in the program indicated by conflictOption.
	 * @param addr the address
	 * @param conflictOption KEEP_LATEST, KEEP_MY, or KEEP_ORIGINAL.
	 */
	private void setPrimary(Address addr, int conflictOption) {
		Symbol primary = null;
		switch (conflictOption) {
			case KEEP_LATEST:
				primary = getResultSymbolFromLatestSymbol(latestSymTab.getPrimarySymbol(addr));
				break;
			case KEEP_MY:
				primary = getResultSymbolFromMySymbol(mySymTab.getPrimarySymbol(addr));
				break;
			case KEEP_ORIGINAL:
				primary = getResultSymbolFromOriginalSymbol(originalSymTab.getPrimarySymbol(addr));
				break;
		}
		if ((primary != null) && !primary.isPrimary()) {
			primary.setPrimary();
		}
	}

	/**
	 * Returns the conflict panel for resolving whether to remove or change a symbol.
	 * @param symbol the symbol
	 * @param listener listener for handling user selecting an option.
	 * @return the conflict panel
	 */
	protected VerticalChoicesPanel getRemoveConflictPanel(Symbol symbol, ChangeListener listener) {
		long symbolID = symbol.getID();
		String text = "Symbol '" + ConflictUtility.getEmphasizeString(symbol.getName(true)) +
			"' @ address " + ConflictUtility.getAddressString(symbol.getAddress()) +
			"' was removed in one version and changed in other.";
		conflictPanel.clear();
		conflictPanel.setHeader(text);
		conflictPanel.setRowHeader(getSymbolInfo(null, null));
		Symbol latestSymbol = latestPgm.getSymbolTable().getSymbol(symbolID);
		Symbol mySymbol = myPgm.getSymbolTable().getSymbol(symbolID);
		String latestPrefix = (latestSymbol == null) ? "Remove as in '" : "Change as in '";
		String myPrefix = (mySymbol == null) ? "Remove as in '" : "Change as in '";
		String suffix = "' version";
		conflictPanel.addRadioButtonRow(
			getSymbolInfo(latestPgm, latestSymbol, latestPrefix, suffix), LATEST_BUTTON_NAME,
			KEEP_LATEST, listener);
		conflictPanel.addRadioButtonRow(getSymbolInfo(myPgm, mySymbol, myPrefix, suffix),
			CHECKED_OUT_BUTTON_NAME, KEEP_MY, listener);
		conflictPanel.addInfoRow(getSymbolInfo(originalPgm, symbolID, "'", suffix));
		return conflictPanel;
	}

	/**
	 * Returns the conflict panel for resolving which name to use when
	 * Latest and My programs both renamed the symbol.
	 * @param symbol the symbol
	 * @param listener listener for handling user selecting an option.
	 * @return the conflict panel
	 */
	protected VerticalChoicesPanel getRenameConflictPanel(Symbol symbol, ChangeListener listener) {
		long symbolID = symbol.getID();
		String text = "Symbol: " + ConflictUtility.getEmphasizeString(symbol.getName(true)) +
			ConflictUtility.spaces(4) + "Address: " +
			ConflictUtility.getAddressString(symbol.getAddress());
		conflictPanel.clear();
		conflictPanel.setHeader(text);
		conflictPanel.setRowHeader(getSymbolInfo(null, null));
		String prefix = "Rename as in '";
		String suffix = "' version";
		conflictPanel.addRadioButtonRow(getSymbolInfo(latestPgm, symbolID, prefix, suffix),
			LATEST_BUTTON_NAME, KEEP_LATEST, listener);
		conflictPanel.addRadioButtonRow(getSymbolInfo(myPgm, symbolID, prefix, suffix),
			CHECKED_OUT_BUTTON_NAME, KEEP_MY, listener);
		conflictPanel.addInfoRow(getSymbolInfo(originalPgm, symbolID, "'", suffix));
		return conflictPanel;
	}

	/**
	 * Returns the conflict panel for resolving which comment to use when
	 * Latest and My programs both changed the symbol comment.
	 * @param symbol the symbol
	 * @param listener listener for handling user selecting an option.
	 * @return the conflict panel
	 */
//	protected VerticalChoicesPanel getCommentConflictPanel(Symbol symbol, ChangeListener listener) {
//		long symbolID = symbol.getID();
//		String text =
//			"Symbol: " + ConflictUtility.getEmphasizeString(symbol.getName(true)) +
//				ConflictUtility.spaces(4) + "Address: " +
//				ConflictUtility.getAddressString(symbol.getAddress());
//		conflictPanel.clear();
//		conflictPanel.setHeader(text);
//		conflictPanel.setRowHeader(getSymbolCommentInfo(null, null, "", ""));
//		String prefix = "Set comment as in '";
//		String suffix = "' version";
//		conflictPanel.addRadioButtonRow(getSymbolCommentInfo(latestPgm, symbolID, prefix, suffix),
//			LATEST_BUTTON_NAME, KEEP_LATEST, listener);
//		conflictPanel.addRadioButtonRow(getSymbolCommentInfo(myPgm, symbolID, prefix, suffix),
//			CHECKED_OUT_BUTTON_NAME, KEEP_MY, listener);
//		conflictPanel.addInfoRow(getSymbolCommentInfo(originalPgm, symbolID, "'", suffix));
//		return conflictPanel;
//	}

	/**
	 * Returns the conflict panel for resolving which comment to use when
	 * Result and My programs symbol comment don't match.
	 * @param symbol the symbol from My version.
	 * @param listener listener for handling user selecting an option.
	 * @return the conflict panel
	 */
//	protected VerticalChoicesPanel getAddCommentConflictPanel(Symbol mySymbol,
//			ChangeListener listener) {
//		Symbol resultSymbol = getResultSymbolFromMySymbol(mySymbol);
//		Symbol symbol = (resultSymbol != null) ? resultSymbol : mySymbol;
//		String text =
//			"Symbol: " + ConflictUtility.getEmphasizeString(symbol.getName(true)) +
//				ConflictUtility.spaces(4) + "Address: " +
//				ConflictUtility.getAddressString(symbol.getAddress());
//		conflictPanel.clear();
//		conflictPanel.setHeader(text);
//		conflictPanel.setRowHeader(getSymbolCommentInfo(null, null, "", ""));
//		String prefix = "Set comment as in '";
//		String suffix = "' version";
//		conflictPanel.addRadioButtonRow(
//			getSymbolCommentInfo(null, resultSymbol, "Leave comment as it was.", ""),
//			RESULT_BUTTON_NAME, KEEP_RESULT, listener);
//		conflictPanel.addRadioButtonRow(getSymbolCommentInfo(myPgm, mySymbol, prefix, suffix),
//			CHECKED_OUT_BUTTON_NAME, KEEP_MY, listener);
//		return conflictPanel;
//	}

	/**
	 * Returns the conflict panel for resolving different symbols with the
	 * same name in the same namespace.
	 * @param myNamespace the symbol namespace
	 * @param symbolName the symbol name
	 * @param listener listener for handling user selecting an option.
	 * @return the conflict panel
	 */
	protected VerticalChoicesPanel getNamespaceConflictPanel(Namespace myNamespace,
			String symbolName, ChangeListener listener) {
		Symbol latest =
			latestSymTab.getNamespace(symbolName, DiffUtility.getNamespace(myNamespace, latestPgm))
					.getSymbol();
		Symbol my = mySymTab.getNamespace(symbolName, myNamespace).getSymbol();
		String text = "Namespace Conflict";
		conflictPanel.clear();
		conflictPanel.setHeader(text);
		conflictPanel.setRowHeader(getSymbolInfo(null, my));
		String prefix = "'";
		String suffix = "' version";
		conflictPanel.addInfoRow(getSymbolInfo(latestPgm, latest, prefix, suffix));
		conflictPanel.addInfoRow(getSymbolInfo(myPgm, my, prefix, suffix));
		String removeMsg = "Discard '" + MY_TITLE + "' symbol";
		String renameMsg = "Rename '" + MY_TITLE + "' symbol to '" + uniqueName + "'";
		conflictPanel.addRadioButtonRow(new String[] { removeMsg }, REMOVE_CHECKED_OUT_BUTTON_NAME,
			REMOVE_MY, listener);
		conflictPanel.addRadioButtonRow(new String[] { renameMsg }, RENAME_CHECKED_OUT_BUTTON_NAME,
			RENAME_MY, listener);
		return conflictPanel;
	}

	/**
	 * Returns the conflict panel for resolving symbols with the same name and namespace at an address.
	 * @param address the address
	 * @param symbolName the name of the conflicting symbol
	 * @param listener listener for handling user selecting an option.
	 * @return the conflict panel
	 */
	protected VerticalChoicesPanel getAddressConflictPanel(Address address, String symbolName,
			ChangeListener listener) {
		Symbol my = currentSymbol;
		Namespace latestNamespace = DiffUtility.getNamespace(currentNamespace, latestPgm);
		Symbol latest = latestSymTab.getSymbol(symbolName, currentAddress, latestNamespace);
		String text = "Symbol Name Conflict @ " + ConflictUtility.getAddressString(currentAddress) +
			"<br>Can't have symbols with same name and different scope at an address.";
		conflictPanel.clear();
		conflictPanel.setHeader(text);
		conflictPanel.setRowHeader(getSymbolInfo(null, my));
		String prefix = "'";
		String suffix = "' version";
		conflictPanel.addInfoRow(getSymbolInfo(latestPgm, latest, prefix, suffix));
		conflictPanel.addInfoRow(getSymbolInfo(myPgm, my, prefix, suffix));
		conflictPanel.addInfoRow(new String[] { "", "", "", "", "", "", "" });
		String removeMsg = "Discard '" + MY_TITLE + "' symbol";
		String renameMsg = "Rename '" + MY_TITLE + "' symbol to '" + uniqueName + "'";
		conflictPanel.addRadioButtonRow(new String[] { removeMsg, "", "", "", "", "", "" },
			REMOVE_CHECKED_OUT_BUTTON_NAME, REMOVE_MY, listener);
		conflictPanel.addRadioButtonRow(new String[] { renameMsg, "", "", "", "", "", "" },
			RENAME_CHECKED_OUT_BUTTON_NAME, RENAME_MY, listener);
		return conflictPanel;
	}

	/**
	 * Returns the conflict panel for resolving differences in the symbol
	 * set to primary at an address.
	 * @param address the address
	 * @param listener listener for handling user selecting an option.
	 * @return the conflict panel or null if the conflict no longer exists.
	 */
	private VerticalChoicesPanel getPrimaryConflictPanel(Address address, ChangeListener listener) {
		Symbol original = originalSymTab.getPrimarySymbol(address);
		Symbol latest = latestSymTab.getPrimarySymbol(address);
		Symbol my = mySymTab.getPrimarySymbol(address);
		try {
			latest = resultSymTab.getSymbol(getResultIDFromLatestID(latest.getID()));
		}
		catch (NoValueException e) {
			conflictPanel = null;
			return null;
		}
		try {
			my = resultSymTab.getSymbol(getResultIDFromMyID(my.getID()));
		}
		catch (NoValueException e) {
			conflictPanel = null;
			return null;
		}
		String text = "Primary Symbol Conflict";
		conflictPanel.clear();
		conflictPanel.setHeader(text);
		conflictPanel.setRowHeader(getPrimarySymbolInfo(null, null, null, null));
		conflictPanel.addRadioButtonRow(
			getPrimarySymbolInfo(latestPgm, latest, "Set '", "' to primary"), LATEST_BUTTON_NAME,
			KEEP_LATEST, listener);
		conflictPanel.addRadioButtonRow(getPrimarySymbolInfo(myPgm, my, "Set '", "' to primary"),
			CHECKED_OUT_BUTTON_NAME, KEEP_MY, listener);
		conflictPanel.addInfoRow(getPrimarySymbolInfo(originalPgm, original, "'", "' version"));
		return conflictPanel;
	}

	/**
	 * Returns an array of strings to display for a row of symbol information.
	 * @param pgm the program containing the symbol
	 * @param id the symbol ID.
	 * @param prefix prefix for the first column's info.
	 * @param suffix suffix for the first column's info.
	 * @return the strings of symbol information
	 */
	private String[] getSymbolInfo(Program pgm, long id, String prefix, String suffix) {
		Symbol s = (pgm != null) ? pgm.getSymbolTable().getSymbol(id) : null;
		return getSymbolInfo(pgm, s, prefix, suffix);
	}

	/**
	 * Returns an array of strings to display for a row of symbol information.
	 * @param pgm the program containing the symbol
	 * @param s the symbol
	 * @return the strings of symbol information
	 */
	private String[] getSymbolInfo(Program pgm, Symbol s) {
		return getSymbolInfo(pgm, s, "", "");
	}

	/**
	 * Returns an array of strings to display for a row of symbol information.
	 * @param pgm the program containing the symbol
	 * @param s the symbol
	 * @param prefix prefix for the first column's info.
	 * @param suffix suffix for the first column's info.
	 * @return the strings of symbol information
	 */
	private String[] getSymbolInfo(Program pgm, Symbol s, String prefix, String suffix) {
		if (pgm == null) { // Header info
			return new String[] { "Option", "Symbol", "Scope", "Address", "Type", "Primary",
				"Source" };
		}
		String[] info = new String[] { "", "", "", "", "", "", "" };
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
		if (s != null) {
			info[1] = s.getName(false);
			info[2] = s.getParentNamespace().getSymbol().getName();
			info[3] = s.getAddress().toString();
			info[4] = s.getSymbolType().toString();
			info[5] = "" + s.isPrimary();
			info[6] = s.getSource().toString();
		}
		return info;
	}

	/**
	 * Returns an array of strings to display for a row of symbol comment conflict information.
	 * @param pgm the program containing the symbol
	 * @param id the symbol ID.
	 * @param prefix prefix for the first column's info.
	 * @param suffix suffix for the first column's info.
	 * @return the strings of symbol comment information
	 */
//	private String[] getSymbolCommentInfo(Program pgm, long id, String prefix, String suffix) {
//		Symbol s = (pgm != null) ? pgm.getSymbolTable().getSymbol(id) : null;
//		return getSymbolCommentInfo(pgm, s, prefix, suffix);
//	}

	/**
	 * Returns an array of strings to display for a row of symbol comment conflict information.
	 * @param pgm the program containing the symbol
	 * @param s the symbol (pass null here for header row.)
	 * @param prefix prefix for the first column's info.
	 * @param suffix suffix for the first column's info.
	 * @return the strings of symbol comment information
	 */
//	private String[] getSymbolCommentInfo(Program pgm, Symbol s, String prefix, String suffix) {
//		if (s == null) { // Header info
//			return new String[] { "Option", "Symbol", "Scope", "Type", "Comment" };
//		}
//		String[] info = new String[] { "", "", "", "", "" };
//		String version = "";
//		if (pgm == originalPgm) {
//			version = ORIGINAL_TITLE;
//		}
//		else if (pgm == latestPgm) {
//			version = LATEST_TITLE;
//		}
//		else if (pgm == myPgm) {
//			version = MY_TITLE;
//		}
//		else if (pgm == resultPgm) {
//			version = RESULT_TITLE;
//		}
//		info[0] = prefix + version + suffix;
//		info[1] = s.getName(false);
//		info[2] = s.getParentNamespace().getSymbol().getName();
//		info[3] = s.getSymbolType().toString();
//		info[4] = ConflictUtility.getTruncatedHTMLString(s.getSymbolStringData(), TRUNCATE_LENGTH);
//		return info;
//	}

	/**
	 * Returns an array of strings to display for a row of symbol information
	 * for a conflict on which symbol to set as primary.
	 * @param pgm the program containing the symbol
	 * @param s the symbol
	 * @param prefix prefix for the first column's info.
	 * @param suffix suffix for the first column's info.
	 * @return the strings of symbol information
	 */
	private String[] getPrimarySymbolInfo(Program pgm, Symbol s, String prefix, String suffix) {
		if (pgm == null) { // Header info
			return new String[] { "Option", "Symbol", "Scope", "Address", "Type", "Source" };
		}
		String[] info = new String[] { "", "", "", "", "", "" };
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
		if (s != null) {
			info[1] = s.getName(false);
			info[2] = s.getParentNamespace().getSymbol().getName();
			Address symbolAddress = s.getAddress();
			if (s.isExternal()) {
				ExternalManager externalManager = pgm.getExternalManager();
				ExternalLocation externalLocation = externalManager.getExternalLocation(s);
				symbolAddress = externalLocation.getAddress();
			}
			info[3] = (symbolAddress != null) ? symbolAddress.toString() : "";
			info[4] = s.getSymbolType().toString();
			info[5] = s.getSource().toString();
		}
		return info;
	}

	/**
	 * A convenience class that is simply a hash set containing long values.
	 */
	private class LongHashSet extends HashSet<Long> {
		private final static long serialVersionUID = 1;

		public boolean add(long l) {
			return super.add(new Long(l));
		}

		public boolean contains(long l) {
			return super.contains(new Long(l));
		}

		public boolean remove(long l) {
			return super.remove(new Long(l));
		}
	}

}
