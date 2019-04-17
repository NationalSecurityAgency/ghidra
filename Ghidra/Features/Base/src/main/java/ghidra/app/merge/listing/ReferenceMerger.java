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
import ghidra.app.merge.util.MergeUtilities;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.datastruct.LongLongHashtable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NoValueException;
import ghidra.util.task.TaskMonitor;

/**
 * Class for merging reference changes. This class can determine
 * where there are conflicts between the latest checked in version and my
 * checked out version. It can then automatically merge non-conflicting changes
 * and manually merge the conflicting references.
 * <br>The ReferenceMerger takes into account anywhere that code units have been merged.
 * If code units were merged, then this will not try to merge at those addresses.
 * The code unit merger should have already merged the references where it 
 * merged code units.
 * <br>Important: This class is intended to be used only for a single program 
 * version merge. It should be constructed, followed by an autoMerge(), and lastly
 * each address with a conflict should have mergeConflicts() called on it.
 */
class ReferenceMerger extends AbstractListingMerger {

	final static String REFERENCES_PHASE = "References";
	private final static int TYPE_CONFLICT = 1;
	private final static int REMOVE_CONFLICT = 2;
	private final static int CHANGE_CONFLICT = 3;
	private final static int ADD_CONFLICT = 4;
	private final static int PRIMARY_CONFLICT = 5;

	VerticalChoicesPanel conflictPanel;
	// currentAddress is declared in AbstractListingMerger
	Reference currentReference;
	int currentOpIndex;
	AddressSet currentBackgroundSet;

	ReferenceManager latestRefMgr;
	ReferenceManager myRefMgr;
	ReferenceManager originalRefMgr;
	ReferenceManager resultRefMgr;

	ProgramDiff latestMyDiff;
	ProgramDiff originalLatestDiff;
	ProgramDiff originalMyDiff;

	AddressSetView latestDetailSet; // latest reference change set
	AddressSetView myDetailSet; // my reference change set

	Listing resultListing;
	Listing latestListing;
	Listing myListing;
	Listing originalListing;

	AddressSet conflictSet;
	HashMap<Address, ArrayList<Integer>> typeConflicts;
	HashMap<Address, ArrayList<Reference>> removeConflicts;
	HashMap<Address, ArrayList<Reference>> changeConflicts;
	HashMap<Address, ArrayList<Reference>> addConflicts;
	HashMap<Address, ArrayList<Integer>> primaryConflicts;

	// Members for accessing symbol resolution information.
	LongLongHashtable origResolvedSymbols; // Maps original symbolID to result symbolID
	LongLongHashtable latestResolvedSymbols; // Maps latest symbolID to result symbolID
	LongLongHashtable myResolvedSymbols; // Maps my symbolID to result symbolID

	AddressSetView pickedLatestCodeUnits;
	AddressSetView pickedMyCodeUnits;
	AddressSetView pickedOriginalCodeUnits;

	private int currentConflictType;
	private int referenceChoice = ASK_USER;
	private int referenceTypeChoice = ASK_USER;
	private int primaryReferenceChoice = ASK_USER;

	/**
	 * Constructs a reference merger.
	 * @param listingMergeMgr the listing merge manager that owns this merger.
	 */
	ReferenceMerger(ListingMergeManager listingMergeMgr) {
		super(listingMergeMgr);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.AbstractListingMerger#init()
	 */
	@Override
	public void init() {
		super.init();
		latestRefMgr = latestPgm.getReferenceManager();
		myRefMgr = myPgm.getReferenceManager();
		originalRefMgr = originalPgm.getReferenceManager();
		resultRefMgr = resultPgm.getReferenceManager();

		resultListing = resultPgm.getListing();
		latestListing = latestPgm.getListing();
		myListing = myPgm.getListing();
		originalListing = originalPgm.getListing();

		diffLatestMy = listingMergeMgr.diffLatestMy;
		diffOriginalLatest = listingMergeMgr.diffOriginalLatest;
		diffOriginalMy = listingMergeMgr.diffOriginalMy;

		origResolvedSymbols = new LongLongHashtable();
		latestResolvedSymbols = new LongLongHashtable();
		myResolvedSymbols = new LongLongHashtable();

		pickedLatestCodeUnits = new AddressSet();
		pickedMyCodeUnits = new AddressSet();
		pickedOriginalCodeUnits = new AddressSet();

		latestDetailSet = new AddressSet();
		myDetailSet = new AddressSet();
		conflictSet = new AddressSet();
		typeConflicts = new HashMap<>();
		removeConflicts = new HashMap<>();
		changeConflicts = new HashMap<>();
		addConflicts = new HashMap<>();
		primaryConflicts = new HashMap<>();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#getConflictType()
	 */
	@Override
	public String getConflictType() {
		return "Reference";
	}

	@Override
	public boolean apply() {
		conflictOption = conflictPanel.getSelectedOptions();

		// If the "Use For All" check box is selected 
		// then save the option chosen for this conflict type.
		if (conflictPanel.getUseForAll()) {
			setChoiceForConflictType(currentConflictType, conflictOption);
		}

		return super.apply();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#autoMerge(ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void autoMerge(int progressMin, int progressMax, TaskMonitor monitor)
			throws ProgramConflictException, MemoryAccessException, CancelledException {

		initializeAutoMerge("Auto-merging References and determining conflicts.", progressMin,
			progressMax, monitor);
		totalChanges = 7;

		if (mergeManager != null) {
			latestResolvedSymbols =
				(LongLongHashtable) mergeManager.getResolveInformation(MergeConstants.RESOLVED_LATEST_SYMBOLS);
			myResolvedSymbols =
				(LongLongHashtable) mergeManager.getResolveInformation(MergeConstants.RESOLVED_MY_SYMBOLS);
			origResolvedSymbols =
				(LongLongHashtable) mergeManager.getResolveInformation(MergeConstants.RESOLVED_ORIGINAL_SYMBOLS);

			pickedLatestCodeUnits =
				(AddressSetView) mergeManager.getResolveInformation(MergeConstants.PICKED_LATEST_CODE_UNITS);
			pickedMyCodeUnits =
				(AddressSetView) mergeManager.getResolveInformation(MergeConstants.PICKED_MY_CODE_UNITS);
			pickedOriginalCodeUnits =
				(AddressSetView) mergeManager.getResolveInformation(MergeConstants.PICKED_ORIGINAL_CODE_UNITS);
		}
		updateProgressMessage("Setting references where code units were merged...");
		autoMergeWhereCodeUnitsMerged(monitor);
		incrementProgress(1);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS);
		latestDetailSet = listingMergeMgr.diffOriginalLatest.getDifferences(filter, monitor);
		myDetailSet = listingMergeMgr.diffOriginalMy.getDifferences(filter, monitor);
		AddressSet tmpAutoSet = new AddressSet();
		AddressSet possibleConflicts = new AddressSet();
		MergeUtilities.adjustSets(latestDetailSet, myDetailSet, tmpAutoSet, possibleConflicts);

		// Ignore the code units that were automatically and manually merged
		// by CodeUnitMerger. References are already merged there.
		AddressSet mergedCodeUnits = listingMergeMgr.getMergedCodeUnits();
		tmpAutoSet.delete(mergedCodeUnits);
		possibleConflicts.delete(mergedCodeUnits);

		updateProgressMessage("Auto-merging references...");
		replaceReferences(tmpAutoSet, KEEP_MY, monitor);
		incrementProgress(1);

		updateProgressMessage("Finding reference conflicts...");
		determineChanges(possibleConflicts, monitor);
		incrementProgress(1);
	}

	private void clearFallThroughOverride(Program program, Address address) {
		Instruction instruction = program.getListing().getInstructionAt(address);
		if (instruction != null) {
			instruction.clearFallThroughOverride();
		}
	}

	/**
	 * Merges the references from the same program that had its code units chosen
	 * in the Code Unit merge phase.
	 * @param monitor the task monitor for allowing cancel and showing progress.
	 * @throws CancelledException if the user cancels the merge.
	 */
	private void autoMergeWhereCodeUnitsMerged(TaskMonitor monitor) throws CancelledException {
		replaceReferences(pickedLatestCodeUnits, KEEP_LATEST, monitor);
		replaceReferences(pickedMyCodeUnits, KEEP_MY, monitor);
		replaceReferences(pickedOriginalCodeUnits, KEEP_ORIGINAL, monitor);
	}

	private void determineChanges(AddressSet possibleConflicts, TaskMonitor monitor) {
		monitor.setMessage("Determining reference changes.");
		CodeUnitIterator iter = resultPgm.getListing().getCodeUnits(possibleConflicts, true);
		while (iter.hasNext()) {
			CodeUnit resultCU = iter.next();
			int numOps = resultCU.getNumOperands();
			Address address = resultCU.getMinAddress();
			// Check each operand for ref conflicts.
			for (int opIndex = -1; opIndex < numOps; opIndex++) {
				processOperandRefs(address, opIndex);
			}
		}
	}

	private void processOperandRefs(Address address, int opIndex) {
		Reference[] latestRefs = latestRefMgr.getReferencesFrom(address, opIndex);
		Reference[] myRefs = myRefMgr.getReferencesFrom(address, opIndex);
		Reference[] originalRefs = originalRefMgr.getReferencesFrom(address, opIndex);
		// Only need the non-fallthrough references so call getDiffRefs().
		latestRefs = ProgramDiff.getDiffRefs(latestRefs);
		myRefs = ProgramDiff.getDiffRefs(myRefs);
		originalRefs = ProgramDiff.getDiffRefs(originalRefs);
		Arrays.sort(latestRefs);
		Arrays.sort(myRefs);
		Arrays.sort(originalRefs);
		if (equalRefArrays(listingMergeMgr.diffLatestMy, latestRefs, myRefs)) {
			return; // LATEST and MY refs match.
		}
		if (equalRefArrays(listingMergeMgr.diffOriginalMy, originalRefs, myRefs)) {
			return; // No changes to MY from original
		}
		if (equalRefArrays(listingMergeMgr.diffOriginalLatest, originalRefs, latestRefs)) {
			listingMergeMgr.mergeMy.replaceReferences(address, opIndex);
			return; // No changes to LATEST from original so automerge MY.
		}
		// Otherwise, something changed in LATEST and in MY.
		if (!compatibleRefs(myRefs, latestRefs)) {
			saveTypeConflict(address, opIndex);
			return;
		}
		// Otherwise the type of references are similar.
		Reference someRef = getSomeRef(myRefs, latestRefs);
		if (someRef.isMemoryReference()) {
			processMemoryRefs(address, opIndex, latestRefs, myRefs, originalRefs);
		}
		else {
			processSingleRefs(address, opIndex, latestRefs, myRefs, originalRefs);
		}
	}

	private boolean equalRefArrays(ProgramDiff programDiff, Reference[] refs1, Reference[] refs2) {
		if (refs1 == refs2)
			return true;
		if (refs1 == null || refs2 == null)
			return false;

		int length = refs1.length;
		if (refs2.length != length)
			return false;

		for (int i = 0; i < length; i++) {
			Reference ref1 = refs1[i];
			Reference ref2 = refs2[i];
			// If the references are external refs, see if they map to the same thing.
			if (ref1.isExternalReference() && ref2.isExternalReference()) {
				if (!ref1.getReferenceType().equals(ref2.getReferenceType())) {
					return false;
				}
				Program programOne = programDiff.getProgramOne();
				Program programTwo = programDiff.getProgramTwo();
				Address toAddress1 = ref1.getToAddress();
				Address toAddress2 = ref2.getToAddress();
				Symbol symbol1 = programOne.getSymbolTable().getPrimarySymbol(toAddress1);
				Symbol symbol2 = programTwo.getSymbolTable().getPrimarySymbol(toAddress2);
				long id1 = (symbol1 != null) ? symbol1.getID() : -1;
				long id2 = (symbol2 != null) ? symbol2.getID() : -1;
				try {
					long resultID1 = getResultID(programOne, id1);
					long resultID2 = getResultID(programTwo, id2);
					if (resultID1 == resultID2) {
						// Both references resolved to the same external.
						Msg.trace(this, "!!! Both references resolved to the same external. !!!");
						// Note: The reference source could still be different, but we will just keep what is in Result.
						continue;
					}
					return false;
				}
				catch (NoValueException e) {
					return false;
				}
			}

			// Otherwise they didn't map to the same so compare them.
			if (!programDiff.equalRefs(ref1, ref2)) {
				return false;
			}
		}

		return true;
	}

	private long getResultID(Program program, long id1) throws NoValueException {
		if (latestPgm == program) {
			return getExternalResultIDFromLatestID(id1);
		}
		if (myPgm == program) {
			return getExternalResultIDFromMyID(id1);
		}
		if (originalPgm == program) {
			return getExternalResultIDFromOriginalID(id1);
		}
		return id1;
	}

	private void processMemoryRefs(Address address, int opIndex, Reference[] latestRefs,
			Reference[] myRefs, Reference[] originalRefs) {
		processOriginalRefs(originalRefs);
		processMyRefsAdded(myRefs);
		getPrimaryConflicts(address, opIndex);
	}

	private void processOriginalRefs(Reference[] originalRefs) {
		for (int origIndex = 0; origIndex < originalRefs.length; origIndex++) {
			Reference originalRef = originalRefs[origIndex];
			Reference myRef = DiffUtility.getReference(originalPgm, originalRef, myPgm);
			Reference latestRef = DiffUtility.getReference(originalPgm, originalRef, latestPgm);
			if (myRef == null) {
				if (!diffOriginalLatest.equalRefs(originalRef, latestRef)) {
					saveRemoveConflict(originalRef);
				}
				else {
					// AutoMerge: Remove ref as in MY.
					Reference resultRef =
						DiffUtility.getReference(originalPgm, originalRef, resultPgm);
					if (resultRef != null) {
						resultRefMgr.delete(resultRef);
					}
				}
			}
			else if (latestRef == null) {
				if (!diffOriginalMy.equalRefs(originalRef, myRef)) {
					saveRemoveConflict(originalRef);
				} // Otherwise should already be gone.
			}
			else {
				if (diffLatestMy.equalRefs(latestRef, myRef)) {
					continue;
				}
				boolean changedLatest = !diffOriginalLatest.equalRefs(originalRef, latestRef);
				boolean changedMy = !diffOriginalMy.equalRefs(originalRef, myRef);
				if (changedMy) {
					if (changedLatest) {
						saveChangeConflict(myRef);
					}
					else {
						// AutoMerge: Change to MY ref
						DiffUtility.createReference(myPgm, myRef, resultPgm);
					}
				}
			}
		}
	}

	private void processMyRefsAdded(Reference[] myRefs) {
		// Check Adds which could result in an AddConflict or a type conflict.
		for (int myIndex = 0; myIndex < myRefs.length; myIndex++) {
			Reference myRef = myRefs[myIndex];
			Reference originalRef = DiffUtility.getReference(myPgm, myRef, originalPgm);
			if (originalRef == null) {
				Reference latestRef = DiffUtility.getReference(myPgm, myRef, latestPgm);
				if (latestRef == null) {
					// AutoMerge: Add MY ref
					DiffUtility.createReference(myPgm, myRef, resultPgm);
				}
				else {
					if (diffLatestMy.equalRefs(latestRef, myRef)) {
						continue;
					}
					saveAddConflict(myRef);
				}
			}
		}
	}

	/**
	 * 
	 * @param program
	 * @param fromAddress
	 * @param operandIndex
	 * @return
	 */
	private Reference getFallThroughReference(Program program, Address fromAddress, int operandIndex) {
		Reference[] otherRefs =
			program.getReferenceManager().getReferencesFrom(fromAddress, operandIndex);
		for (Reference reference : otherRefs) {
			if (reference.getReferenceType().isFallthrough()) {
				return reference;
			}
		}
		return null;
	}

	private void getPrimaryConflicts(Address address, int opIndex) {
		Reference latestPrimary = latestRefMgr.getPrimaryReferenceFrom(address, opIndex);
		Reference myPrimary = myRefMgr.getPrimaryReferenceFrom(address, opIndex);
		if (latestPrimary != null && myPrimary != null && latestPrimary.compareTo(myPrimary) != 0) {
			// If both refs changed from original then conflict.
			Reference origForLatest =
				DiffUtility.getReference(latestPgm, latestPrimary, originalPgm);
			if (origForLatest != null && diffOriginalLatest.equalRefs(origForLatest, latestPrimary)) {
				return;
			}
			Reference origForMy = DiffUtility.getReference(myPgm, myPrimary, originalPgm);
			if (origForMy != null && diffOriginalMy.equalRefs(origForMy, myPrimary)) {
				return;
			}
			savePrimaryConflict(address, opIndex);
		}
	}

	private void processSingleRefs(Address address, int opIndex, Reference[] latestRefs,
			Reference[] myRefs, Reference[] originalRefs) {
		boolean hasRefTypeConflict = hasRefTypeConflict(latestRefs, myRefs, originalRefs);
		if (originalRefs.length > 0) {
			if ((myRefs.length == 0) || (latestRefs.length == 0)) {
				if (hasRefTypeConflict) {
					saveRemoveConflict(originalRefs[0]);
				}
				else {
					// Auto merge the type it changed to.
					if (myRefs.length != 0) {
						listingMergeMgr.mergeMy.replaceReferences(address, opIndex);
					}
				}
			}
			else if (!diffOriginalMy.equalRefs(originalRefs[0], myRefs[0])) {
				saveChangeConflict(myRefs[0]);
			}
		}
		else {
			if (!diffLatestMy.equalRefs(latestRefs[0], myRefs[0])) {
				saveAddConflict(myRefs[0]);
			}
		}
	}

	private boolean hasRefTypeConflict(Reference[] latestRefs, Reference[] myRefs,
			Reference[] originalRefs) {
		if (originalRefs.length > 0) {
			return (compatibleRefs(originalRefs[0], latestRefs) && compatibleRefs(originalRefs[0],
				myRefs));
		}
		else if (latestRefs.length > 0) {
			return (compatibleRefs(latestRefs[0], myRefs));
		}
		return true;
	}

	private void addToRefsHash(Address address, Reference ref,
			HashMap<Address, ArrayList<Reference>> refsHash) {
		ArrayList<Reference> refsList = refsHash.get(address);
		if (refsList == null) {
			refsList = new ArrayList<>();
			refsHash.put(address, refsList);
		}
		if (!refsList.contains(ref)) {
			refsList.add(ref);
		}
	}

	private boolean compatibleRefs(Reference[] myRefs, Reference[] latestRefs) {
		if (myRefs.length == 0 || latestRefs.length == 0) {
			return true;
		}
		return compatibleRefs(myRefs[0], latestRefs);
	}

	private Reference getSomeRef(Reference[] myRefs, Reference[] latestRefs) {
		if (myRefs.length > 0) {
			return myRefs[0];
		}
		else if (latestRefs.length > 0) {
			return latestRefs[0];
		}
		return null;
	}

	private boolean compatibleRefs(Reference ref1, Reference[] refs) {
		Address toAddr = ref1.getToAddress();
		if (toAddr.isMemoryAddress()) {
			for (int i = 0; i < refs.length; i++) {
				if (!refs[i].getToAddress().isMemoryAddress()) {
					return false;
				}
			}
			return true;
		}
		else if (toAddr.isExternalAddress()) {
			for (int i = 0; i < refs.length; i++) {
				if (!refs[i].getToAddress().isExternalAddress()) {
					return false;
				}
			}
			return true;
		}
		if (toAddr.isRegisterAddress()) {
			for (int i = 0; i < refs.length; i++) {
				if (!refs[i].getToAddress().isRegisterAddress()) {
					return false;
				}
			}
			return true;
		}
		if (toAddr.isStackAddress()) {
			for (int i = 0; i < refs.length; i++) {
				if (!refs[i].getToAddress().isStackAddress()) {
					return false;
				}
			}
			return true;
		}
		return false;
	}

	private void saveTypeConflict(Address address, int opIndex) {
		ArrayList<Integer> opIndexes = typeConflicts.get(address);
		if (opIndexes == null) {
			opIndexes = new ArrayList<>();
			typeConflicts.put(address, opIndexes);
		}
		opIndexes.add(new Integer(opIndex));
		conflictSet.addRange(address, address);
	}

	private void saveAddConflict(Reference myRef) {
		Address address = myRef.getFromAddress();
		addToRefsHash(address, myRef, addConflicts);
		conflictSet.addRange(address, address);
	}

	private void saveChangeConflict(Reference myRef) {
		Address address = myRef.getFromAddress();
		addToRefsHash(address, myRef, changeConflicts);
		conflictSet.addRange(address, address);
	}

	private void saveRemoveConflict(Reference originalRef) {
		Address address = originalRef.getFromAddress();
		addToRefsHash(address, originalRef, removeConflicts);
		conflictSet.addRange(address, address);
	}

	private void savePrimaryConflict(Address address, int opIndex) {
		ArrayList<Integer> opIndexes = primaryConflicts.get(address);
		if (opIndexes == null) {
			opIndexes = new ArrayList<>();
			primaryConflicts.put(address, opIndexes);
		}
		opIndexes.add(new Integer(opIndex));
		conflictSet.addRange(address, address);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#hasConflict(ghidra.program.model.address.Address)
	 */
	@Override
	public boolean hasConflict(Address addr) {
		return conflictSet.contains(addr);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#getConflictCount(ghidra.program.model.address.Address)
	 */
	@Override
	public int getConflictCount(Address addr) {
		return getTypeConflictCount(addr) + getRemoveConflictCount(addr) +
			getChangeConflictCount(addr) + getAddConflictCount(addr) +
			getPrimaryConflictCount(addr);
	}

	private int getTypeConflictCount(Address addr) {
		ArrayList<Integer> opIndexList;
		opIndexList = typeConflicts.get(addr);
		return ((opIndexList != null) ? opIndexList.size() : 0);
	}

	private int getRemoveConflictCount(Address addr) {
		ArrayList<Reference> refsList = removeConflicts.get(addr);
		if (refsList == null) {
			return 0;
		}
		return refsList.size();
	}

	private int getChangeConflictCount(Address addr) {
		ArrayList<Reference> refsList = changeConflicts.get(addr);
		if (refsList == null) {
			return 0;
		}
		return refsList.size();
	}

	private int getAddConflictCount(Address addr) {
		ArrayList<Reference> refsList = addConflicts.get(addr);
		if (refsList == null) {
			return 0;
		}
		return refsList.size();
	}

	private int getPrimaryConflictCount(Address addr) {
		ArrayList<Integer> opIndexList;
		opIndexList = primaryConflicts.get(addr);
		return ((opIndexList != null) ? opIndexList.size() : 0);
	}

	/**
	 * Replace the references where possible. 
	 * @param addressSet the address set where references should be replaced
	 * @param chosenConflictOption indicator of where to get references from (KEEP_ORIGINAL, KEEP_LATEST, KEEP_MY).
	 * @param monitor task monitor
	 * @throws CancelledException if user cancels.
	 */
	private void replaceReferences(final AddressSetView addressSet, final int chosenConflictOption,
			final TaskMonitor monitor) throws CancelledException {
		if ((chosenConflictOption & KEEP_ORIGINAL) != 0) {
			listingMergeMgr.mergeOriginal.replaceReferences(addressSet, monitor);
		}
		else if ((chosenConflictOption & KEEP_LATEST) != 0) {
			listingMergeMgr.mergeLatest.replaceReferences(addressSet, monitor);
		}
		else if ((chosenConflictOption & KEEP_MY) != 0) {
			listingMergeMgr.mergeMy.replaceReferences(addressSet, monitor);
		}
	}

	/**
	 * Replace the fallthroughs where possible. 
	 * @param addressSet the address set where fallthroughs should be replaced
	 * @param chosenConflictOption indicator of where to get references from (KEEP_ORIGINAL, KEEP_LATEST, KEEP_MY).
	 * @param monitor task monitor
	 * @throws CancelledException if user cancels.
	 */
	private void replaceFallThroughs(final AddressSetView addressSet,
			final int chosenConflictOption, final TaskMonitor monitor) throws CancelledException {
		if ((chosenConflictOption & KEEP_ORIGINAL) != 0) {
			listingMergeMgr.mergeOriginal.replaceFallThroughs(addressSet, monitor);
		}
		else if ((chosenConflictOption & KEEP_LATEST) != 0) {
			listingMergeMgr.mergeLatest.replaceFallThroughs(addressSet, monitor);
		}
		else if ((chosenConflictOption & KEEP_MY) != 0) {
			listingMergeMgr.mergeMy.replaceFallThroughs(addressSet, monitor);
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#mergeConflicts(ghidra.app.merge.tool.ListingMergePanel, 
	 * ghidra.program.model.address.Address, int, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void mergeConflicts(ListingMergePanel listingPanel, Address addr,
			int chosenConflictOption, TaskMonitor monitor) throws CancelledException,
			MemoryAccessException {
		if (!hasConflict(addr)) {
			return;
		}
		monitor.setMessage("Merging conflicting References.");
		// Manually merge each operand as necessary.
		CodeUnit resultCU = resultPgm.getListing().getCodeUnitAt(addr);
		int numOps = resultCU.getNumOperands();
		// Check each operand for ref conflicts.
		for (int opIndex = -1; opIndex < numOps; opIndex++) {
			mergeConflicts(listingPanel, addr, opIndex, chosenConflictOption, monitor);
		}
	}

	private void mergeConflicts(ListingMergePanel listingPanel, Address addr, int opIndex,
			int chosenConflictOption, TaskMonitor monitor) throws CancelledException {
		boolean askUser = chosenConflictOption == ASK_USER;
		handleTypeConflict(listingPanel, addr, opIndex, chosenConflictOption, askUser, monitor);
		handleRemoveConflict(listingPanel, addr, opIndex, chosenConflictOption, askUser, monitor);
		handleChangeConflict(listingPanel, addr, opIndex, chosenConflictOption, askUser, monitor);
		handleAddConflict(listingPanel, addr, opIndex, chosenConflictOption, askUser, monitor);
		handlePrimaryConflict(listingPanel, addr, opIndex, chosenConflictOption, askUser, monitor);
	}

	private void handleTypeConflict(ListingMergePanel listingPanel, Address addr, int opIndex,
			int chosenConflictOption, boolean askUser, TaskMonitor monitor)
			throws CancelledException {
		ArrayList<Integer> opIndexList = typeConflicts.get(addr);
		if (opIndexList == null || opIndexList.size() == 0) {
			return;
		}
		if (opIndexList.contains(new Integer(opIndex))) {
			currentReference = null;
			currentAddress = addr;
			currentOpIndex = opIndex;
			currentBackgroundSet = new AddressSet(addr, addr);
			currentConflictType = TYPE_CONFLICT;
			// If we have a reference type choice then a "Use For All" has already occurred.
			if (referenceTypeChoice != ASK_USER) {
				resolveTypeConflict(addr, opIndex, referenceTypeChoice);
			}
			else {
				if (askUser && mergeManager != null) {
					showConflictPanel(listingPanel, TYPE_CONFLICT);
					monitor.checkCanceled();
				}
				else {
					resolveTypeConflict(addr, opIndex, chosenConflictOption);
				}
			}
		}
	}

	private void handleRemoveConflict(ListingMergePanel listingPanel, Address addr, int opIndex,
			int chosenConflictOption, boolean askUser, TaskMonitor monitor)
			throws CancelledException {
		ArrayList<Reference> removeList = removeConflicts.get(addr);
		if (removeList == null || removeList.size() == 0) {
			return;
		}
		currentAddress = addr;
		currentOpIndex = opIndex;
		currentBackgroundSet = new AddressSet(addr, addr);
		currentConflictType = REMOVE_CONFLICT;
		for (Iterator<Reference> iter = removeList.iterator(); iter.hasNext();) {
			Reference removeRef = iter.next();
			currentReference = removeRef;
			if (currentReference.getOperandIndex() == opIndex) {
				// If we have a reference choice then a "Use For All" has already occurred.
				if (referenceChoice != ASK_USER) {
					resolveRemoveVsChange(currentReference, referenceChoice);
				}
				else {
					if (askUser && mergeManager != null) {
						showConflictPanel(listingPanel, REMOVE_CONFLICT);
						monitor.checkCanceled();
					}
					else {
						resolveRemoveVsChange(currentReference, chosenConflictOption);
					}
				}
			}
		}
	}

	private void handleChangeConflict(ListingMergePanel listingPanel, Address addr, int opIndex,
			int chosenConflictOption, boolean askUser, TaskMonitor monitor)
			throws CancelledException {
		ArrayList<Reference> changeList = changeConflicts.get(addr);
		if (changeList == null || changeList.size() == 0) {
			return;
		}
		currentAddress = addr;
		currentOpIndex = opIndex;
		currentBackgroundSet = new AddressSet(addr, addr);
		currentConflictType = CHANGE_CONFLICT;
		for (Iterator<Reference> iter = changeList.iterator(); iter.hasNext();) {
			Reference changeRef = iter.next();
			currentReference = changeRef;
			if (currentReference.getOperandIndex() == opIndex) {
				// If we have a reference choice then a "Use For All" has already occurred.
				if (referenceChoice != ASK_USER) {
					resolveChangeConflict(currentReference, referenceChoice);
				}
				else {
					if (askUser && mergeManager != null) {
						showConflictPanel(listingPanel, CHANGE_CONFLICT);
						monitor.checkCanceled();
					}
					else {
						resolveChangeConflict(currentReference, chosenConflictOption);
					}
				}
			}
		}
	}

	private void handleAddConflict(ListingMergePanel listingPanel, Address addr, int opIndex,
			int chosenConflictOption, boolean askUser, TaskMonitor monitor)
			throws CancelledException {
		ArrayList<Reference> addList = addConflicts.get(addr);
		if (addList == null || addList.size() == 0) {
			return;
		}
		currentAddress = addr;
		currentOpIndex = opIndex;
		currentBackgroundSet = new AddressSet(addr, addr);
		currentConflictType = ADD_CONFLICT;
		for (Iterator<Reference> iter = addList.iterator(); iter.hasNext();) {
			Reference changeRef = iter.next();
			currentReference = changeRef;
			if (currentReference.getReferenceType().isFallthrough()) {
				continue; // Ignore fallthrough references.
			}
			if (currentReference.getOperandIndex() == opIndex) {
				// If we have a reference choice then a "Use For All" has already occurred.
				if (referenceChoice != ASK_USER) {
					resolveAddConflict(currentReference, referenceChoice);
				}
				else {
					if (askUser && mergeManager != null) {
						showConflictPanel(listingPanel, ADD_CONFLICT);
						monitor.checkCanceled();
					}
					else {
						resolveAddConflict(currentReference, chosenConflictOption);
					}
				}
			}
		}
	}

	private void handlePrimaryConflict(ListingMergePanel listingPanel, Address addr, int opIndex,
			int chosenConflictOption, boolean askUser, TaskMonitor monitor)
			throws CancelledException {
		ArrayList<Integer> opIndexList = primaryConflicts.get(addr);
		if (opIndexList == null || opIndexList.size() == 0) {
			return;
		}
		if (opIndexList.contains(new Integer(opIndex))) {
			// Check that the conflict still exists. It may have gotten resolved via another conflict.
			if (!hasPrimaryConflict(addr, opIndex)) {
				return;
			}
			currentReference = null;
			currentAddress = addr;
			currentOpIndex = opIndex;
			currentBackgroundSet = new AddressSet(addr, addr);
			currentConflictType = PRIMARY_CONFLICT;
			// If we have a primary reference choice then a "Use For All" has already occurred.
			if (primaryReferenceChoice != ASK_USER) {
				resolvePrimaryConflict(addr, opIndex, primaryReferenceChoice);
			}
			else {
				if (askUser && mergeManager != null) {
					showConflictPanel(listingPanel, PRIMARY_CONFLICT);
					monitor.checkCanceled();
				}
				else {
					resolvePrimaryConflict(addr, opIndex, chosenConflictOption);
				}
			}
		}
	}

	private boolean hasPrimaryConflict(Address addr, int opIndex) {
		Reference latestPrimary = latestRefMgr.getPrimaryReferenceFrom(addr, opIndex);
		Reference myPrimary = myRefMgr.getPrimaryReferenceFrom(addr, opIndex);
		if (latestPrimary != null && myPrimary != null) {
			// If both refs exist in result then conflict.
			Reference resultForLatest =
				DiffUtility.getReference(latestPgm, latestPrimary, resultPgm);
			if (resultForLatest != null) {
				Reference resultForMy = DiffUtility.getReference(myPgm, myPrimary, resultPgm);
				if (resultForMy != null && resultForLatest != resultForMy) {
					return true;
				}
			}
		}
		return false;
	}

	@SuppressWarnings("unused")
	private boolean hasLatestFallThrough(Address fromAddress, int operandIndex) {
		Reference resultFallThrough = getFallThroughReference(resultPgm, fromAddress, operandIndex);
		Reference latestFallThrough = getFallThroughReference(resultPgm, fromAddress, operandIndex);
		if (latestFallThrough != null && resultFallThrough != null) {
			return latestFallThrough.equals(resultFallThrough);
		}
		return false;
	}

	private void showConflictPanel(final ListingMergePanel listingPanel, final int conflictType) {
		try {
			final ChangeListener changeListener = new ChangeListener() {
				@Override
				public void stateChanged(ChangeEvent e) {
					int chosenConflictOption =
						ReferenceMerger.this.conflictPanel.getSelectedOptions();
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
						Msg.error(this, "Unexpected Exception: " + e1.getMessage(), e1);
					}
				}
			};
			SwingUtilities.invokeAndWait(new Runnable() {
				@Override
				public void run() {
					try {
						getConflictPanel(conflictType, changeListener);

						int choice = getChoiceForConflictType(conflictType);
						boolean useForAll = (choice != ASK_USER);
						conflictPanel.setUseForAll(useForAll);
						conflictPanel.setConflictType(getConflictTypeText(conflictType));

						listingPanel.setBottomComponent(conflictPanel);
					}
					catch (Exception e) {
						Msg.showError(this, listingPanel, "Error Merging References",
							"Error Getting Conflict Panel", e);
					}
				}
			});
			SwingUtilities.invokeLater(() -> {
				listingPanel.clearAllBackgrounds();
				if (ReferenceMerger.this.currentBackgroundSet != null) {
					listingPanel.paintAllBackgrounds(ReferenceMerger.this.currentBackgroundSet);
				}
			});
		}
		catch (InterruptedException e) {
			e.printStackTrace();
		}
		catch (InvocationTargetException e) {
			e.printStackTrace();
		}
		if (mergeManager != null && conflictPanel.hasChoice()) {
			mergeManager.setApplyEnabled(false);
			mergeManager.showListingMergePanel(currentAddress);
			// block until the user either cancels or hits the "Apply" button
			// on the merge dialog...
			// when the "Apply" button is hit, get the user's selection
			// and continue.
		}
	}

	protected String getConflictTypeText(int conflictType) {
		switch (conflictType) {
			case TYPE_CONFLICT:
				return "Reference Type";
			case REMOVE_CONFLICT:
			case CHANGE_CONFLICT:
			case ADD_CONFLICT:
				return "Reference Add/Change/Remove";
			case PRIMARY_CONFLICT:
				return "Primary Reference";
			default:
				return null;
		}
	}

	protected VerticalChoicesPanel getConflictPanel(int conflictType, ChangeListener listener) {
		switch (conflictType) {
			case TYPE_CONFLICT:
				return getTypeConflictPanel(currentAddress, currentOpIndex, listener);
			case REMOVE_CONFLICT:
				return getRemoveConflictPanel(currentReference, listener);
			case CHANGE_CONFLICT:
				return getChangeConflictPanel(currentReference, listener);
			case ADD_CONFLICT:
				return getAddConflictPanel(currentReference, listener);
			case PRIMARY_CONFLICT:
				return getPrimaryConflictPanel(currentAddress, currentOpIndex, listener);
			default:
				return null;
		}
	}

	private void mergeConflict(int conflictType, int chosenConflictOption) {

		switch (conflictType) {
			case TYPE_CONFLICT:
				resolveTypeConflict(ReferenceMerger.this.currentAddress,
					ReferenceMerger.this.currentOpIndex, chosenConflictOption);
				break;
			case REMOVE_CONFLICT:
				resolveRemoveVsChange(ReferenceMerger.this.currentReference, chosenConflictOption);
				break;
			case CHANGE_CONFLICT:
				resolveChangeConflict(currentReference, chosenConflictOption);
				break;
			case ADD_CONFLICT:
				resolveAddConflict(currentReference, chosenConflictOption);
				break;
			case PRIMARY_CONFLICT:
				resolvePrimaryConflict(ReferenceMerger.this.currentAddress,
					ReferenceMerger.this.currentOpIndex, chosenConflictOption);
				break;
		}
	}

	private VerticalChoicesPanel getVerticalConflictPanel() {
		if (conflictPanel == null) {
			conflictPanel = new VerticalChoicesPanel();
			currentConflictPanel = conflictPanel;
			conflictPanel.setTitle("Reference");
		}
		else {
			conflictPanel.clear();
		}
		return conflictPanel;
	}

	protected VerticalChoicesPanel getTypeConflictPanel(Address fromAddress, int opIndex,
			ChangeListener listener) {
		VerticalChoicesPanel panel = getVerticalConflictPanel();
		Reference[] originalRefs = originalRefMgr.getReferencesFrom(fromAddress, opIndex);
		Reference[] latestRefs = latestRefMgr.getReferencesFrom(fromAddress, opIndex);
		Reference[] myRefs = myRefMgr.getReferencesFrom(fromAddress, opIndex);
		panel.setTitle("Reference");
		String fromAddrStr = ConflictUtility.getAddressString(fromAddress);
		String text =
			" Conflicting reference types, " + getRefGroup(latestRefs[0]) + " & " +
				getRefGroup(myRefs[0]) + ", at '" + fromAddrStr + "' " +
				getOperandIndexString(opIndex) + ".";
		panel.setHeader(text);
		panel.setRowHeader(getReferenceInfo(null, null, null, null));
		String suffix = "' version";
		panel.addRadioButtonRow(
			getReferenceInfo(latestPgm, ((latestRefs.length == 1) ? latestRefs[0] : null),
				((latestRefs.length == 1) ? "Use '" : "Use all in '"), suffix), LATEST_BUTTON_NAME,
			KEEP_LATEST, listener);
		if (latestRefs.length > 1) {
			for (int i = 0; i < latestRefs.length; i++) {
				panel.addInfoRow(getReferenceInfo(latestPgm, latestRefs[i], "'", suffix));
			}
		}
		panel.addRadioButtonRow(
			getReferenceInfo(myPgm, ((myRefs.length == 1) ? myRefs[0] : null),
				((myRefs.length == 1) ? "Use '" : "Use all in '"), suffix),
			CHECKED_OUT_BUTTON_NAME, KEEP_MY, listener);
		if (myRefs.length > 1) {
			for (int i = 0; i < myRefs.length; i++) {
				panel.addInfoRow(getReferenceInfo(myPgm, myRefs[i], "'", suffix));
			}
		}
		panel.addInfoRow(getReferenceInfo(originalPgm, ((originalRefs.length > 0) ? originalRefs[0]
				: null), "'", suffix));
		for (int i = 1; i < originalRefs.length; i++) {
			panel.addInfoRow(getReferenceInfo(originalPgm, originalRefs[i], "'", suffix));
		}

		return panel;
	}

	protected VerticalChoicesPanel getRemoveConflictPanel(Reference ref, ChangeListener listener) {
		VerticalChoicesPanel panel = getVerticalConflictPanel();
		Reference originalRef = ref;
		Reference latestRef = DiffUtility.getReference(originalPgm, originalRef, latestPgm);
		Reference myRef = DiffUtility.getReference(originalPgm, originalRef, myPgm);
		if (originalRef.getReferenceType().isFallthrough()) {
			Address fromAddr = originalRef.getFromAddress();
			int opIndex = originalRef.getOperandIndex();
			Reference latestFallthrough = getFallThroughReference(latestPgm, fromAddr, opIndex);
			Reference myFallthrough = getFallThroughReference(myPgm, fromAddr, opIndex);
			latestRef = latestFallthrough;
			myRef = myFallthrough;
		}
		panel.setTitle("Reference");
		String fromAddrStr = ConflictUtility.getAddressString(ref.getFromAddress());
		String toAddrStr =
			ConflictUtility.colorString(ConflictUtility.ADDRESS_COLOR,
				DiffUtility.getUserToAddressString(resultPgm, ref.getToAddress()));
		String text =
			getRefGroup(ref) + " Reference from '" + fromAddrStr + "' " +
				getOperandIndexString(ref) + " to '" + toAddrStr +
				"' was removed in one version and changed in other.";
		panel.setHeader(text);
		panel.setRowHeader(getReferenceInfo(null, null, null, null));
		String latestPrefix = (latestRef == null) ? "Remove as in '" : "Change as in '";
		String myPrefix = (myRef == null) ? "Remove as in '" : "Change as in '";
		String suffix = "' version";
		String[] latestRefInfo = getReferenceInfo(latestPgm, latestRef, latestPrefix, suffix);
		String[] myRefInfo = getReferenceInfo(myPgm, myRef, myPrefix, suffix);
		panel.addRadioButtonRow(latestRefInfo, LATEST_BUTTON_NAME, KEEP_LATEST, listener);
		panel.addRadioButtonRow(myRefInfo, CHECKED_OUT_BUTTON_NAME, KEEP_MY, listener);
		panel.addInfoRow(getReferenceInfo(originalPgm, originalRef, "'", suffix));

		return panel;
	}

	protected VerticalChoicesPanel getChangeConflictPanel(Reference myRef, ChangeListener listener) {
		VerticalChoicesPanel panel = getVerticalConflictPanel();
		panel.setTitle("Reference");
		Address fromAddr = myRef.getFromAddress();
		int opIndex = myRef.getOperandIndex();
		String fromAddrStr = ConflictUtility.getAddressString(myRef.getFromAddress());
		String toAddrStr =
			ConflictUtility.colorString(ConflictUtility.ADDRESS_COLOR,
				DiffUtility.getUserToAddressString(resultPgm, myRef.getToAddress()));
		Reference latestRef;
		Reference originalRef;
		if (myRef.isMemoryReference()) {
			latestRef = DiffUtility.getReference(myPgm, myRef, latestPgm);
			originalRef = DiffUtility.getReference(myPgm, myRef, originalPgm);
		}
		else {
			Reference[] latestRefs = latestRefMgr.getReferencesFrom(fromAddr, opIndex);
			latestRef = (latestRefs.length > 0) ? latestRefs[0] : null;
			Reference[] originalRefs = originalRefMgr.getReferencesFrom(fromAddr, opIndex);
			originalRef = (originalRefs.length > 0) ? originalRefs[0] : null;
		}
		String text;
		if (myRef.isExternalReference()) {
			text =
				getRefGroup(myRef) + " Reference from '" + fromAddrStr + "' " +
					getOperandIndexString(myRef) + " was changed in both versions.";
		}
		else {
			text =
				getRefGroup(myRef) + " Reference from '" + fromAddrStr + "' " +
					getOperandIndexString(myRef) + " to '" + toAddrStr +
					"' was changed in both versions.";
		}
		panel.setHeader(text);
		panel.setRowHeader(getReferenceInfo(null, null, null, null));
		String latestPrefix = "Change as in '";
		String myPrefix = "Change as in '";
		String suffix = "' version";
		panel.addRadioButtonRow(getReferenceInfo(latestPgm, latestRef, latestPrefix, suffix),
			LATEST_BUTTON_NAME, KEEP_LATEST, listener);
		panel.addRadioButtonRow(getReferenceInfo(myPgm, myRef, myPrefix, suffix),
			CHECKED_OUT_BUTTON_NAME, KEEP_MY, listener);
		panel.addInfoRow(getReferenceInfo(originalPgm, originalRef, "'", suffix));

		return panel;
	}

	protected VerticalChoicesPanel getAddConflictPanel(Reference myReference,
			ChangeListener listener) {
		VerticalChoicesPanel panel = getVerticalConflictPanel();
		Reference myRef = myReference;
		Reference latestRef = DiffUtility.getReference(myPgm, myRef, latestPgm);
		Reference originalRef = DiffUtility.getReference(myPgm, myRef, originalPgm);
		if (latestRef == null) {
			Reference[] latestRefs =
				latestRefMgr.getReferencesFrom(myRef.getFromAddress(), myRef.getOperandIndex());
			latestRef = (latestRefs.length > 0) ? latestRefs[0] : null;
		}
		if (originalRef == null) {
			Reference[] originalRefs =
				originalRefMgr.getReferencesFrom(myRef.getFromAddress(), myRef.getOperandIndex());
			originalRef = (originalRefs.length > 0) ? originalRefs[0] : null;
		}
		panel.setTitle("Reference");
		String fromAddrStr = ConflictUtility.getAddressString(myRef.getFromAddress());
		String text =
			getRefGroup(myRef) + " Reference from '" + fromAddrStr + "' " +
				getOperandIndexString(myRef) + " was added in both versions.";
		panel.setHeader(text);
		panel.setRowHeader(getReferenceInfo(null, null, null, null));
		String latestPrefix = "Use '";
		String myPrefix = "Use '";
		String suffix = "' version";
		panel.addRadioButtonRow(getReferenceInfo(latestPgm, latestRef, latestPrefix, suffix),
			LATEST_BUTTON_NAME, KEEP_LATEST, listener);
		panel.addRadioButtonRow(getReferenceInfo(myPgm, myRef, myPrefix, suffix),
			CHECKED_OUT_BUTTON_NAME, KEEP_MY, listener);
		panel.addInfoRow(getReferenceInfo(originalPgm, originalRef, "'", suffix));

		return panel;
	}

	protected VerticalChoicesPanel getPrimaryConflictPanel(Address fromAddress, int opIndex,
			ChangeListener listener) {
		VerticalChoicesPanel panel = getVerticalConflictPanel();
		Reference latestPrimary = latestRefMgr.getPrimaryReferenceFrom(fromAddress, opIndex);
		Reference myPrimary = myRefMgr.getPrimaryReferenceFrom(fromAddress, opIndex);
		panel.setTitle("Reference");
		String fromAddrStr = ConflictUtility.getAddressString(fromAddress);
		String text =
			" Conflicting primary references at '" + fromAddrStr + "' " +
				getOperandIndexString(opIndex) + ".";
		panel.setHeader(text);
		panel.setRowHeader(getReferenceInfo(null, null, null, null));
		String prefix = "Set '";
		String suffix = "' version to primary";
		panel.addRadioButtonRow(getReferenceInfo(latestPgm, latestPrimary, prefix, suffix),
			LATEST_BUTTON_NAME, KEEP_LATEST, listener);
		panel.addRadioButtonRow(getReferenceInfo(myPgm, myPrimary, prefix, suffix),
			CHECKED_OUT_BUTTON_NAME, KEEP_MY, listener);

		return panel;
	}

	private String getRefGroup(Reference ref) {
		if (ref.isMemoryReference()) {
			return "Memory";
		}
		else if (ref.isExternalReference()) {
			return "External";
		}
		else if (ref.isStackReference()) {
			return "Stack";
		}
		if (ref.isRegisterReference()) {
			return "Register";
		}
		return "Unknown";
	}

	private String[] getReferenceInfo(Program pgm, Reference ref, String prefix, String suffix) {
		if (pgm == null) { // Header info
			return new String[] { "Option", "Type", "From", "Operand", "To", "Symbol", "Primary",
				"Source" };
		}
		String[] info = new String[] { "", "", "", "", "", "", "", "" };
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
		if (ref != null) {
			int opIndex = ref.getOperandIndex();
			info[1] = ref.getReferenceType().toString();
			info[2] = ref.getFromAddress().toString();
			info[3] = (opIndex == -1) ? "mnemonic" : Integer.toString(opIndex);
			Address toAddress = ref.getToAddress();
			if (ref.isExternalReference()) {
				ExternalReference extRef = (ExternalReference) ref;
				ExternalLocation externalLocation = extRef.getExternalLocation();
				if (externalLocation != null) {
					toAddress = externalLocation.getAddress();
				}
			}
			info[4] = DiffUtility.getUserToAddressString(pgm, toAddress);
			info[5] = DiffUtility.getUserToSymbolString(pgm, ref);
			info[6] = "" + ref.isPrimary();
			info[7] = "" + ref.getSource().toString();
		}
		return info;
	}

	private String getOperandIndexString(Reference ref) {
		String opIndexStr = ConflictUtility.getNumberString(ref.getOperandIndex());
		return (ref.isMnemonicReference()) ? "mnemonic" : ("operand " + opIndexStr);
	}

	private String getOperandIndexString(int opIndex) {
		String opIndexStr = ConflictUtility.getNumberString(opIndex);
		return (opIndex == -1) ? "mnemonic" : ("operand " + opIndexStr);
	}

	private void resolveTypeConflict(Address fromAddress, int opIndex, int chosenConflictOption) {
		if ((chosenConflictOption & KEEP_LATEST) != 0) {
			listingMergeMgr.mergeLatest.replaceReferences(fromAddress, opIndex);
		}
		else if ((chosenConflictOption & KEEP_MY) != 0) {
			listingMergeMgr.mergeMy.replaceReferences(fromAddress, opIndex);
		}
	}

	private void resolveRemoveVsChange(Reference ref, int chosenConflictOption) {
		Reference resultRef = DiffUtility.getReference(originalPgm, ref, resultPgm);
		long resultSymID = -1;
		if ((chosenConflictOption & KEEP_LATEST) != 0) {
			Reference latestRef = DiffUtility.getReference(originalPgm, ref, latestPgm);
			if (ref != null && ref.getReferenceType().isFallthrough()) {
				Address fromAddr = ref.getFromAddress();
				int opIndex = ref.getOperandIndex();
				latestRef = getFallThroughReference(latestPgm, fromAddr, opIndex);
				if (latestRef == null) {
					Address fallthroughAddr =
						SimpleDiffUtility.getCompatibleAddress(originalPgm, fromAddr, resultPgm);
					clearFallThroughOverride(resultPgm, fallthroughAddr);
					return;
				}
			}
			resultSymID = (latestRef != null) ? latestRef.getSymbolID() : -1;
			try {
				resultSymID = getResultIDFromLatestID(resultSymID);
			}
			catch (NoValueException e) {
				// Do nothing.
			}
			listingMergeMgr.mergeLatest.replaceReference(resultRef, latestRef, resultSymID);
		}
		else if ((chosenConflictOption & KEEP_MY) != 0) {
			Reference myRef = DiffUtility.getReference(originalPgm, ref, myPgm);
			if (ref != null && ref.getReferenceType().isFallthrough()) {
				Address fromAddr = ref.getFromAddress();
				int opIndex = ref.getOperandIndex();
				myRef = getFallThroughReference(myPgm, fromAddr, opIndex);
				if (myRef == null) {
					Address fallthroughAddr =
						SimpleDiffUtility.getCompatibleAddress(originalPgm, fromAddr, resultPgm);
					clearFallThroughOverride(resultPgm, fallthroughAddr);
					return;
				}
			}
			resultSymID = (myRef != null) ? myRef.getSymbolID() : -1;
			try {
				resultSymID = getResultIDFromMyID(resultSymID);
			}
			catch (NoValueException e) {
				// Do nothing.
			}
			listingMergeMgr.mergeMy.replaceReference(resultRef, myRef, resultSymID);
		}
		else {
			return;
		}
	}

	private void resolveChangeConflict(Reference ref, int chosenConflictOption) {
		Reference resultRef = DiffUtility.getReference(originalPgm, ref, resultPgm);
		if ((chosenConflictOption & KEEP_LATEST) != 0) {
			keepLatestRefForChangeConflict(ref, resultRef);
		}
		else if ((chosenConflictOption & KEEP_MY) != 0) {
			keepMyRefForChangeConflict(ref, resultRef);
		}
		else {
			return;
		}
	}

	private void keepLatestRefForChangeConflict(Reference ref, Reference resultRef) {
		long resultSymID;
		Reference latestRef;
		if (ref.isMemoryReference()) {
			latestRef = DiffUtility.getReference(originalPgm, ref, latestPgm);
		}
		else {
			Reference[] latestRefs =
				latestRefMgr.getReferencesFrom(ref.getFromAddress(), ref.getOperandIndex());
			latestRef = (latestRefs.length > 0) ? latestRefs[0] : null;
		}
		resultSymID = (latestRef != null) ? latestRef.getSymbolID() : -1;
		try {
			resultSymID = getResultIDFromLatestID(resultSymID);
		}
		catch (NoValueException e) {
			// Do nothing.
		}
		listingMergeMgr.mergeLatest.replaceReference(resultRef, latestRef, resultSymID);
	}

	private void keepMyRefForChangeConflict(Reference ref, Reference resultRef) {
		long resultSymID;
		Reference myRef;
		if (ref.isMemoryReference()) {
			myRef = DiffUtility.getReference(originalPgm, ref, myPgm);
		}
		else {
			Reference[] myRefs =
				myRefMgr.getReferencesFrom(ref.getFromAddress(), ref.getOperandIndex());
			myRef = (myRefs.length > 0) ? myRefs[0] : null;
		}
		resultSymID = (myRef != null) ? myRef.getSymbolID() : -1;
		try {
			resultSymID = getResultIDFromMyID(resultSymID);
		}
		catch (NoValueException e) {
			// Do nothing.
		}
		listingMergeMgr.mergeMy.replaceReference(resultRef, myRef, resultSymID);
	}

	private Reference resolveAddConflict(Reference ref, int chosenConflictOption) {
		Reference myRef = ref;
		Reference resultRef = null;
		if ((chosenConflictOption & KEEP_LATEST) != 0) {
			resultRef = keepLatestRefForAddConflict(ref, myRef, resultRef);
		}
		else if ((chosenConflictOption & KEEP_MY) != 0) {
			resultRef = keepMyRefForAddConflict(ref, myRef, resultRef);
		}
		return resultRef;
	}

	private Reference keepLatestRefForAddConflict(Reference ref, Reference myRef,
			Reference resultRef) {
		long resultSymID;
		Reference latestRef = DiffUtility.getReference(myPgm, myRef, latestPgm);
		if (ref.isMemoryReference()) {
			resultRef = DiffUtility.getReference(latestPgm, latestRef, resultPgm);
		}
		else {
			Reference[] latestRefs =
				latestRefMgr.getReferencesFrom(ref.getFromAddress(), ref.getOperandIndex());
			latestRef = (latestRefs.length > 0) ? latestRefs[0] : null;
		}
		resultSymID = (latestRef != null) ? latestRef.getSymbolID() : -1;
		try {
			resultSymID = getResultIDFromLatestID(resultSymID);
		}
		catch (NoValueException e) {
			// Do nothing
		}
		// Check to see if this is really an update of the reference.
		if (resultRef == null) {
			resultRef = listingMergeMgr.mergeLatest.addReference(latestRef, resultSymID, true);
		}
		else {
			resultRef = listingMergeMgr.mergeMy.replaceReference(resultRef, latestRef);
		}
		return resultRef;
	}

	private Reference keepMyRefForAddConflict(Reference ref, Reference myRef, Reference resultRef) {
		long resultSymID;
		if (ref.isMemoryReference()) {
			resultRef = DiffUtility.getReference(myPgm, myRef, resultPgm);
		}
		else {
			Reference[] myRefs =
				myRefMgr.getReferencesFrom(ref.getFromAddress(), ref.getOperandIndex());
			myRef = (myRefs.length > 0) ? myRefs[0] : null;
		}
		resultSymID = (myRef != null) ? myRef.getSymbolID() : -1;
		try {
			resultSymID = getResultIDFromMyID(resultSymID);
		}
		catch (NoValueException e) {
			// Do nothing.
		}
		// Check to see if this is really an update of the reference.
		if (resultRef == null) {
			resultRef = listingMergeMgr.mergeMy.addReference(myRef, resultSymID, true);
		}
		else {
			resultRef = listingMergeMgr.mergeMy.replaceReference(resultRef, myRef);
		}
		return resultRef;
	}

	private void resolvePrimaryConflict(Address fromAddress, int opIndex, int chosenConflictOption) {
		if ((chosenConflictOption & KEEP_LATEST) != 0) {
			Reference latest = latestRefMgr.getPrimaryReferenceFrom(fromAddress, opIndex);
			Reference result = DiffUtility.getReference(latestPgm, latest, resultPgm);
			if (result != null) {
				resultRefMgr.setPrimary(result, true);
			}
		}
		else if ((chosenConflictOption & KEEP_MY) != 0) {
			Reference my = myRefMgr.getPrimaryReferenceFrom(fromAddress, opIndex);
			Reference result = DiffUtility.getReference(myPgm, my, resultPgm);
			if (result != null) {
				resultRefMgr.setPrimary(result, true);
			}
		}
	}

	@Override
	public AddressSetView getConflicts() {
		return conflictSet;
	}

	private int getChoiceForConflictType(int programMergeCommentType) {
		switch (programMergeCommentType) {
			case TYPE_CONFLICT:
				return referenceTypeChoice;
			case PRIMARY_CONFLICT:
				return primaryReferenceChoice;
			case REMOVE_CONFLICT:
			case CHANGE_CONFLICT:
			case ADD_CONFLICT:
				return referenceChoice;
			default:
				return ASK_USER;
		}
	}

	private void setChoiceForConflictType(int programMergeConflictType, int choiceForConflictType) {
		switch (programMergeConflictType) {
			case TYPE_CONFLICT:
				referenceTypeChoice = choiceForConflictType;
				break;
			case PRIMARY_CONFLICT:
				primaryReferenceChoice = choiceForConflictType;
				break;
			case REMOVE_CONFLICT:
			case CHANGE_CONFLICT:
			case ADD_CONFLICT:
				referenceChoice = choiceForConflictType;
				break;
			default:
				Msg.showError(this, listingMergePanel, "Unrecognized Reference Conflict Type",
					"Unrecognized indicator (" + programMergeConflictType +
						") for reference conflict type to merge.");
		}
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
				Symbol resultSymbol =
					SimpleDiffUtility.getSymbol(latestSymbol, resultPgm);
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

	private long getExternalResultIDFromLatestID(long latestSymbolID) throws NoValueException {
		try {
			return latestResolvedSymbols.get(latestSymbolID);
		}
		catch (NoValueException e) {
			if (resultPgm.getSymbolTable().getSymbol(latestSymbolID) != null) {
				return latestSymbolID;
			}
			throw e;
		}
	}

	private long getExternalResultIDFromMyID(long mySymbolID) throws NoValueException {
		try {
			return myResolvedSymbols.get(mySymbolID);
		}
		catch (NoValueException e) {
			if (resultPgm.getSymbolTable().getSymbol(mySymbolID) != null) {
				return mySymbolID;
			}
			throw e;
		}
	}

	private long getExternalResultIDFromOriginalID(long originalSymbolID) throws NoValueException {
		try {
			return origResolvedSymbols.get(originalSymbolID);
		}
		catch (NoValueException e) {
			if (resultPgm.getSymbolTable().getSymbol(originalSymbolID) != null) {
				return originalSymbolID;
			}
			throw e;
		}
	}
}
