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
import java.util.ArrayList;
import java.util.Hashtable;

import javax.swing.SwingUtilities;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import ghidra.app.merge.tool.ListingMergePanel;
import ghidra.app.merge.util.ConflictUtility;
import ghidra.app.merge.util.MergeUtilities;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.util.DiffUtility;
import ghidra.program.util.ProgramDiffFilter;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Class for merging equate changes. This class can merge equate changes 
 * that were made to the checked out version. It can determine
 * where there are conflicts between the latest checked in version and my
 * checked out version. It can then manually merge the conflicting equates.
 * <br>The EquateMerger takes into account anywhere that code units have been merged.
 * If code units were merged, then this will not try to merge at those addresses.
 * The code unit merger should have already merged the equates where it 
 * merged code units.
 * <br>Important: This class is intended to be used only for a single program 
 * version merge. It should be constructed, followed by an autoMerge(), and lastly
 * each address with a conflict should have mergeConflicts() called on it.
 */
class EquateMerger extends AbstractListingMerger {

	final static String EQUATES_PHASE = "Equates";
	EquateConflict currentConflict;

	EquateTable latestEquateTab;
	EquateTable myEquateTab;
	EquateTable originalEquateTab;

	AddressSetView latestDetailSet; // latest equate change set
	AddressSetView myDetailSet; // my equate change set

	AddressSet conflictSet;
	Hashtable<Address, ArrayList<EquateConflict>> conflicts;
	private VerticalChoicesPanel conflictPanel;
	private int equateChoice = ASK_USER;

	/**
	 * Constructs an equate merger.
	 * @param listingMergeMgr the listing merge manager that owns this merger.
	 */
	EquateMerger(ListingMergeManager listingMergeMgr) {
		super(listingMergeMgr);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.AbstractListingMerger#init()
	 */
	@Override
	public void init() {
		super.init();

		latestEquateTab = latestPgm.getEquateTable();
		myEquateTab = myPgm.getEquateTable();
		originalEquateTab = originalPgm.getEquateTable();

		conflictSet = new AddressSet();
		conflicts = new Hashtable<>();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#getConflictType()
	 */
	@Override
	public String getConflictType() {
		return "Equate";
	}

	@Override
	public boolean apply() {
		conflictOption = conflictPanel.getSelectedOptions();

		// If the "Use For All" check box is selected 
		// then save the option chosen for this conflict type.
		if (conflictPanel.getUseForAll()) {
			equateChoice = conflictOption;
		}

		return super.apply();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#autoMerge(ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void autoMerge(int progressMin, int progressMax, TaskMonitor monitor)
			throws CancelledException {

		initializeAutoMerge("Auto-merging Equates and determining conflicts.", progressMin,
			progressMax, monitor);

		ProgramDiffFilter filter = new ProgramDiffFilter(ProgramDiffFilter.EQUATE_DIFFS);
		latestDetailSet = listingMergeMgr.diffOriginalLatest.getDifferences(filter, monitor);
		myDetailSet = listingMergeMgr.diffOriginalMy.getDifferences(filter, monitor);
		AddressSet tmpAutoSet = new AddressSet();
		AddressSet possibleConflicts = new AddressSet();
		MergeUtilities.adjustSets(latestDetailSet, myDetailSet, tmpAutoSet, possibleConflicts);
		// Ignore the code units that were automatically and manually merged
		// by CodeUnitMerger. Equates are already handled there.
		AddressSet mergedCodeUnits = listingMergeMgr.getMergedCodeUnits();
		tmpAutoSet.delete(mergedCodeUnits);
		mergeAllEquates(tmpAutoSet, KEEP_MY, monitor);
		possibleConflicts.delete(mergedCodeUnits);
		// FIXME
		mergeManager.updateProgress(progressMin + ((progressMax - progressMin) / 3)); // For now increment the phase progress 1/3 of the total.

		// The equate changes could be on different operands.
		// For instructions, they can be on different sub-operands.
		// Inspect the equates at each operand/sub-operand to get the true conflicts.
		CodeUnitIterator iter = resultPgm.getListing().getCodeUnits(possibleConflicts, true);
		while (iter.hasNext()) {
			CodeUnit resultCU = iter.next();
			Address addr = resultCU.getMinAddress();
			int numOps = resultCU.getNumOperands();
			for (int opIndex = 0; opIndex < numOps; opIndex++) {
				// Each operand index can have multiple scalars
				Scalar[] scalars = getScalars(resultCU, opIndex);
				for (Scalar scalar : scalars) {
					monitor.checkCanceled();
					getOperandScalarConflicts(addr, opIndex, scalar);
				}
			}
		}
		updateProgress(100, "Done auto-merging Equates and determining conflicts.");
	}

	/**
	 * Auto-merges equate changes for a scalar value at a particular address and operand.
	 * It also determines the equate conflicts for this scalar at this address and operand.
	 * @param addr the address of the code unit.
	 * @param opIndex the operand index
	 * @param scalar the scalar value.
	 * @throws MemoryAccessException
	 */
	private void getOperandScalarConflicts(Address addr, int opIndex, Scalar scalar) {
		long scalarValue = scalar.getValue();
		Equate latestEquate = latestEquateTab.getEquate(addr, opIndex, scalarValue);
		Equate myEquate = myEquateTab.getEquate(addr, opIndex, scalarValue);
		Equate originalEquate = originalEquateTab.getEquate(addr, opIndex, scalarValue);
		boolean sameOriginalLatest = sameEquates(originalEquate, latestEquate);
		boolean sameOriginalMy = sameEquates(originalEquate, myEquate);
		boolean sameLatestMy = sameEquates(latestEquate, myEquate);
		if (sameLatestMy) {
			return; // Do nothing.
		}
		if (!sameOriginalMy) {
			if (sameOriginalLatest) {
				merge(addr, opIndex, scalar, KEEP_MY);
			}
			else {
				saveConflict(addr, opIndex, scalar);
			}
		}
	}

	/**
	 * Compares two equates to determine if they are equal.
	 * @param equate1 the first equate or null.
	 * @param equate2 the second equate or null.
	 * @return true if the equates are equal.
	 */
	private boolean sameEquates(Equate equate1, Equate equate2) {
		if (equate1 == null) {
			return (equate2 == null);
		}
		return equate1.equals(equate2);
	}

	/**
	 * Gets an array with all the scalar values at a code unit and operand index.
	 * There can be multiple sub-operands and therefore multiple scalars for an operand.
	 * @param codeUnit the code unit
	 * @param opIndex the index of the operand
	 * @return the array of scalars.
	 */
	private Scalar[] getScalars(CodeUnit codeUnit, int opIndex) {
		Scalar cuScalar = codeUnit.getScalar(opIndex);
		if (cuScalar != null) {
			return new Scalar[] { cuScalar };
		}
		ArrayList<Scalar> list = new ArrayList<>();
		if (codeUnit instanceof Instruction) {
			Object[] objs = ((Instruction) codeUnit).getOpObjects(opIndex);
			for (int index = 0; index < objs.length; index++) {
				if (index >= 0 && index < objs.length && objs[index] instanceof Scalar) {
					Scalar scalar = (Scalar) objs[index];
					if (!list.contains(scalar)) {
						list.add(scalar);
					}
				}
			}
		}
		return list.toArray(new Scalar[list.size()]);
	}

	/**
	 * Saves off the indicated equate conflict.
	 * @param address the address of the conflict
	 * @param opIndex the operand index of the conflict
	 * @param scalar the scalar value of the conflict.
	 */
	private void saveConflict(Address address, int opIndex, Scalar scalar) {
		ArrayList<EquateConflict> list = conflicts.get(address);
		if (list == null) {
			list = new ArrayList<>(1);
			conflicts.put(address, list);
		}
		list.add(new EquateConflict(address, opIndex, scalar));
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
		ArrayList<EquateConflict> list = conflicts.get(addr);
		if (list == null) {
			return 0;
		}
		return list.size();
	}

	/**
	 * Performs the actual eqaute merge into the result program using the indicated program version as the source.
	 * @param address the address of the equate
	 * @param opIndex the operand index of the equate
	 * @param scalar the scalar value of the equate
	 * @param chosenConflictOption conflict option indicating whether to keep the latest, my, or original version.
	 */
	private void merge(Address address, int opIndex, Scalar scalar, int chosenConflictOption) {
		if ((chosenConflictOption & KEEP_ORIGINAL) != 0) {
			listingMergeMgr.mergeOriginal.mergeEquate(address, opIndex, scalar.getValue());
		}
		else if ((chosenConflictOption & KEEP_LATEST) != 0) {
			listingMergeMgr.mergeLatest.mergeEquate(address, opIndex, scalar.getValue());
		}
		else if ((chosenConflictOption & KEEP_MY) != 0) {
			listingMergeMgr.mergeMy.mergeEquate(address, opIndex, scalar.getValue());
		}
	}

	/**
	 * Merges all the equates for the address set. It merges into the result version from the
	 * version indicated by the conflict option.
	 * @param addressSet the address set
	 * @param chosenConflictOption conflict option indicating whether to keep the latest, my, or original version.
	 * @param monitor task monitor providing user with status or allowing merge to be canceled.
	 * @throws CancelledException
	 */
	private void mergeAllEquates(final AddressSet addressSet, final int chosenConflictOption,
			final TaskMonitor monitor) throws CancelledException {
		if ((chosenConflictOption & KEEP_ORIGINAL) != 0) {
			listingMergeMgr.mergeOriginal.mergeEquates(addressSet, monitor);
		}
		else if ((chosenConflictOption & KEEP_LATEST) != 0) {
			listingMergeMgr.mergeLatest.mergeEquates(addressSet, monitor);
		}
		else if ((chosenConflictOption & KEEP_MY) != 0) {
			listingMergeMgr.mergeMy.mergeEquates(addressSet, monitor);
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#mergeConflicts(ghidra.app.merge.tool.ListingMergePanel, ghidra.program.model.address.Address, int, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void mergeConflicts(ListingMergePanel listingPanel, Address addr,
			int chosenConflictOption, TaskMonitor monitor) throws CancelledException,
			MemoryAccessException {
		if (!hasConflict(addr)) {
			return;
		}
		monitor.setMessage("Resolving Equate conflicts.");
		boolean askUser = chosenConflictOption == ASK_USER;

		// At address get the equate conflict ArrayList.
		ArrayList<EquateConflict> list = conflicts.get(addr);
		if (list != null) {
			int len = list.size();
			// merge each conflict at this address.
			for (int i = 0; i < len; i++) {
				EquateConflict equateConflict = list.get(i);
				// If we have a equate choice then a "Use For All" has already occurred.
				if (equateChoice != ASK_USER) {
					merge(equateConflict.address, equateConflict.opIndex, equateConflict.scalar,
						equateChoice);
				}
				else {
					if (askUser && mergeManager != null) {
						setupConflictPanel(listingPanel, equateConflict);
						monitor.checkCanceled();
					}
					else {
						merge(equateConflict.address, equateConflict.opIndex,
							equateConflict.scalar, chosenConflictOption);
					}
				}
			}
		}
	}

	/**
	 * Sets up the equate conflict panel to present a choice to the user.
	 * @param listingPanel the listing merge panel.
	 * @param equateConflict the equate conflict to resolve.
	 */
	private void setupConflictPanel(final ListingMergePanel listingPanel,
			final EquateConflict equateConflict) {
		// This could have been invoked for a global conflict, primary conflict, or both.
		this.currentConflict = equateConflict;
		this.currentAddress = equateConflict.address;
		try {
			final ChangeListener changeListener = new ChangeListener() {
				@Override
				public void stateChanged(ChangeEvent e) {
					conflictOption = conflictPanel.getSelectedOptions();
					if (conflictOption == ASK_USER) {
						if (mergeManager != null) {
							mergeManager.setApplyEnabled(false);
						}
						return;
					}
					if (mergeManager != null) {
						mergeManager.clearStatusText();
					}
					EquateConflict conflictInfo = EquateMerger.this.currentConflict;
					merge(conflictInfo.address, conflictInfo.opIndex, conflictInfo.scalar,
						conflictOption);
					if (mergeManager != null) {
						mergeManager.setApplyEnabled(true);
					}
				}
			};
			SwingUtilities.invokeAndWait(new Runnable() {
				@Override
				public void run() {
					EquateConflict conflictInfo = EquateMerger.this.currentConflict;
					Address address = conflictInfo.address;
					int opIndex = conflictInfo.opIndex;
					long value = conflictInfo.scalar.getValue();
					Equate latest = latestEquateTab.getEquate(address, opIndex, value);
					Equate my = myEquateTab.getEquate(address, opIndex, value);
					Equate original = originalEquateTab.getEquate(address, opIndex, value);

					if (conflictPanel != null) {
						conflictPanel.clear();
					}
					else {
						conflictPanel = new VerticalChoicesPanel();
						currentConflictPanel = conflictPanel;
					}
					conflictPanel.setTitle("Equate");
					StringBuffer conflictBuf = new StringBuffer();
					conflictBuf.append("The equate changes at address ");
					ConflictUtility.addAddress(conflictBuf, address);
					conflictBuf.append(" and operand ");
					ConflictUtility.addCount(conflictBuf, opIndex);
					conflictBuf.append(" are in conflict. Select the desired result.");
					conflictPanel.setHeader(conflictBuf.toString());
					conflictPanel.setRowHeader(getEquateInfo(-1, null));
					conflictPanel.addRadioButtonRow(getEquateInfo(LATEST, latest),
						LATEST_BUTTON_NAME, KEEP_LATEST, changeListener);
					conflictPanel.addRadioButtonRow(getEquateInfo(MY, my), CHECKED_OUT_BUTTON_NAME,
						KEEP_MY, changeListener);
					conflictPanel.addInfoRow(getEquateInfo(ORIGINAL, original));

					boolean useForAll = (equateChoice != ASK_USER);
					conflictPanel.setUseForAll(useForAll);
					conflictPanel.setConflictType("Equate");

					listingPanel.setBottomComponent(conflictPanel);
				}
			});
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					EquateConflict conflictInfo = EquateMerger.this.currentConflict;
					Address address = conflictInfo.address;
					listingPanel.clearAllBackgrounds();
					listingPanel.paintAllBackgrounds(new AddressSet(address, address));
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
		// when the "Apply" button is hit, get the user's selection
		// and continue.
	}

	/**
	 * Gets the strings for presenting a row of equate information as column data.
	 * This is used to present the conflict in a table format.
	 * @param version the program version
	 * @param equate the equate to display from that version.
	 * @return the array of column strings.
	 */
	private String[] getEquateInfo(int version, Equate equate) {
		String[] info = new String[] { "", "", "" };
		if (version == LATEST) {
			info[0] = getChoice(LATEST_TITLE, equate);
		}
		else if (version == MY) {
			info[0] = getChoice(MY_TITLE, equate);
		}
		else if (version == ORIGINAL) {
			info[0] = " '" + ORIGINAL_TITLE + "' version";
		}
		else {
			return new String[] { "Option", "Equate", "Value" };
		}
		if (equate != null) {
			info[1] = equate.getDisplayName();
			info[2] = DiffUtility.toSignedHexString(equate.getValue());
		}
		return info;
	}

	/**
	 * Creates the string for the option or choice column of a row.
	 * @param version the program version.
	 * @param equate the equate
	 * @return the option string.
	 */
	private String getChoice(String version, Equate equate) {
		if (equate == null) {
			return "No equate as in '" + version + "' version";
		}
		return "Keep '" + version + "' version";
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#getConflicts()
	 */
	@Override
	public AddressSetView getConflicts() {
		return conflictSet;
	}

	/**
	 * <code>EquateConflict</code> provides the information needed to retain 
	 * and display an equate conflict to the user. It contains the address,
	 * operand index, and scalar value.
	 */
	private class EquateConflict {
		Address address;
		int opIndex;
		Scalar scalar;

		EquateConflict(Address address, int opIndex, Scalar scalar) {
			this.address = address;
			this.opIndex = opIndex;
			this.scalar = scalar;
		}
	}

}
