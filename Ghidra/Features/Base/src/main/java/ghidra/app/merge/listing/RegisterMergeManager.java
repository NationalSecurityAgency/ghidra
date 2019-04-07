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

import ghidra.app.merge.MergeConstants;
import ghidra.app.merge.ProgramMultiUserMergeManager;
import ghidra.app.merge.tool.ListingMergePanel;
import ghidra.app.merge.util.ConflictUtility;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.util.ArrayList;

import javax.swing.SwingUtilities;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

/**
 * <code>RegisterMergeManager</code> handles the merge for a single named register.
 */
class RegisterMergeManager implements ListingMergeConstants {

	/** conflictOption can be ASK_USER, PICK_LATEST, PICK_MY, or PICK_ORIGINAL */
	private int conflictOption = ASK_USER;

	private ProgramMultiUserMergeManager mergeManager;
	private ConflictInfoPanel conflictInfoPanel;
	private ListingMergePanel listingMergePanel;
	private VerticalChoicesPanel conflictPanel;
	private String registerName;
	private Address min;
	private Address max;
	private Register resultReg;
	private AddressSet autoSet;
	private AddressSet conflictSet;
	private AddressRange[] rvrs;

	/** the program to be updated with the result of the merge.
	 * This is the program that will actually get checked in. */
	Program resultPgm;
	/** the program that was checked out. */
	Program originalPgm;
	/** the latest checked-in version of the program. */
	Program latestPgm;
	/** the program requesting to be checked in. */
	Program myPgm;
	/** program changes between the original and latest versioned program. */
	ProgramChangeSet latestChanges;
	/** program changes between the original and my modified program. */
	ProgramChangeSet myChanges;
	/** addresses of listing changes between the original and latest versioned program. */
	AddressSetView latestSet;
	/** addresses of listing changes between the original and my modified program. */
	AddressSetView mySet;

	ProgramContext originalContext;
	ProgramContext latestContext;
	ProgramContext myContext;
	ProgramContext resultContext;

	/** Used to determine differences between the original program and latest program. */
	ProgramDiff diffOriginalLatest;
	/** Used to determine differences between the original program and my program. */
	ProgramDiff diffOriginalMy;
	ProgramDiffFilter diffFilter;
	ProgramMergeFilter mergeFilter;
	ProgramMerge pm;

	private int contextChoice = ASK_USER;

	/**
	 * Creates a RegisterMergeManager.
	 * @param resultPgm the program to be updated with the result of the merge.
	 * This is the program that will actually get checked in.
	 * @param originalPgm the program that was checked out.
	 * @param latestPgm the latest checked-in version of the program.
	 * @param myPgm the program requesting to be checked in.
	 * @param latestChanges the address set of changes between original and latest versioned program.  
	 * @param myChanges the address set of changes between original and my modified program.
	 */
	RegisterMergeManager(String registerName, ProgramMultiUserMergeManager mergeManager,
			Program resultPgm, Program originalPgm, Program latestPgm, Program myPgm,
			ProgramChangeSet latestChanges, ProgramChangeSet myChanges) {
		this.registerName = registerName;
		this.mergeManager = mergeManager;
		this.resultPgm = resultPgm;
		this.originalPgm = originalPgm;
		this.latestPgm = latestPgm;
		this.myPgm = myPgm;
		this.latestChanges = latestChanges;
		this.myChanges = myChanges;
		this.latestSet = latestChanges.getRegisterAddressSet();
		this.mySet = myChanges.getRegisterAddressSet();

		originalContext = originalPgm.getProgramContext();
		latestContext = latestPgm.getProgramContext();
		myContext = myPgm.getProgramContext();
		resultContext = resultPgm.getProgramContext();

		resultReg = resultContext.getRegister(registerName);
		if (resultReg.isProcessorContext()) {
			throw new IllegalArgumentException("Processor context register not allowed");
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#apply()
	 */
	public void apply() {
		conflictOption = conflictPanel.getSelectedOptions();

		// If the "Use For All" check box is selected 
		// then save the option chosen for this conflict type.
		if (conflictPanel.getUseForAll()) {
			contextChoice = conflictOption;
		}

		merge(min, max, resultReg);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#cancel()
	 */
	public void cancel() {
		conflictOption = CANCELED;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#getDescription()
	 */
	public String getDescription() {
		return "Merge Register";
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#getName()
	 */
	public String getName() {
		return "Register Merger";
	}

	/**
	 * 
	 * @param monitor
	 */
	private void determineConflicts(TaskMonitor monitor) throws CancelledException {
		if (conflictSet != null) {
			return; //This method only needs to be called once.
		}
		RegisterConflicts rc =
			new RegisterConflicts(registerName, originalContext, latestContext, myContext,
				resultContext);
		Memory resultMem = resultPgm.getMemory();
		AddressSetView myDiffs =
			rc.getRegisterDifferences(registerName, originalContext, myContext, mySet, monitor);
		AddressSet setToCheck = resultMem.intersect(myDiffs);
		conflictSet = new AddressSet();
		rvrs = rc.getConflicts(setToCheck, monitor);
		if (rvrs.length > 0) {
			for (int j = 0; j < rvrs.length; j++) {
				conflictSet.add(rvrs[j]);
			}
		}
		autoSet = setToCheck.subtract(conflictSet);
	}

	/**
	 * Merges all the register values for the named register being managed by this merge manager.
	 * @param monitor the monitor that provides feedback to the user.
	 * @throws ProgramConflictException
	 * @throws CancelledException if the user cancels
	 */
	public void merge(TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Auto-merging " + registerName +
			" Register Values and determining conflicts.");

		determineConflicts(monitor);

		// Auto merge any program context changes from my program where the
		// resulting program has the mem addresses but the latest doesn't.
		AddressRangeIterator arIter = autoSet.getAddressRanges();
		try {
			while (arIter.hasNext() && !monitor.isCancelled()) {
				AddressRange range = arIter.next();
				Address rangeMin = range.getMinAddress();
				Address rangeMax = range.getMaxAddress();
				resultContext.remove(rangeMin, rangeMax, resultReg);
				AddressRangeIterator it =
					myContext.getRegisterValueAddressRanges(resultReg, rangeMin, rangeMax);
				while (it.hasNext()) {
					AddressRange valueRange = it.next();
					BigInteger value =
						myContext.getValue(resultReg, valueRange.getMinAddress(), false);
					resultContext.setValue(resultReg, valueRange.getMinAddress(),
						valueRange.getMaxAddress(), value);
				}
			}
		}
		catch (ContextChangeException e) {
			// ignore since processor context-register is not handled by this merge manager
		}

		int totalConflicts = rvrs.length;
		if (totalConflicts == 0) {
			return;
		}

		listingMergePanel = mergeManager.getListingMergePanel();
		conflictInfoPanel = new ConflictInfoPanel();
		listingMergePanel.setTopComponent(conflictInfoPanel);

		// Merge the conflicts.
		monitor.setMessage("Resolving " + registerName + " Register Value conflicts.");
		boolean askUser = (conflictOption == ASK_USER);
		for (int conflictIndex = 0; conflictIndex < totalConflicts; conflictIndex++) {
			AddressRange range = rvrs[conflictIndex];
			Address rangeMin = range.getMinAddress();
			Address rangeMax = range.getMaxAddress();
			BigInteger myValue = myContext.getValue(resultReg, rangeMin, false);
			BigInteger latestValue = latestContext.getValue(resultReg, rangeMin, false);
			BigInteger originalValue = originalContext.getValue(resultReg, rangeMin, false);
			// If we have a register context choice then a "Use For All" has already occurred.
			if (contextChoice != ASK_USER) {
				if (conflictOption != contextChoice) {
					conflictOption = contextChoice;
				}
				askUser = (conflictOption == ASK_USER);
			}
			if (askUser) {
				conflictInfoPanel.setRegisterInfo(registerName);
				conflictInfoPanel.setCodeUnitInfo(new AddressRangeImpl(rangeMin, rangeMax),
					conflictIndex + 1, totalConflicts);
				// Display dialog to allow user to choose latest or my register value.
				showMergePanel(rangeMin, rangeMax, latestValue, myValue, originalValue);
				// apply() will set the conflictOption and do the merge.
				if (conflictOption == CANCELED) {
					throw new CancelledException();
				}
				continue;
			}
			merge(rangeMin, rangeMax, resultReg);
		}
	}

	/**
	 * @param minAddress
	 * @param maxAddress
	 * @param myValue
	 */
	private void merge(Address minAddress, Address maxAddress, Register resultRegister) {
		// Everywhere there is a conflict, we want to merge according to the conflict decision.
		switch (conflictOption) {
			case KEEP_LATEST:
				merge(minAddress, maxAddress, resultRegister,
					latestContext.getValue(resultRegister, minAddress, false));
				break;
			case KEEP_MY:
				merge(minAddress, maxAddress, resultRegister,
					myContext.getValue(resultRegister, minAddress, false));
				break;
			case KEEP_ORIGINAL:
				merge(minAddress, maxAddress, resultRegister,
					originalContext.getValue(resultRegister, minAddress, false));
				break;
		}
	}

	/**
	 * 
	 * @param minAddress
	 * @param maxAddress
	 * @param resultRegister
	 * @param myValue
	 */
	private void merge(Address minAddress, Address maxAddress, Register resultRegister,
			BigInteger myValue) {
		try {
			resultContext.setValue(resultRegister, minAddress, maxAddress, myValue);
		}
		catch (ContextChangeException e) {
			// ignore since this merge manager does not handle the processor context register
		}
	}

	/**
	 * For JUnit testing only, set the option for resolving a conflict.
	 * @param decision ASK_USER, PICK_LATEST, PICK_MY
	 */
	void setConflictDecision(int decision) {
		if (decision == ASK_USER || decision == KEEP_LATEST || decision == KEEP_MY) {
			conflictOption = decision;
		}
		else {
			throw new IllegalArgumentException();
		}
	}

	private void showMergePanel(final Address minAddress, final Address maxAddress,
			final BigInteger latestValue, final BigInteger myValue, final BigInteger originalValue) {
		this.min = minAddress;
		this.max = maxAddress;
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
						mergeManager.setApplyEnabled(true);
					}
				}
			};
			SwingUtilities.invokeAndWait(new Runnable() {
				@Override
				public void run() {
					VerticalChoicesPanel panel =
						getConflictsPanel(minAddress, maxAddress, latestValue, myValue,
							originalValue, changeListener);
					listingMergePanel.setBottomComponent(panel);
				}
			});
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					listingMergePanel.clearAllBackgrounds();
					listingMergePanel.paintAllBackgrounds(new AddressSet(minAddress, maxAddress));
				}
			});
		}
		catch (InterruptedException e) {
		}
		catch (InvocationTargetException e) {
		}
		if (mergeManager != null) {
			mergeManager.setApplyEnabled(false);
			mergeManager.showListingMergePanel(minAddress);
		}
		// block until the user either cancels or hits the "Apply" button
		// on the merge dialog...
		// when the "Apply" button is hit, get the user's selection
		// and continue.
	}

	private VerticalChoicesPanel getConflictsPanel(final Address minAddress,
			final Address maxAddress, final BigInteger latestValue, final BigInteger myValue,
			final BigInteger originalValue, ChangeListener changeListener) {
		if (conflictPanel == null) {
			conflictPanel = new VerticalChoicesPanel();
		}
		else {
			conflictPanel.clear();
		}
		conflictPanel.setTitle("\"" + registerName + "\" Register Value");
		String text =
			"Register: " + ConflictUtility.getEmphasizeString(registerName) +
				ConflictUtility.spaces(4) + "Address Range: " +
				ConflictUtility.getAddressString(minAddress) + " - " +
				ConflictUtility.getAddressString(maxAddress) +
				"<br>Select the desired register value for the address range.";
		conflictPanel.setHeader(text);
		conflictPanel.setRowHeader(getRegisterInfo(-1, null));
		conflictPanel.addRadioButtonRow(getRegisterInfo(MergeConstants.LATEST, latestValue),
			LATEST_BUTTON_NAME, KEEP_LATEST, changeListener);
		conflictPanel.addRadioButtonRow(getRegisterInfo(MergeConstants.MY, myValue),
			CHECKED_OUT_BUTTON_NAME, KEEP_MY, changeListener);
		conflictPanel.addRadioButtonRow(getRegisterInfo(MergeConstants.ORIGINAL, originalValue),
			ORIGINAL_BUTTON_NAME, KEEP_ORIGINAL, changeListener);
		conflictPanel.setConflictType(registerName + " Register Value");
		return conflictPanel;
	}

	private String[] getRegisterInfo(int version, BigInteger value) {
		String[] info = new String[] { "", "" };
		if (version == MergeConstants.LATEST) {
			info[0] = " '" + MergeConstants.LATEST_TITLE + "' version";
		}
		else if (version == MergeConstants.MY) {
			info[0] = " '" + MergeConstants.MY_TITLE + "' version";
		}
		else if (version == MergeConstants.ORIGINAL) {
			info[0] = " '" + MergeConstants.ORIGINAL_TITLE + "' version";
		}
		else {
			return new String[] { "Option", "Register Value" };
		}
		if (value != null) {
			info[1] = "0x" + value.toString(16);
		}
		else {
			info[1] = ConflictUtility.NO_VALUE;
		}
		return info;
	}

	private class RegisterConflicts {

		String conflictRegisterName;
		ProgramContext conflictOriginalContext;
		ProgramContext conflictLatestContext;
		ProgramContext conflictMyContext;
		ProgramContext conflictResultContext;
		Register conflictOriginalReg;
		Register conflictLatestReg;
		Register conflictMyReg;
		Register conflictResultReg;

		RegisterConflicts(String registerName, ProgramContext originalContext,
				ProgramContext latestContext, ProgramContext myContext, ProgramContext resultContext) {
			this.conflictRegisterName = registerName;
			this.conflictOriginalContext = originalContext;
			this.conflictLatestContext = latestContext;
			this.conflictMyContext = myContext;
			this.conflictResultContext = resultContext;
			conflictOriginalReg = originalContext.getRegister(registerName);
			conflictLatestReg = latestContext.getRegister(registerName);
			conflictMyReg = myContext.getRegister(registerName);
			conflictResultReg = resultContext.getRegister(registerName);
		}

		/** Gets the addresses where the named register differs 
		 * between two programs.
		 *
		 * @param regName
		 * @param addressSet
		 * @param monitor the task monitor for indicating the progress of
		 * determining differences. This monitor reports the progress to the user.
		 *
		 * @return the addresses of code units where the register values differ.
		 */
		private AddressSet getRegisterDifferences(String regName, ProgramContext context1,
				ProgramContext context2, AddressSetView addressSet, TaskMonitor monitor) {
			AddressSet differences = new AddressSet();
			ProgramContext pc1 = context1;
			ProgramContext pc2 = context2;
			Register rb1 = pc1.getRegister(regName);
			Register rb2 = pc2.getRegister(regName);

			AddressRangeIterator iter = addressSet.getAddressRanges();
			while (iter.hasNext()) {
				AddressRange range = iter.next();
				Address rangeMin = range.getMinAddress();
				Address rangeMax = range.getMaxAddress();

				AddressRangeIterator it1 =
					pc1.getRegisterValueAddressRanges(rb1, rangeMin, rangeMax);
				AddressRangeIterator it2 =
					pc2.getRegisterValueAddressRanges(rb2, rangeMin, rangeMax);

				AddressRangeIterator it = new CombinedAddressRangeIterator(it1, it2);

				while (it.hasNext()) {
					AddressRange addrRange = it.next();
					BigInteger value1 = pc1.getValue(rb1, addrRange.getMinAddress(), false);
					BigInteger value2 = pc2.getValue(rb2, addrRange.getMinAddress(), false);
					boolean sameValue = (value1 == null) ? (value2 == null) : value1.equals(value2);
					if (!sameValue) {
						differences.addRange(addrRange.getMinAddress(), addrRange.getMaxAddress());
					}
				}

				if (monitor.isCancelled()) {
					return null;
				}
			}
			return differences;
		}

		AddressRange[] getConflicts(AddressSetView addressSet, TaskMonitor monitor)
				throws CancelledException {

			ArrayList<AddressRange> conflicts = new ArrayList<AddressRange>();

			AddressSet tempLatestChanges =
				getRegisterDifferences(conflictRegisterName, conflictOriginalContext,
					conflictLatestContext, addressSet, monitor);

			AddressSet tempMyChanges =
				getRegisterDifferences(conflictRegisterName, conflictOriginalContext,
					conflictMyContext, addressSet, monitor);

			AddressSet bothChanged = tempMyChanges.intersect(tempLatestChanges);

			// For each range in my program context change set.
			AddressRangeIterator iter = bothChanged.getAddressRanges();
			while (iter.hasNext()) {
				AddressRange range = iter.next();
				Address rangeMin = range.getMinAddress();
				Address rangeMax = range.getMaxAddress();

				AddressRangeIterator it1 =
					conflictLatestContext.getRegisterValueAddressRanges(conflictLatestReg,
						rangeMin, rangeMax);
				AddressRangeIterator it2 =
					conflictMyContext.getRegisterValueAddressRanges(conflictMyReg, rangeMin,
						rangeMax);
				AddressRangeIterator it = new CombinedAddressRangeIterator(it1, it2);

				while (it.hasNext()) {
					AddressRange addrRange = it.next();
					BigInteger lastestValue =
						conflictLatestContext.getValue(conflictLatestReg,
							addrRange.getMinAddress(), false);
					BigInteger myValue =
						conflictMyContext.getValue(conflictMyReg, addrRange.getMinAddress(), false);
					boolean sameValue =
						(lastestValue == null) ? (myValue == null) : lastestValue.equals(myValue);
					if (!sameValue) {
						conflicts.add(addrRange);
					}

				}
				monitor.checkCanceled();
			}
			return conflicts.toArray(new AddressRange[conflicts.size()]);
		}
	}
}
