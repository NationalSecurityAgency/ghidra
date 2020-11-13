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
import java.util.Map;

import javax.swing.SwingUtilities;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import ghidra.app.merge.MergeConstants;
import ghidra.app.merge.tool.ListingMergePanel;
import ghidra.app.merge.util.ConflictUtility;
import ghidra.app.merge.util.MergeUtilities;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotYetImplementedException;
import ghidra.util.task.TaskMonitor;

/**
 * Manages byte and code unit changes and conflicts between the latest versioned
 * program and the modified program being checked into version control.
 * <br>Indirect conflicts include:
 * <ul>
 * <li>bytes and code units</li>
 * <li>bytes and equates</li>
 * <li>code units and equates</li>
 * </ul>
 * <br>Important: This class is intended to be used only for a single program
 * version merge. It should be constructed, followed by an autoMerge(), and lastly
 * should call mergeConflicts() passing it ASK_USER for the conflictOption.
 */
class CodeUnitMerger extends AbstractListingMerger {

	final static String CODE_UNITS_PHASE = "Bytes & Code Units";
	private Address min;
	private Address max;
	private VariousChoicesPanel conflictPanel;
	private int conflictChoice = ASK_USER;

	AddressSetView latestCUSet;
	AddressSetView myCUSet;
	AddressSetView bothChangedCUSet;
	AddressSetView latestByteSet; // latest and original bytes differ
	AddressSetView myByteSet; // my and original bytes differ

	AddressSet resultUninitSet; // Uninitialized memory addresses.

	// Addresses with conflicts.
	AddressSet conflictBytes; // LatestByte MyByte in conflict
	AddressSet conflictCodeUnits; // LatestCodeUnit MyCodeUnit in conflict
	AddressSet conflictByteCU; // LatestByte MyCodeUnit in conflict
	AddressSet conflictCUByte; // LatestCodeUnit MyByte in conflict
	AddressSet conflictByteEquate; // LatestByte MyEquate in conflict
	AddressSet conflictEquateByte; // LatestEquate MyByte in conflict
	AddressSet conflictEquateCU; // LatestEquate MyCodeUnit in conflict
	AddressSet conflictCUEquate; // LatestCodeUnit MyEquate in conflict
	AddressSet conflictRefCU; // LatestReferences MyCodeUnit in conflict
	AddressSet conflictCURef; // LatestCodeUnit MyReferences in conflict

	AddressSet conflictAll; // All the addresses with byte or code unit conflicts.
	AddressRange[] ranges; // Each range for the manual merge.
	AddressSet manualSet; // All addresses where manual merging will occur.

	// Addresses to autoMerge.
	AddressSet autoBytes;
	AddressSet autoCodeUnits;
	private AddressSet mergedCodeUnits;

	// Keep track of which code units were changed in the result file
	// and where they originated from.
	AddressSet pickedLatestCodeUnits;
	AddressSet pickedMyCodeUnits;
	AddressSet pickedOriginalCodeUnits;

	ProgramMerge mergeMy;
	ProgramMerge mergeLatest;
	ProgramMerge mergeOriginal;

	private Map<Long, DataType> myResolvedDts; // maps data type ID -> resolved Data type
	private Map<Long, DataType> origResolvedDts;

	/**
	 * Manages code unit changes and conflicts between the latest versioned
	 * program and the modified program being checked into version control.
	 * @param listingMergeMgr the listing merge manager that owns this merger.
	 */
	CodeUnitMerger(ListingMergeManager listingMergeMgr) {
		super(listingMergeMgr);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.AbstractListingMerger#init()
	 */
	@SuppressWarnings("unchecked")
	@Override
	public void init() {
		super.init();
		autoBytes = new AddressSet();
		autoCodeUnits = new AddressSet();

		pickedLatestCodeUnits = new AddressSet();
		pickedMyCodeUnits = new AddressSet();
		pickedOriginalCodeUnits = new AddressSet();

		conflictBytes = new AddressSet();
		conflictCodeUnits = new AddressSet();
		conflictByteCU = new AddressSet();
		conflictCUByte = new AddressSet();
		conflictByteEquate = new AddressSet();
		conflictEquateByte = new AddressSet();
		conflictEquateCU = new AddressSet();
		conflictCUEquate = new AddressSet();
		conflictRefCU = new AddressSet();
		conflictCURef = new AddressSet();

		resultUninitSet = ProgramMemoryUtil.getAddressSet(resultPgm, false);

		conflictAll = new AddressSet(); // All the conflicting addresses.
		ranges = new AddressRange[0]; // Each range for the manual merge.
		manualSet = new AddressSet(); // Expanded set of all conflicts

		mergeMy = listingMergeMgr.mergeMy;
		mergeLatest = listingMergeMgr.mergeLatest;
		mergeOriginal = listingMergeMgr.mergeOriginal;

		myResolvedDts = (Map<Long, DataType>) mergeManager.getResolveInformation(
			MergeConstants.RESOLVED_MY_DTS);
		origResolvedDts = (Map<Long, DataType>) mergeManager.getResolveInformation(
			MergeConstants.RESOLVED_ORIGINAL_DTS);

		mergedCodeUnits = new AddressSet();

		if (mergeManager != null) {
			mergeManager.setResolveInformation(MergeConstants.RESOLVED_CODE_UNITS, mergedCodeUnits);
			mergeManager.setResolveInformation(MergeConstants.PICKED_LATEST_CODE_UNITS,
				pickedLatestCodeUnits);
			mergeManager.setResolveInformation(MergeConstants.PICKED_MY_CODE_UNITS,
				pickedMyCodeUnits);
			mergeManager.setResolveInformation(MergeConstants.PICKED_ORIGINAL_CODE_UNITS,
				pickedOriginalCodeUnits);
		}
	}

	@Override
	public boolean apply() {
		int selectedChoice = getSelectedOption(conflictPanel);

		// If the "Use For All" check box is selected
		// then save the option chosen for this conflict type.
		if (conflictPanel.getUseForAll()) {
			conflictChoice = selectedChoice;
		}

		return super.apply();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#getConflictType()
	 */
	@Override
	public String getConflictType() {
		return "Byte / Code Unit";
	}

	/**
	 * For JUnit testing only, set the option for resolving a conflict.
	 * @param decision CANCELED, ASK_USER, LATEST, MY, ORIGINAL
	 */
	void setConflictDecision(int decision) {
		switch (decision) {
			case CANCELED:
			case ASK_USER:
			case KEEP_MY:
			case KEEP_LATEST:
			case KEEP_ORIGINAL:
				conflictOption = decision;
				break;
			default:
				throw new IllegalArgumentException();
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#autoMerge(ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void autoMerge(int progressMin, int progressMax, TaskMonitor monitor)
			throws ProgramConflictException, MemoryAccessException, CancelledException {

		initializeAutoMerge("Auto-merging Bytes and Code Units and determining conflicts.",
			progressMin, progressMax, monitor);

		monitor.setMessage("Setting up Code Unit merge.");

		updateProgress(0, "Finding conflicting byte changes...");
		getByteSets(monitor); // Direct byte conflicts

		updateProgress(15, "Finding conflicting code unit changes...");
		getCodeUnitSets(monitor); // Direct Code Unit conflicts

		updateProgress(30,
			"Finding conflicts between bytes, code units, equates and references...");
		getIndirectConflicts(monitor); // Indirect conflicts between bytes, code units, equates, and references.

		conflictAll = new AddressSet(conflictCodeUnits);
		conflictAll.add(conflictBytes);
		conflictAll.add(conflictByteCU);
		conflictAll.add(conflictCUByte);
		conflictAll.add(conflictByteEquate);
		conflictAll.add(conflictEquateByte);
		conflictAll.add(conflictEquateCU);
		conflictAll.add(conflictCUEquate);
		conflictAll.add(conflictRefCU);
		conflictAll.add(conflictCURef);

		updateProgress(45, "Aligning conflict ranges...");
		// Align the conflict ranges between the Latest, My, and Original programs.
		ranges = getManualMergeRanges(conflictAll); // This also sets "manualSet".
		AddressSet sameCodeUnitChanges = bothChangedCUSet.subtract(conflictCodeUnits);
		autoCodeUnits = myCUSet.subtract(sameCodeUnitChanges).subtract(manualSet);
		autoBytes = myByteSet.subtract(manualSet);
		if (monitor.isCancelled()) {
			throw new CancelledException();
		}

		updateProgress(60, "Auto-merging byte, code unit, and equate changes...");
		performAutoMerge(monitor); // 3 Auto-Merges (bytes, code units, equates)

		updateProgress(100, "Done auto-merging Bytes and Code Units and determining conflicts.");
	}

	private void getCodeUnitSets(TaskMonitor monitor)
			throws ProgramConflictException, CancelledException {
		monitor.setMessage("Getting Code Unit change sets.");
		ProgramDiffFilter cuFilter = new ProgramDiffFilter(ProgramDiffFilter.CODE_UNIT_DIFFS);
		myCUSet = diffOriginalMy.getDifferences(cuFilter, monitor);
		myCUSet = SimpleDiffUtility.expandAddressSetToIncludeFullDelaySlots(myPgm, myCUSet);
		updateProgress(20);
		latestCUSet = diffOriginalLatest.getDifferences(cuFilter, monitor);
		latestCUSet =
			SimpleDiffUtility.expandAddressSetToIncludeFullDelaySlots(latestPgm, latestCUSet);
		updateProgress(25);
		bothChangedCUSet = myCUSet.intersect(latestCUSet);
		AddressSetView latestMyCUSet =
			diffLatestMy.getTypeDiffs(ProgramDiffFilter.CODE_UNIT_DIFFS, bothChangedCUSet, monitor);
		conflictCodeUnits = new AddressSet(latestMyCUSet);
	}

	private void getByteSets(TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Getting Byte change sets.");
		ProgramDiffFilter byteFilter = new ProgramDiffFilter(ProgramDiffFilter.BYTE_DIFFS);
// TODO: !!! Eliminate instruction locations in result program from byte sets !!!
		myByteSet = diffOriginalMy.getDifferences(byteFilter, monitor);
		latestByteSet = diffOriginalLatest.getDifferences(byteFilter, monitor);
		MergeUtilities.adjustSets(latestByteSet, myByteSet, autoBytes, conflictBytes);
		conflictBytes = new AddressSet(diffLatestMy.getDifferences(byteFilter, monitor));
	}

	private AddressRange[] getManualMergeRanges(AddressSet conflictSet) {
		ArrayList<AddressRange> list = new ArrayList<AddressRange>();
		Listing latestListing = latestPgm.getListing();
		Listing myListing = myPgm.getListing();
		Listing originalListing = originalPgm.getListing();
		Listing listings[] = new Listing[] { latestListing, myListing, originalListing };
		// Create address ranges based on alignment between versions.
		AddressRangeIterator iter = conflictSet.getAddressRanges();
		while (iter.hasNext()) {
			AddressRange range = iter.next();
			if (manualSet.contains(range.getMinAddress(), range.getMaxAddress())) {
				continue;
			}
			Address nextRangeMin = range.getMinAddress();
			Address finalMax = range.getMaxAddress();
			while (nextRangeMin.compareTo(finalMax) <= 0) {
				Address rangeMin = backwardToCommon(listings, nextRangeMin);
				Address rangeMax = forwardToCommon(listings, nextRangeMin);
				if (rangeMin == null || rangeMax == null) {
					throw new RuntimeException(
						"Null rangeMin or rangeMax getting manual merge ranges.");
				}
				nextRangeMin = rangeMax.add(1L);
				AddressRange addRange = new AddressRangeImpl(rangeMin, rangeMax);
				list.add(addRange);
				manualSet.add(addRange);
			}
		}
		return list.toArray(new AddressRange[list.size()]);
	}

	/**
	 * Code units are compared between the indicated listings starting at the
	 * indicated address. The listings are searched in reverse address order
	 * until the address is found where all the listings have a code unit
	 * with the same minimum address.
	 * @param listings the program listings in the order LATEST, MY, ORIGINAL.
	 * @param start the address to start at.
	 * @return the common address where code units begin for all listings or null.
	 */
	private Address backwardToCommon(Listing[] listings, Address start) {
		CodeUnitIterator iter = listings[0].getCodeUnits(start, false);
		while (iter.hasNext()) {
			boolean matches = true;
			CodeUnit cu = iter.next();
			if (cu instanceof Instruction) {
				Instruction checkInstr = (Instruction) cu;
				while (checkInstr != null && checkInstr.isInDelaySlot() && iter.hasNext()) {
					cu = iter.next();
					if (cu instanceof Instruction) {
						checkInstr = (Instruction) cu;
					}
					else {
						checkInstr = null;
					}
				}
			}
			Address addr = cu.getMinAddress();
			for (int i = 1; i < listings.length; i++) {
				CodeUnit checkCU = listings[i].getCodeUnitAt(addr);
				if (checkCU == null) {
					matches = false;
					break;
				}
				if (checkCU instanceof Instruction) {
					Instruction checkInstr = (Instruction) checkCU;
					if (checkInstr.isInDelaySlot()) {
						matches = false;
						break;
					}
				}
			}
			if (matches) {
				return addr;
			}
		}
		return null;
	}

	/**
	 * Code units are compared between the indicated listings starting at the
	 * indicated address. The listings are searched in forward address order
	 * until the address is found where all the listings have a code unit
	 * with the same maximum address.
	 * @param listings the program listings in the order LATEST, MY, ORIGINAL.
	 * @param start the address to start at.
	 * @return the common address where code units end for all listings or null.
	 */
	private Address forwardToCommon(Listing[] listings, Address start) {
		CodeUnit realCU = listings[0].getCodeUnitContaining(start);
		if (realCU == null) {
			return null;
		}
		Address realStart = realCU.getMinAddress();
		CodeUnitIterator iter = listings[0].getCodeUnits(realStart, true);
		while (iter.hasNext()) {
			boolean matches = true;
			CodeUnit cu = iter.next();
			Address addr = cu.getMaxAddress();
			if (cu instanceof Instruction) {
				Instruction checkInstr = (Instruction) cu;
				int delaySlotDepth;
				if (checkInstr.isInDelaySlot()) {
					// unexpected - but lets handle it anyway
					delaySlotDepth = computeRemainingDelaySlots(checkInstr);
				}
				else {
					delaySlotDepth = checkInstr.getDelaySlotDepth();
				}
				while (delaySlotDepth != 0 && iter.hasNext()) {
					cu = iter.next();
					addr = cu.getMaxAddress();
					--delaySlotDepth;
				}
			}
			for (int i = 1; i < listings.length; i++) {
				CodeUnit checkCU = listings[i].getCodeUnitContaining(addr);
				if (checkCU == null) {
					break;
				}
				if (checkCU instanceof Instruction) {
					// make sure we consume delay-slotted instruction group
					Instruction checkInstr = (Instruction) checkCU;
					if (checkInstr.isInDelaySlot() || checkInstr.getDelaySlotDepth() != 0) {
						checkCU = findLastDelaySlot(checkInstr);
					}
				}
				if (!checkCU.getMaxAddress().equals(addr)) {
					matches = false;
					break;
				}
			}
			if (matches) {
				return addr;
			}
		}
		return null;
	}

	private int computeRemainingDelaySlots(Instruction instr) {

		if (!instr.isInDelaySlot()) {
			return instr.getDelaySlotDepth();
		}

		int count = 0;
		InstructionIterator iter =
			instr.getProgram().getListing().getInstructions(instr.getAddress(), false);
		iter.next(); // skip initial instr
		try {
			while (instr.isInDelaySlot() && iter.hasNext()) {
				Address prevAddr = instr.getMinAddress().subtractNoWrap(1);
				instr = iter.next();
				if (!prevAddr.equals(instr.getMaxAddress())) {
					Msg.error(this, "Missing delay-slotted instruction at " + prevAddr);
					return 0;
				}
			}
		}
		catch (AddressOverflowException e) {
			Msg.error(this, "Invalid delay-slot instruction at " + instr.getAddress());
			return 0;
		}
		return instr.getDelaySlotDepth() - count;
	}

	private Instruction findLastDelaySlot(Instruction instr) {
		Instruction lastInstr = instr;
		try {
			while (true) {
				Address nextAddr = lastInstr.getMaxAddress().addNoWrap(1);
				Instruction checkInstr = instr.getProgram().getListing().getInstructionAt(nextAddr);
				if (checkInstr == null || !checkInstr.isInDelaySlot()) {
					break;
				}
				lastInstr = checkInstr;
			}
		}
		catch (AddressOverflowException e) {
			// ignore
		}
		return lastInstr;
	}

	/**
	 * Merges all the current conflicts according to the conflictOption.
	 * @param listingPanel the listing merge panel
	 * @param chosenConflictOption the conflict option to use when merging (should be ASK_USER for interactive).
	 * @param monitor the status monitor
	 * @throws CancelledException if the user cancels
	 * @throws MemoryAccessException if bytes can't be merged.
	 */
	public void mergeConflicts(ListingMergePanel listingPanel, int chosenConflictOption,
			TaskMonitor monitor) throws CancelledException, MemoryAccessException {

		monitor.setMessage("Resolving Code Unit conflicts.");
		boolean askUser = (chosenConflictOption == ASK_USER);
		int totalConflicts = ranges.length;
		monitor.initialize(totalConflicts);
		for (int conflictIndex = 0; conflictIndex < totalConflicts; conflictIndex++) {
			AddressRange range = ranges[conflictIndex];
			Address rangeMin = range.getMinAddress();
			Address rangeMax = range.getMaxAddress();
			// If we have a byte/codeUnit/equate choice then a "Use For All" has already occurred.
			if (conflictChoice != ASK_USER) {
				merge(rangeMin, rangeMax, chosenConflictOption, monitor);
			}
			else {
				if (askUser && mergeManager != null) {
					conflictInfoPanel.setCodeUnitInfo(range, conflictIndex + 1, totalConflicts);
					conflictInfoPanel.setConflictInfo(1, 1);
					showMergePanel(listingPanel, rangeMin, rangeMax, monitor);
					monitor.checkCanceled();
					chosenConflictOption = getSelectedOption(conflictPanel);
					monitor.setMaximum(totalConflicts);
					monitor.setProgress(conflictIndex + 1);
				}
				else {
					merge(rangeMin, rangeMax, chosenConflictOption, monitor);
				}
			}
		}
	}

	private int getSelectedOption(ConflictPanel conflictPanel2) {
		int option = 0;
		int choice = conflictPanel2.getUseForAllChoice();
		switch (choice) {
			case 1:
				option = KEEP_LATEST;
				break;
			case 2:
				option = KEEP_MY;
				break;
			case 4:
				option = KEEP_ORIGINAL;
				break;
			default:
				option = ASK_USER;
				break;
		}
		return option;
	}

	private void showMergePanel(final ListingMergePanel listingPanel, final Address minAddress,
			final Address maxAddress, TaskMonitor monitor) {
		this.min = minAddress;
		this.currentAddress = minAddress;
		this.max = maxAddress;
		this.currentMonitor = monitor;
		try {
			final ChangeListener changeListener = new ChangeListener() {
				@Override
				public void stateChanged(ChangeEvent e) {
					ResolveConflictChangeEvent re = (ResolveConflictChangeEvent) e;
					int choice = re.getChoice();
					switch (choice) {
						case 1:
							conflictOption = KEEP_LATEST;
							break;
						case 2:
							conflictOption = KEEP_MY;
							break;
						case 4:
							conflictOption = KEEP_ORIGINAL;
							break;
						default:
							conflictOption = ASK_USER;
							break;
					}
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
						merge(CodeUnitMerger.this.min, CodeUnitMerger.this.max, conflictOption,
							currentMonitor);
					}
					catch (CancelledException ce) {
						// User cancelled.
					}
					catch (MemoryAccessException e1) {
						Msg.error(this, "Unexpected Exception: " + e1.getMessage(), e1);
					}
					if (mergeManager != null) {
						mergeManager.setApplyEnabled(true);
					}
				}
			};
			SwingUtilities.invokeAndWait(new Runnable() {
				@Override
				public void run() {
					if (conflictPanel != null) {
						conflictPanel.clear();
					}
					else {
						conflictPanel = new VariousChoicesPanel();
						currentConflictPanel = conflictPanel;
						conflictPanel.setTitle("Code Unit");
					}
					String text = getConflictString(minAddress, maxAddress);
					conflictPanel.setHeader(text);

					String latest = "'" + LATEST_TITLE + "' version";
					String my = "'" + MY_TITLE + "' version";
					String original = "'" + ORIGINAL_TITLE + "' version";
					conflictPanel.addSingleChoice("Use Code Unit From: ",
						new String[] { latest, my, original }, changeListener);

					boolean useForAll = (conflictChoice != ASK_USER);
					conflictPanel.setUseForAll(useForAll);
					conflictPanel.setConflictType("Byte / Code Unit");

					listingPanel.setBottomComponent(conflictPanel);
				}
			});
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					listingPanel.clearAllBackgrounds();
					listingPanel.paintAllBackgrounds(
						resultAddressFactory.getAddressSet(minAddress, maxAddress));
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

	protected String getConflictString(Address min2, Address max2) {
		StringBuffer buf = new StringBuffer();
		buf.append("Conflicting code units are defined in '" + LATEST_TITLE + "' and '" + MY_TITLE +
			"' from ");
		ConflictUtility.addAddress(buf, min2);
		buf.append(" to ");
		ConflictUtility.addAddress(buf, max2);
		buf.append(".");
		buf.append("<br>");
		StringBuffer conflictBuf = new StringBuffer();
		int count = 0;
		if (conflictBytes.intersects(min2, max2)) {
			conflictBuf.append("bytes"); // LatestByte MyByte in conflict
			count++;
		}
		if (conflictCodeUnits.intersects(min2, max2)) {
			conflictBuf.append(
				getConflictPrefix(conflictBuf) + "code units (including any overrides)");
			count++;
		}
		if ((conflictByteCU.intersects(min2, max2)) || (conflictCUByte.intersects(min2, max2))) {
			conflictBuf.append(
				getConflictPrefix(conflictBuf) + "byte versus code unit (including any overrides)");
			count++;
		}
		if ((conflictByteEquate.intersects(min2, max2)) ||
			(conflictEquateByte.intersects(min2, max2))) {
			conflictBuf.append(getConflictPrefix(conflictBuf) + "byte versus equate");
			count++;
		}
		if ((conflictEquateCU.intersects(min2, max2)) ||
			(conflictCUEquate.intersects(min2, max2))) {
			conflictBuf.append(getConflictPrefix(conflictBuf) +
				"equate versus code unit (including any overrides)");
			count++;
		}
		if ((conflictRefCU.intersects(min2, max2)) || (conflictCURef.intersects(min2, max2))) {
			conflictBuf.append(getConflictPrefix(conflictBuf) +
				"reference versus code unit (including any overrides)");
			count++;
		}
		if (conflictBuf.length() > 0) {
			buf.append("Conflicting change" + ((count > 1) ? "s are" : " is") + ": ");
			buf.append(conflictBuf);
			buf.append(".");
		}
		return buf.toString();
	}

	private String getConflictPrefix(StringBuffer conflictBuffer) {
		return (conflictBuffer.length() > 0) ? ", " : "";
	}

	private void performAutoMerge(TaskMonitor monitor)
			throws MemoryAccessException, CancelledException {

		monitor.setMessage("Merging Code Unit bytes.");
		// merge the bytes.
		mergeMy.mergeBytes(autoBytes.subtract(resultUninitSet), false, monitor);
		mergeManager.updateProgress(70);

		// merge the code units.
		// Note: For instructions, this may change some bytes that were auto-merged.
		totalChanges = 500;
		changeNum = 350;
		monitor.setMessage("Auto merging Code Units...");
		mergeCodeUnits(myPgm, autoCodeUnits, true, monitor);
		mergeManager.updateProgress(90);

		monitor.setMessage("Merging Code Unit equates.");
		mergeMy.mergeEquates(autoCodeUnits, monitor);
		mergeManager.updateProgress(100);
	}

	private void merge(Address minAddress, Address maxAddress, int chosenConflictOption,
			TaskMonitor monitor) throws MemoryAccessException, CancelledException {
		ProgramMerge pm = null;
		switch (chosenConflictOption) {
			case KEEP_LATEST:
				pm = mergeLatest;
				break;
			case KEEP_MY:
				pm = mergeMy;
				break;
			case KEEP_ORIGINAL:
				pm = mergeOriginal;
				break;
			default:
				return;
		}
		merge(pm, resultAddressFactory.getAddressSet(minAddress, maxAddress), monitor);
	}

	private void merge(ProgramMerge pm, AddressSet addrSet, TaskMonitor monitor)
			throws MemoryAccessException, CancelledException {
		mergeCodeUnits(pm.getOriginProgram(), addrSet, true, monitor);
		pm.mergeEquates(addrSet, monitor);
		// Add the references, since others were removed when the code unit was cleared initially
		// as it was merged.
		pm.replaceReferences(addrSet, monitor);
		monitor.setMessage("Resolving Code Unit conflicts.");
	}

	private void mergeProgramContext(ProgramContext resultContext, ProgramContext originContext,
			Register register, AddressRange addrRange, TaskMonitor monitor)
			throws CancelledException {
		try {
			AddressRangeIterator origValueIter = originContext.getRegisterValueAddressRanges(
				register, addrRange.getMinAddress(), addrRange.getMaxAddress());
			resultContext.remove(addrRange.getMinAddress(), addrRange.getMaxAddress(), register);
			while (origValueIter.hasNext()) {
				monitor.checkCanceled();
				AddressRange valueRange = origValueIter.next();
				RegisterValue value =
					originContext.getRegisterValue(register, valueRange.getMinAddress());
				if (value != null && value.hasAnyValue()) {
					resultContext.setRegisterValue(valueRange.getMinAddress(),
						valueRange.getMaxAddress(), value);
				}
			}
		}
		catch (ContextChangeException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
	}

	/*
	 * Note: equates and references may be removed by clearing the code units as we merge
	 *       to get the new code units.
	 */
	private void mergeCodeUnits(Program fromPgm, AddressSetView addrSet, boolean copyBytes,
			TaskMonitor monitor) throws MemoryAccessException, CancelledException {
		if (addrSet.isEmpty()) {
			return;
		}
		adjustCodeUnitPicked(fromPgm, addrSet);

		Listing resultListing = resultPgm.getListing();

		ProgramContext originContext = fromPgm.getProgramContext();
		ProgramContext resultContext = resultPgm.getProgramContext();
		Register contextReg = originContext.getBaseContextRegister();

		for (AddressRange range : addrSet) {

			// Clear any existing code units in the merged program
			// where this code unit needs to go.
			// May cause the merge code unit to lose info attached to it, such as references.
			resultListing.clearCodeUnits(range.getMinAddress(), range.getMaxAddress(), false);

			if (contextReg != null) {
				// Copy context register value
				mergeProgramContext(resultContext, originContext,
					originContext.getBaseContextRegister(), range, monitor);
			}
		}

		CodeUnitIterator sourceCodeUnits = fromPgm.getListing().getCodeUnits(addrSet, true);
		long totalAddresses = addrSet.getNumAddresses();
		long granularity = (totalAddresses / 100) + 1;
		int mergeProgress = 0;
		int mergeCount = 0;
		monitor.initialize(totalAddresses);
		// Get each code unit out of the iterator and set it in the merged
		// program if it is an instruction.
		while (sourceCodeUnits.hasNext()) {
			monitor.checkCanceled();
			CodeUnit cu = sourceCodeUnits.next();
			if (mergeCount > granularity) {
				monitor.setProgress(mergeProgress);
				incrementProgress(1);
				mergeCount = 0;
			}
			//monitor.setMessage("Replacing Code Unit @ " + cu.getMinAddress().toString());
			try {
				// create a new instruction or data.
				if (cu instanceof Instruction) {
					performMergeInstruction((Instruction) cu, true);
				}
				else if (cu instanceof Data) {
					performMergeData((Data) cu, copyBytes);
				}
			}
			catch (CodeUnitInsertionException exc) {
			}
			int increment =
				(int) (cu.getMaxAddress().getOffset() - cu.getMinAddress().getOffset() + 1);
			mergeProgress += increment;
			mergeCount += increment;
		}
	}

	/**
	 * @param fromPgm
	 * @param addrSet
	 */
	private void adjustCodeUnitPicked(Program fromPgm, AddressSetView addrSet) {
		mergedCodeUnits.add(addrSet);
		if (fromPgm == latestPgm) {
			pickedLatestCodeUnits.add(addrSet);
			pickedMyCodeUnits.delete(addrSet);
			pickedOriginalCodeUnits.delete(addrSet);
		}
		else if (fromPgm == myPgm) {
			pickedLatestCodeUnits.delete(addrSet);
			pickedMyCodeUnits.add(addrSet);
			pickedOriginalCodeUnits.delete(addrSet);
		}
		else if (fromPgm == originalPgm) {
			pickedLatestCodeUnits.delete(addrSet);
			pickedMyCodeUnits.delete(addrSet);
			pickedOriginalCodeUnits.add(addrSet);
		}
	}

	/**
	 * <CODE>performMergeInstruction</CODE> merges the indicated instruction
	 * into the result program. The bytes are also moved from the program
	 * if they differ. The flow override and fallthrough override will be set
	 * the same in the result program's instruction as they are in the instruction
	 * that is passed to this method.
	 *
	 * @param instruction the instruction to be merged
	 * @param copyBytes whether or not bytes should be copied if turned into
	 * an instruction.
	 * @throws CodeUnitInsertionException if the instruction can't be created
	 * in the merge program.
	 *
	 * @throws MemoryAccessException if bytes can't be copied.
	 */
	private void performMergeInstruction(Instruction instruction, boolean copyBytes)
			throws CodeUnitInsertionException, MemoryAccessException {
		Address minAddress = instruction.getMinAddress();
		Address maxAddress = instruction.getMaxAddress();
		Program fromPgm = instruction.getProgram();
		// Code unit should already be cleared where this instruction needs to go.
		Listing resultListing = resultPgm.getListing();

		// Copy the bytes if requested.
		if (copyBytes && !resultUninitSet.intersects(minAddress, maxAddress)) {
			ProgramMemoryUtil.copyBytesInRanges(resultPgm, fromPgm, minAddress, maxAddress);
		}

		Instruction inst = resultListing.createInstruction(minAddress, instruction.getPrototype(),
			new DumbMemBufferImpl(resultPgm.getMemory(), minAddress),
			new ProgramProcessorContext(resultPgm.getProgramContext(), minAddress));

		// Set the fallthrough override if necessary.
		if (instruction.isFallThroughOverridden()) {
			// override the fallthrough the same as it is in the one being merged.
			inst.setFallThrough(instruction.getFallThrough());
		}

		// Set the flow override if necessary.
		if (instruction.getFlowOverride() != FlowOverride.NONE) {
			inst.setFlowOverride(instruction.getFlowOverride());
		}
	}

	/**
	 * <CODE>performMergeData</CODE> merges the indicated defined data
	 * into the merge program. The bytes in the merge program are not affected
	 * by this method.
	 *
	 * @param data the defined data to be merged
	 * @param copyBytes whether or not bytes should be copied.
	 * @throws CodeUnitInsertionException if the defined data can't be created
	 * in the merge program.
	 */
	private void performMergeData(Data data, boolean copyBytes)
			throws CodeUnitInsertionException, MemoryAccessException {
		Address minAddress = data.getMinAddress();
		Address maxAddress = data.getMaxAddress();
		Program fromPgm = data.getProgram();
		DataType dt = data.getDataType();
		DataTypeManager fromDTM = fromPgm.getDataTypeManager();
		long dtID = fromDTM.getID(dt);
		if (!(dt instanceof BuiltInDataType)) {
			dt = (dt != DataType.DEFAULT) ? getResultDataType(dtID, fromPgm) : DataType.DEFAULT;
		}
		boolean hasNewData = false;
		Listing resultListing = resultPgm.getListing();

		if (copyBytes && !resultUninitSet.intersects(minAddress, maxAddress)) {
			ProgramMemoryUtil.copyBytesInRanges(resultPgm, fromPgm, minAddress, maxAddress);
		}
		if (!(dt.equals(DataType.DEFAULT))) {
			DataType tmpDt = dt;
			resultListing.createData(minAddress, tmpDt, data.getLength());
			hasNewData = true;
		}
		if (hasNewData) {
			Data newData = resultListing.getDataAt(minAddress);
			String[] settingNames = data.getNames();
			for (String settingName : settingNames) {
				Object obj = data.getValue(settingName);
				if (obj != null) {
					newData.setValue(settingName, obj);
				}
			}
		}
	}

	private DataType getResultDataType(long dtID, Program fromPgm) {
		DataType dt = null;
		if (fromPgm == myPgm) {
			dt = myResolvedDts.get(dtID);
			if (dt == null) {
				DataType origDt = originalPgm.getDataTypeManager().getDataType(dtID);
				if (origDt != null) {
					dt = resultPgm.getDataTypeManager().getDataType(dtID);
				}
			}
		}
		else if (fromPgm == latestPgm) {
			dt = resultPgm.getDataTypeManager().getDataType(dtID);
		}
		else if (fromPgm == originalPgm) {
			dt = origResolvedDts.get(dtID);
		}
		else if (fromPgm == resultPgm) {
			dt = resultPgm.getDataTypeManager().getDataType(dtID);
		}
		if (dt == null) {
			dt = fromPgm.getDataTypeManager().getDataType(dtID);
		}
		return dt;
	}

	/**
	 * Determines indirect code unit conflicts. This is anywhere that code unit
	 * changes to one program conflict with non-codeunit changes to the other
	 * program. The following non-codeunit changes conflict with code unit changes.
	 * <ul>
	 * <li>bytes</li>
	 * <li>equates</li>
	 * <li>references</li>
	 * </ul>
	 */

	private void getIndirectConflicts(TaskMonitor monitor) throws CancelledException {

		monitor.setMessage("Getting Byte changes.");
		AddressSet onlyMyBytesChanged = myByteSet.subtract(conflictBytes);
		AddressSet onlyLatestBytesChanged = latestByteSet.subtract(conflictBytes);

		monitor.setMessage("Getting Code Unit changes.");
		AddressSet onlyMyCUsChanged = myCUSet.subtract(bothChangedCUSet);
		AddressSet onlyLatestCUsChanged = latestCUSet.subtract(bothChangedCUSet);

		// Get Latest Code Unit & My Byte change conflicts.
		monitor.setMessage("Checking for conflicts between Byte & Code Unit changes.");
		conflictCUByte = onlyMyBytesChanged.intersect(onlyLatestCUsChanged);
		conflictCUByte = DiffUtility.getCodeUnitSet(conflictCUByte, latestPgm);
		// Get Latest Byte & My Code Unit change conflicts.
		conflictByteCU = onlyLatestBytesChanged.intersect(onlyMyCUsChanged);
		conflictByteCU = DiffUtility.getCodeUnitSet(conflictByteCU, myPgm);

		determineEquateConflicts(monitor, onlyMyBytesChanged, onlyLatestBytesChanged,
			onlyMyCUsChanged, onlyLatestCUsChanged);

		determineReferenceConflicts(monitor, onlyMyCUsChanged, onlyLatestCUsChanged);
	}

	private void determineEquateConflicts(TaskMonitor monitor, AddressSet onlyMyBytesChanged,
			AddressSet onlyLatestBytesChanged, AddressSet onlyMyCUsChanged,
			AddressSet onlyLatestCUsChanged) throws CancelledException {
		// Get EQUATE Diffs to check for conflicts with code units.
		monitor.setMessage("Getting Equate changes.");
		ProgramDiffFilter equateFilter = new ProgramDiffFilter(ProgramDiffFilter.EQUATE_DIFFS);
		AddressSetView latestEquateDiffs =
			this.diffOriginalLatest.getDifferences(equateFilter, monitor);
		AddressSetView myEquateDiffs = this.diffOriginalMy.getDifferences(equateFilter, monitor);

		// Get Latest Equate & My Byte change conflicts.
		monitor.setMessage("Checking for conflicts between Byte & Equate changes.");
		conflictEquateByte = onlyMyBytesChanged.intersect(latestEquateDiffs);
		conflictEquateByte = DiffUtility.getCodeUnitSet(conflictEquateByte, latestPgm);
		// Get Latest Byte & My Equate change conflicts.
		conflictByteEquate = onlyLatestBytesChanged.intersect(myEquateDiffs);
		conflictByteEquate = DiffUtility.getCodeUnitSet(conflictByteEquate, myPgm);

		// Get Latest Equate & My Code Unit change conflicts.
		monitor.setMessage("Checking for conflicts between Code Unit & Equate changes.");
		conflictEquateCU = onlyMyCUsChanged.intersect(latestEquateDiffs);
		conflictEquateCU = DiffUtility.getCodeUnitSet(conflictEquateCU, myPgm);
		// Get Latest Code Unit & My Equate change conflicts.
		conflictCUEquate = onlyLatestCUsChanged.intersect(myEquateDiffs);
		conflictCUEquate = DiffUtility.getCodeUnitSet(conflictCUEquate, latestPgm);
	}

	private void determineReferenceConflicts(TaskMonitor monitor, AddressSet onlyMyCUsChanged,
			AddressSet onlyLatestCUsChanged) throws CancelledException {
		// Get REFERENCE Diffs to check for conflicts with code units.
		monitor.setMessage("Getting Reference changes.");
		ProgramDiffFilter referenceFilter =
			new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS);
		AddressSetView latestRefDiffs =
			this.diffOriginalLatest.getDifferences(referenceFilter, monitor);
		AddressSetView myRefDiffs = this.diffOriginalMy.getDifferences(referenceFilter, monitor);

		// Get Latest Reference & My Code Unit change conflicts.
		monitor.setMessage("Checking for conflicts between Code Unit & Reference changes.");
		conflictRefCU = onlyMyCUsChanged.intersect(latestRefDiffs);
		conflictRefCU = DiffUtility.getCodeUnitSet(conflictRefCU, myPgm);
		// Get Latest Code Unit & My Reference change conflicts.
		conflictCURef = onlyLatestCUsChanged.intersect(myRefDiffs);
		conflictCURef = DiffUtility.getCodeUnitSet(conflictCURef, latestPgm);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#hasConflict(ghidra.program.model.address.Address)
	 */
	@Override
	public boolean hasConflict(Address addr) {
		return conflictAll.contains(addr);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#getConflictCount(ghidra.program.model.address.Address)
	 */
	@Override
	public int getConflictCount(Address addr) {
		return hasConflict(addr) ? 1 : 0;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#mergeConflicts(ghidra.app.merge.tool.ListingMergePanel, ghidra.program.model.address.Address, int, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void mergeConflicts(ListingMergePanel listingPanel, Address addr,
			int chosenConflictOption, TaskMonitor monitor)
			throws CancelledException, MemoryAccessException {
		throw new NotYetImplementedException(
			"CodeUnitMerger.mergeConflicts(ListingMergePanel listingPanel, Address addr, int conflictOption, TaskMonitor monitor) isn't implemented.");
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ListingMerger#getConflicts()
	 */
	@Override
	public AddressSetView getConflicts() {
		return conflictAll;
	}

}
