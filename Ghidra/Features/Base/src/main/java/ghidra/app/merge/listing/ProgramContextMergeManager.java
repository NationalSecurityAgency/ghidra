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

import java.util.*;

import ghidra.app.merge.MergeResolver;
import ghidra.app.merge.ProgramMultiUserMergeManager;
import ghidra.app.merge.tool.ListingMergePanel;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>ProgramContextMergeManager</code> merges register value changes 
 * for multi-user program versions. It merges changes for each named register
 * in the program.
 * <br>Note: If a register gets changed that is part of another register that has been set, 
 * then each named register will get merged independently. This means that 
 * when in conflict with another version the conflict would arise for each 
 * instead of just the larger register.
 */
public class ProgramContextMergeManager implements MergeResolver, ListingMergeConstants {

	private static String[] PROGRAM_CONTEXT_PHASE = new String[] { "Program Context" };
	private ProgramMultiUserMergeManager mergeManager;
	private ListingMergePanel mergePanel;
	private ConflictInfoPanel conflictInfoPanel; // This goes above the listing merge panels
	RegisterMergeManager rmm;

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
	TaskMonitor currentStatusMonitor;

	ProgramContext originalContext;
	ProgramContext latestContext;
	ProgramContext myContext;
	ProgramContext resultContext;
	List<Register> registers;

	/** Used to determine differences between the original program and latest program. */
	ProgramDiff diffOriginalLatest;
	/** Used to determine differences between the original program and my program. */
	ProgramDiff diffOriginalMy;
	ProgramDiffFilter diffFilter;
	ProgramMergeFilter mergeFilter;

	/**
	 * Creates a new <code>ProgramContextMergeManager</code>.
	 * @param resultPgm the program to be updated with the result of the merge.
	 * This is the program that will actually get checked in.
	 * @param originalPgm the program that was checked out.
	 * @param latestPgm the latest checked-in version of the program.
	 * @param myPgm the program requesting to be checked in.
	 * @param latestChanges the address set of changes between original and latest versioned program.  
	 * @param myChanges the address set of changes between original and my modified program.
	 */
	public ProgramContextMergeManager(ProgramMultiUserMergeManager mergeManager, Program resultPgm,
			Program originalPgm, Program latestPgm, Program myPgm, ProgramChangeSet latestChanges,
			ProgramChangeSet myChanges) {
		this.mergeManager = mergeManager;
		this.resultPgm = resultPgm;
		this.originalPgm = originalPgm;
		this.latestPgm = latestPgm;
		this.myPgm = myPgm;
		this.latestChanges = latestChanges;
		this.myChanges = myChanges;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#apply()
	 */
	@Override
	public void apply() {
		if (rmm != null) {
			rmm.apply();
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#cancel()
	 */
	@Override
	public void cancel() {
		if (rmm != null) {
			rmm.cancel();
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#getDescription()
	 */
	@Override
	public String getDescription() {
		return "Merge Program Context Registers";
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#getName()
	 */
	@Override
	public String getName() {
		return "Program Context Registers Merger";
	}

	/**
	 * Sets up the change address sets, Diffs between the various program versions,
	 * and Merges from various versions to the resulting program.
	 */
	private void initMergeInfo() {
		// Memory Merge may have limited the changed code units we are working with.
		AddressSetView resultSet = resultPgm.getMemory();
		this.latestSet = latestChanges.getRegisterAddressSet().intersect(resultSet);
		this.mySet = myChanges.getRegisterAddressSet().intersect(resultSet);

		originalContext = originalPgm.getProgramContext();
		latestContext = latestPgm.getProgramContext();
		myContext = myPgm.getProgramContext();
		resultContext = resultPgm.getProgramContext();

		registers = myContext.getRegisters();

		try {
			diffOriginalLatest = new ProgramDiff(originalPgm, latestPgm);
			diffOriginalMy = new ProgramDiff(originalPgm, myPgm);
			diffFilter = new ProgramDiffFilter(ProgramDiffFilter.PROGRAM_CONTEXT_DIFFS);

			mergeFilter =
				new ProgramMergeFilter(ProgramMergeFilter.PROGRAM_CONTEXT,
					ProgramMergeFilter.REPLACE);
		}
		catch (ProgramConflictException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
		catch (IllegalArgumentException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.MergeResolver#merge(ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void merge(TaskMonitor monitor) {
		mergeManager.setInProgress(PROGRAM_CONTEXT_PHASE);
		mergeManager.updateProgress(0, "Initializing merge of program context registers...");
		initMergeInfo();
		if (mergeManager != null) {
			mergePanel = mergeManager.getListingMergePanel();
			if (conflictInfoPanel == null) {
				conflictInfoPanel = new ConflictInfoPanel();
			}
			mergePanel.setTopComponent(conflictInfoPanel);
		}
		try {
			List<String> latestNames = latestContext.getRegisterNames();
			List<String> myNames = myContext.getRegisterNames();
			if (!latestNames.equals(myNames)) {
				mergeManager.setStatusText("Program Context Registers don't match between the programs.");
				cancel();
				return;
			}

			ArrayList<Register> regs = new ArrayList<>(latestContext.getRegisters());
			// Sort the registers by size so that largest come first.
			// This prevents the remove call below from incorrectly clearing 
			// smaller registers that are part of a larger register.
			Collections.sort(regs, new Comparator<Register>() {
				@Override
				public int compare(Register r1, Register r2) {
					return r2.getBitLength() - r1.getBitLength();
				}
			});

			int transactionID = resultPgm.startTransaction(getDescription());
			boolean commit = false;
			try {
				int numRegs = regs.size();
				monitor.initialize(numRegs);

				// Get the conflicts for each register
				for (int i = 0; i < numRegs; i++) {
					Register reg = regs.get(i);
					if (reg.isProcessorContext()) {
						continue; // context register handle by code unit merge
					}
					String regName = reg.getName();
					int currentProgressPercentage = (int) (((float) 100 / numRegs) * i);
					mergeManager.updateProgress(currentProgressPercentage,
						"Merging register values for " + regName);
					monitor.setProgress(i);
					monitor.checkCanceled();
					rmm =
						new RegisterMergeManager(regName, mergeManager, resultPgm, originalPgm,
							latestPgm, myPgm, latestChanges, myChanges);
					rmm.merge(monitor);
				}
				mergeManager.updateProgress(100, "Done merging program context registers...");

				commit = true;
			}
			catch (CancelledException e) {
				mergeManager.setStatusText("User cancelled merge.");
				cancel();
			}
			finally {
				resultPgm.endTransaction(transactionID, commit);
			}
		}
		finally {
			monitor = null;
		}
		mergeManager.setCompleted(PROGRAM_CONTEXT_PHASE);
	}

	/**
	 * For JUnit testing only, set the option for resolving a conflict.
	 * @param decision ASK_USER, PICK_LATEST, PICK_MY, or PICK_ORIGINAL
	 */
	void setConflictDecision(int decision) {
		if (decision == ASK_USER || decision == KEEP_LATEST || decision == KEEP_MY ||
			decision == KEEP_ORIGINAL) {
			if (rmm != null) {
				rmm.setConflictDecision(decision);
			}
		}
		else {
			throw new IllegalArgumentException();
		}
	}

	@Override
	public String[][] getPhases() {
		return new String[][] { PROGRAM_CONTEXT_PHASE };
	}

}
