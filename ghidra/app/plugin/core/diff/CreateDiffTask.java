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
package ghidra.app.plugin.core.diff;

import javax.swing.SwingUtilities;

import ghidra.framework.model.DomainObjectException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.ClosedException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Task that generates the address set containing the differences between
 * two programs. 
 * 
 */
class CreateDiffTask extends Task {
	private ProgramDiffPlugin plugin;
	private Program program1;
	private Program program2;
	private AddressSetView limitedAddressSet;
	private ProgramDiffFilter diffFilter;
	private ProgramMergeFilter applyFilter;
	private DiffApplySettingsProvider diffApplySettingsProvider;
	private boolean isLimitedToSelection;

	/**
	 * Construct new LoadDiffTask that loads the dialog with the two 
	 * programs and indicates their differences. The differences should be 
	 * restricted to the limitedAddressSet. 
	 * 
	 */
	CreateDiffTask(ProgramDiffPlugin plugin, Program program1, Program program2,
			AddressSetView limitedAddressSet, boolean isLimitedToSelection,
			ProgramDiffFilter diffFilter, ProgramMergeFilter applyFilter) {
		super("Checking Program Differences", true, false, false);
		this.plugin = plugin;
		this.program1 = program1;
		this.program2 = program2;
		this.limitedAddressSet = limitedAddressSet;
		this.isLimitedToSelection = isLimitedToSelection;
		this.diffFilter = diffFilter;
		this.applyFilter = applyFilter;
	}

	/** 
	 * This is the method TaskMonitor called to do the work.
	 * 
	 * @param monitor The TaskMonitor that will monitor the executing Task.  Will be null if
	 * 		  this task declared that it does not use a TaskMonitor
	 */
	@Override
	public void run(TaskMonitor monitor) {
		if (plugin.isTaskInProgress()) {
			return;
		}

		try {
			DiffController dc = null;
			plugin.setTaskInProgress(true);
			monitor.setIndeterminate(true);
			monitor.setMessage("Checking Program Differences");
			try {
				dc = new DiffController(program1, program2, limitedAddressSet, this.diffFilter,
					this.applyFilter, monitor);
				AddressSetView filteredDifferences = dc.getFilteredDifferences(monitor);
				boolean noFilteredDifferencesFound = filteredDifferences.isEmpty();
				plugin.setDiffController(dc);
				dc.differencesChanged(monitor);
				dc.setLocation(plugin.getCurrentAddress());
				monitor.setMessage("Done");
				Runnable r = () -> displayDifferencesMessageIfNecessary(noFilteredDifferencesFound);
				SwingUtilities.invokeLater(r);
			}
			catch (DomainObjectException e) {
				Throwable cause = e.getCause();
				if (cause instanceof ClosedException) {
					// this can happen if you close the tool while this task is calculating diffs
				}
				else {
					throw e;
				}
			}
			catch (ProgramConflictException e) {
				showErrorMessage(e.getMessage());
				return;
			}
			catch (CancelledException e) {
				plugin.setDiffController(dc);
			}
		}
		finally {
			completed();
		}
	}

	private void displayDifferencesMessageIfNecessary(final boolean noFilteredDifferencesFound) {

		try {
			ProgramMemoryComparator programMemoryComparator =
				new ProgramMemoryComparator(program1, program2);
			boolean hasMemoryDifferences = programMemoryComparator.hasMemoryDifferences();

			String title = null;
			String message = null;

			if (isLimitedToSelection) {
				if (noFilteredDifferencesFound) {
					title = "No Differences In Selection";
					message = "No differences were found for the addresses in the selection" +
						"\nand for the types of program information being compared by this Diff.";
				}
			}
			else {
				if (hasMemoryDifferences) {
					title = "Memory Differs";
					message = getMemoryDifferenceMessage(noFilteredDifferencesFound,
						programMemoryComparator);
				}
				else if (noFilteredDifferencesFound) {
					// Not a Diff on a selection, memory is the same, and no differences found 
					// for current filter and compatible addresses.
					title = "No Differences";
					message =
						"No differences were found for the addresses that are compatible between the two" +
							"\nprograms for the types of program information being compared by this Diff.";
				}
			}
			if (title != null) {
				String note =
					"\n \nNote: Some parts of the program are not handled by Diff (for example:" +
						"\n         Markup where only one program has that memory address," +
						"\n         Registers that are not common to both programs' languages," +
						"\n         Program Trees, Data Types that haven't been applied to memory, etc.)";

				Msg.showInfo(getClass(), plugin.getListingPanel(), title, message + note);
			}
		}
		catch (ProgramConflictException e) {
			Msg.showError(getClass(), plugin.getListingPanel(), "Can't Compare Memory",
				"Diff can't compare the two programs memory. " + e.getMessage());
			return;
		}
	}

	private String getMemoryDifferenceMessage(final boolean noFilteredDifferencesFound,
			ProgramMemoryComparator programMemoryComparator) {
		String message;
		message = "The memory addresses defined by the two programs are not the same.\n \n" +
			(noFilteredDifferencesFound ? "However, no differences were found "
					: "Differences are highlighted ") +
			"for the addresses that are compatible between" +
			"\nthe two programs for the types of program information being compared by this Diff.";

		AddressSet addressesOnlyInOne = programMemoryComparator.getAddressesOnlyInOne();
		if (!addressesOnlyInOne.isEmpty()) {
			message +=
				"\n \nSome addresses are only in program 1 : " + addressesOnlyInOne.toString();
		}

		AddressSet addressesOnlyInTwo = programMemoryComparator.getAddressesOnlyInTwo();
		if (!addressesOnlyInTwo.isEmpty()) {
			message +=
				"\n \nSome addresses are only in program 2 : " + addressesOnlyInTwo.toString();
		}
		return message;
	}

	private void showErrorMessage(String message) {
		SystemUtilities.runSwingLater(() -> Msg.showError(getClass(),
			plugin.getTool().getToolFrame(), "Can't Perform Diff", message));
	}

	private void completed() {
		if (plugin.isDisposed()) {
			// the tool was closed while this task was running
			return;
		}

		if (plugin.getCurrentProgram() == null) {
			// the program was closed while this task was running
			return;
		}

		SystemUtilities.runSwingLater(() -> {
			diffApplySettingsProvider = plugin.getDiffApplySettingsProvider();
			diffApplySettingsProvider.configure(applyFilter);
			plugin.adjustDiffDisplay();
		});

		plugin.setTaskInProgress(false);
	}
}
