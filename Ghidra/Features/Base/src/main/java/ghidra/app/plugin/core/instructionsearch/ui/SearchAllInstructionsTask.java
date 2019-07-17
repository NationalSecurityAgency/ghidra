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
package ghidra.app.plugin.core.instructionsearch.ui;

import java.util.ArrayList;
import java.util.List;

import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin;
import ghidra.app.plugin.core.instructionsearch.model.InstructionMetadata;
import ghidra.program.model.address.AddressRange;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Task to perform a search for instruction patterns over a set of instruction ranges. This task
 * searches for ALL results and displays them in a separate table.
 * 
 */
class SearchAllInstructionsTask extends Task {

	private InstructionSearchDialog searchDialog;
	private InstructionSearchPlugin searchPlugin;

	/**
	 * Constructor
	 * 
	 * @param searchDialog the search dialog
	 * @param searchPlugin the instruction search plugin
	 */
	SearchAllInstructionsTask(InstructionSearchDialog searchDialog,
			InstructionSearchPlugin searchPlugin) {
		super("Searching Program Text", true, true, false);
		this.searchDialog = searchDialog;
		this.searchPlugin = searchPlugin;
	}

	@Override
	public void run(TaskMonitor monitor) {
		if (monitor == null) {
			return;
		}

		// Just show percentage complete in the pop-up.
		monitor.setShowProgressValue(false);

		List<InstructionMetadata> results = doSearch(monitor);

		// If the search finished without being cancelled, just show the results. If it was 
		// cancelled, prompt the user for confirmation and to give them the option of seeing any
		// results which have been collected thus far.
		if (!monitor.isCancelled()) {
			searchDialog.displaySearchResults(results);
		}
		else {
			if (results.isEmpty()) {
				return;
			}
			int option = OptionDialog.showYesNoDialog(searchDialog.getFocusComponent(),
				"Results found!", results.size() + " match(es) found. View results?");

			if (option == OptionDialog.YES_OPTION) {
				searchDialog.displaySearchResults(results);
			}
		}
	}

	/**
	 * Execute a memory search using the current settings in the dialog, returning the results.
	 * 
	 * @param taskMonitor the task monitor
	 * @return list of instruction matches
	 */
	public List<InstructionMetadata> doSearch(TaskMonitor taskMonitor) {

		// First get all the search ranges we have to search.  
		List<AddressRange> searchRanges =
			searchDialog.getControlPanel().getRangeWidget().getSearchRange();

		// Now set up a list to hold all the search results.  
		List<InstructionMetadata> retList = new ArrayList<InstructionMetadata>();

		// Loop over all ranges, performing a separate search on each of them.  We keep track of 
		// the range number so we can display it to the user in progress window.
		int rangeNum = 1;
		for (AddressRange range : searchRanges) {

			// First reset the progress bar for this range.
			taskMonitor.setProgress(0);
			taskMonitor.setMaximum(range.getLength());

			if (searchRanges.size() > 1) {
				taskMonitor.setMessage(
					"Searching range " + rangeNum + " of " + searchRanges.size());
			}
			else {
				taskMonitor.setMessage("Searching...");
			}

			// Now perform the search and add the results to our list.
			List<InstructionMetadata> meta = searchDialog.getSearchData().search(
				searchPlugin.getCurrentProgram(), range, taskMonitor);
			retList.addAll(meta);

			// Increment the range counter.
			rangeNum++;
		}

		return retList;
	}
}
