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

import java.awt.Color;
import java.util.*;

import javax.swing.SwingUtilities;

import ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin;
import ghidra.app.plugin.core.instructionsearch.model.InstructionMetadata;
import ghidra.app.plugin.core.instructionsearch.ui.SearchDirectionWidget.Direction;
import ghidra.app.services.GoToService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.util.BytesFieldLocation;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Task to perform a search from the {@link InstructionSearchDialog}, returning the NEXT or 
 * PREVIOUS result found, depending on the search direction.
 * <p>
 * This class searches for a single result within the appropriate search ranges (or the entire
 * program if that option is selected). It's optimized to ignore ranges that are "out of scope"; 
 * ie: if searching in the forward direction from a certain address, any ranges prior to that
 * address will be ignored.
 * 
 */
class SearchInstructionsTask extends Task {

	private InstructionSearchDialog searchDialog;
	private InstructionSearchPlugin searchPlugin;

	/**
	 * Constructor. 
	 * 
	 * @param dialog the parent dialog
	 * @param plugin the parent plugin
	 */
	SearchInstructionsTask(InstructionSearchDialog dialog, InstructionSearchPlugin plugin) {
		super("Searching Program Text", true, true, false);
		this.searchDialog = dialog;
		this.searchPlugin = plugin;
	}

	@Override
	public void run(TaskMonitor taskMonitor) {
		if (taskMonitor == null) {
			return;
		}

		// First get all the search ranges we have to search.  
		List<AddressRange> searchRanges =
			searchDialog.getControlPanel().getRangeWidget().getSearchRange();

		// Get the current cursor location - we'll always start searching from here. 
		Address currentAddr = searchPlugin.getProgramLocation().getByteAddress();

		// See if we're searching forward or backwards.
		boolean forward =
			searchDialog.getControlPanel().getDirectionWidget().getSearchDirection().equals(
				Direction.FORWARD);

		// If we're searching backwards we need to process address ranges in reverse so reverse
		// the list.
		if (!forward) {
			Collections.reverse(searchRanges);
		}

		// Keep track of the range number we're processing, just for display purposes.
		int rangeNum = 0;

		// Now loop over the ranges, searching each in turn.
		for (AddressRange range : searchRanges) {

			rangeNum++;

			// Now, depending on our current cursor location, we may not have to search all of the
			// ranges. ie: if our cursor is beyond the bounds of a range and we're searching in 
			// the forward direction.
			if (forward) {
				if (currentAddr.compareTo(range.getMaxAddress()) >= 0) {
					continue;
				}
			}
			else {
				if (currentAddr.compareTo(range.getMinAddress()) <= 0) {
					continue;
				}
			}

			if (searchRanges.size() > 1) {
				taskMonitor.setMessage(
					"Searching range " + rangeNum + " of " + searchRanges.size());
			}
			else {
				taskMonitor.setMessage("Searching...");
			}

			// And SEARCH.
			InstructionMetadata searchResults =
				searchDialog.getSearchData().search(searchPlugin, range, taskMonitor, forward);

			// If there are results, move the cursor there, otherwise keep looping and check
			// the next range.
			//
			// Note we put these on the swing thread or it will throw off the task monitor display.
			if (searchResults != null) {
				SwingUtilities.invokeLater(() -> {
					goToLocation(searchResults.getAddr());
					searchDialog.getMessagePanel().clear();
				});

				return;
			}

			continue;
		}

		// If we've gone through all the ranges and there are still no results, show an 
		// error message.
		searchDialog.getMessagePanel().setMessageText("No results found", Color.BLUE);
		return;

	}

	/**
	 * Moves the cursor in the listing to the next search result past, or before (depending on 
	 * the given direction) the current address.
	 * 
	 * @param direction the direction to search (forward/backward)
	 * @param searchResults the list of instructions to search
	 * @return the address of the next result found
	 */
	public Address getNextAddress(Direction direction, List<InstructionMetadata> searchResults) {

		Address currentAddress = searchPlugin.getProgramLocation().getByteAddress();

		// If forward-searching, just find the first address in the given result set that is
		// greater than the current address.  
		//
		// The reason for the getting the CodeUnit is that the instruction might be an off-cut, 
		// and if that's the case, then we can't navigate directly to it.  What we have to do 
		// is find the CodeUnit containing the instruction and navigate to that.
		if (direction == Direction.FORWARD) {
			for (InstructionMetadata instr : searchResults) {
				CodeUnit unit = searchPlugin.getCurrentProgram().getListing().getCodeUnitContaining(
					instr.getAddr());

				if (unit.getMinAddress().compareTo(currentAddress) > 0) {
					return unit.getMinAddress();
				}
			}
		}

		// If backwards, iterate over the list in reverse order and find the first address in
		// the result set that is one less than the current address. 
		//
		// See above for an explanation for why we need to get the CodeUnit in this block.
		if (direction == Direction.BACKWARD) {
			ListIterator<InstructionMetadata> iter =
				searchResults.listIterator(searchResults.size());
			while (iter.hasPrevious()) {
				InstructionMetadata instr = iter.previous();
				CodeUnit unit = searchPlugin.getCurrentProgram().getListing().getCodeUnitContaining(
					instr.getAddr());
				if (unit.getMinAddress().compareTo(currentAddress) < 0) {
					return unit.getMinAddress();
				}
			}
		}

		return null;
	}

	private void goToLocation(Address addr) {
		GoToService gs = searchPlugin.getTool().getService(GoToService.class);
		BytesFieldLocation bloc = new BytesFieldLocation(searchPlugin.getCurrentProgram(), addr);
		gs.goTo(bloc);
	}
}
