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
package ghidra.app.plugin.core.disassembler;

import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

import java.util.NoSuchElementException;

import docking.action.MenuData;

class SetFlowOverrideAction extends ListingContextAction {

	private DisassemblerPlugin plugin;

	public SetFlowOverrideAction(DisassemblerPlugin plugin, String groupName) {
		super("Modify Instruction Flow", plugin.getName());
		this.plugin = plugin;
		setPopupMenuData(new MenuData(new String[] { "Modify Instruction Flow..." }, null,
			groupName));
	}

	@Override
	public void actionPerformed(ListingActionContext context) {

		PluginTool tool = plugin.getTool();
		SetFlowOverrideDialog dialog;

		ProgramSelection selection = context.getSelection();
		if (selection != null && !selection.isEmpty()) {

			try {
				if (!isValidInstructionSelection(context.getProgram(), selection)) {
					Msg.showError(this, tool.getActiveWindow(), "Invalid Flow-Override Selection",
						"Flow Override action does not permit multiple flow instructions within each selection range");
					return;
				}
			}
			catch (CancelledException e) {
				return;
			}
			catch (NoSuchElementException e) {
				Msg.showError(this, tool.getActiveWindow(), "Invalid Flow-Override Selection",
					"No instructions found within selection");
				return;
			}

			dialog = new SetFlowOverrideDialog(tool, context.getProgram(), selection);
		}
		else {
			Address address = context.getAddress();
			if (address == null) {
				return;
			}
			Instruction instr = context.getProgram().getListing().getInstructionAt(address);
			if (instr == null) {
				return;
			}

			dialog = new SetFlowOverrideDialog(tool, instr);
		}
		tool.showDialog(dialog);
	}

	private boolean isValidInstructionSelection(Program program, ProgramSelection selection)
			throws NoSuchElementException, CancelledException {

		OverrideSelectionInspector inspectionTask =
			new OverrideSelectionInspector(program, selection);
		new TaskLauncher(inspectionTask, null, 500);

		return inspectionTask.isValidSelection();
	}

	private class OverrideSelectionInspector extends Task {

		final AddressSet targetSet = new AddressSet();

		private boolean invalidRangeFound = false;
		private boolean cancelled = false;
		private Program program;
		private ProgramSelection selection;

		OverrideSelectionInspector(Program program, ProgramSelection selection) {
			super("Flow Override", true, true, true);
			this.program = program;
			this.selection = selection;
		}

		@Override
		public void run(TaskMonitor monitor) {
			monitor.setMessage("Inspecting Selection...");
			monitor.initialize(selection.getNumAddressRanges());
			Listing listing = program.getListing();
			int runningRangeTotal = 0;
			int currentRangeTotal = 0;
			for (AddressRange range : selection.getAddressRanges()) {
				if (monitor.isCancelled()) {
					cancelled = true;
					break;
				}
				runningRangeTotal += currentRangeTotal;
				currentRangeTotal = 0;
				Address minAddr = range.getMinAddress();
				Address maxAddr = range.getMaxAddress();

				boolean flowFound = false;
				for (Instruction instr : listing.getInstructions(minAddr, true)) {
					if (monitor.isCancelled()) {
						cancelled = true;
						break;
					}
					if (instr.getAddress().compareTo(maxAddr) > 0) {
						break;
					}
					currentRangeTotal = (int) instr.getAddress().subtract(minAddr) + 1;
					if (!instr.getFlowType().isFallthrough()) {
						if (flowFound) {
							Msg.error(this, "Invalid flow-override range found at " + minAddr);
							invalidRangeFound = true;
							return;
						}
						flowFound = true;
						targetSet.add(instr.getAddress());
					}
					monitor.setProgress(runningRangeTotal + currentRangeTotal);
				}
			}
		}

		boolean isValidSelection() throws NoSuchElementException, CancelledException {
			if (invalidRangeFound) {
				return false;
			}
			if (cancelled) {
				throw new CancelledException();
			}
			if (targetSet.isEmpty()) {
				throw new NoSuchElementException("No flow instructions found in selection");
			}
			return true;
		}
	}

	@Override
	public boolean isEnabledForContext(ListingActionContext context) {
		ProgramSelection selection = context.getSelection();
		if (selection != null && !selection.isEmpty()) {
			return true;
		}

		Address address = context.getAddress();
		if (address == null) {
			return false;
		}
		Instruction instr = context.getProgram().getListing().getInstructionAt(address);
		if (instr == null) {
			return false;
		}
		return !instr.isFallthrough();
	}

}
