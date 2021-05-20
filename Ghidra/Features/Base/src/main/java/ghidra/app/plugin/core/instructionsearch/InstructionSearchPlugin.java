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
package ghidra.app.plugin.core.instructionsearch;

import java.awt.Color;
import java.util.HashSet;
import java.util.Set;

import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.instructionsearch.ui.InstructionSearchDialog;
import ghidra.app.services.GoToService;
import ghidra.app.util.query.TableService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorComponent;

/**
 * Plugin allowing users to construct search criteria based on a set of selected
 * instructions.
 * 
 * Note: There's a bug here that is supposed to be fixed under JIRA ticket
 * #2024. When a user switches programs we need to clear out the current
 * instructions in the GUI; this works fine. However, if the user then hits the
 * refresh button to load any selected instructions in the new program, nothing
 * will be loaded because no selection event was generated on the program
 * activation. This problem will be resolved when that bug is fixed.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.SEARCH,
	shortDescription = "Allows users to construct instruction search patterns",
	description = "Provides a component for showing a selected set of instructions. " +
			"Users can mask any operands and/or mnemonics to produce a search" +
			" pattern, which can be used to find similar instruction sets" +
			" in the current program.",
	servicesRequired = { TableService.class, GoToService.class }
)
//@formatter:on
public class InstructionSearchPlugin extends ProgramPlugin {

	final static String SEARCH_ACTION_NAME = "Search Instruction Patterns";

	private TaskMonitor taskMonitor;

	private DockingAction searchAction;

	private final String DIALOG_TITLE = "Instruction Pattern Search";

	// Maximum number of instructions allowed in a selection. This is an arbitrary limit
	// but should be high enough to satisfy any reasonable requirement.
	private int MAX_SELECTION_SIZE = 500;

	private InstructionSearchDialog searchDialog;

	/**
	 * Constructor.
	 * 
	 * @param tool the plugin tool
	 */
	public InstructionSearchPlugin(PluginTool tool) {
		super(tool, true, true);

		// Creates the menu actions used with this plugin.
		createActions();
	}

	public InstructionSearchDialog getSearchDialog() {
		return searchDialog;
	}

	/*********************************************************************************************
	 * PROTECTED METHODS
	 ********************************************************************************************/

	@Override
	protected void init() {
		taskMonitor = new TaskMonitorComponent();
	}

	/*********************************************************************************************
	 * PRIVATE METHODS
	 ********************************************************************************************/

	/**
	 * Checks the selection made by the user to make sure it is within
	 * acceptable bounds regarding size and number of ranges.
	 *
	 * @param selection the user selection
	 * @param dialog the parent dialog
	 * @return true if the selection is valid
	 */
	public boolean isSelectionValid(ProgramSelection selection, InstructionSearchDialog dialog) {

		// Users should not call this will a null selection but we need to check just in case.
		if (selection == null) {
			return false;
		}

		// First clear out the message panel if anything was being displayed there because of a
		// previous search.
		dialog.clearMessage();

		// Users can't select multiple regions or pick a region larger than MAX_SELECTION_SIZE, so
		// immediately return and display an error message if they do.
		if (selection.getNumAddresses() == 0) {
			dialog.displayMessage(
				"Select instructions from the listing (and hit reload) to populate the table.",
				Color.BLUE);
			return false;
		}
		if (!isSelectionSizeValid(selection)) {
			dialog.displayMessage("Invalid selection.  Cannot select more than " +
				MAX_SELECTION_SIZE + " instructions and/or data items.", Color.RED);
			return false;
		}

		try {
			if (isSelectionRangeValid(selection)) {
				return true;
			}
		}
		catch (InvalidInputException e) {
			dialog.displayMessage(e.getMessage(), Color.RED);
			return false;
		}

		return true;
	}

	/**
	 * Returns the number of instructions (and data) in the selection.
	 * 
	 * @param program the current program
	 * @param selection the program selection
	 * @return number of instructions in the selection
	 */
	private int getNumInstructionsInSelection(Program program, ProgramSelection selection) {

		// First get the addresses in the selection;
		AddressRangeIterator addressRanges = selection.getAddressRanges();

		// Keep track of the number of instructions we find.  
		int numInstructions = 0;

		// Loop over all the addresses, getting all code units and checking to see which ones
		// are instructions.  For those that are, increment our counter.
		while (addressRanges.hasNext()) {
			AddressRange range = addressRanges.next();
			AddressSet addrSet = new AddressSet(range);
			CodeUnitIterator cuIter = program.getListing().getCodeUnits(addrSet, true);

			while (cuIter.hasNext()) {
				CodeUnit cu = cuIter.next();
				if ((cu instanceof Instruction) || (cu instanceof Data)) {
					numInstructions++;
				}
			}
		}

		return numInstructions;
	}

	/**
	 * Returns true if the number of instructions selected is less or equal to
	 * MAX_SELECTION_SIZE.
	 * 
	 * @param selection the program selection
	 * @return true if the selection size is valid
	 */
	private boolean isSelectionSizeValid(ProgramSelection selection) {
		int numInstructionsInSelection =
			getNumInstructionsInSelection(getCurrentProgram(), selection);

		return numInstructionsInSelection <= MAX_SELECTION_SIZE;
	}

	/**
	 * Returns true if the user has selected one and only one range of
	 * instructions.
	 * 
	 * If there are multiple ranges, this could be for two reasons: 1) the user
	 * has (via the mouse) selected more than one set of address ranges, or 2)
	 * the user selects a single region but that region spans memory blocks;
	 * this would be interpreted by the program as being 2 distinct selection
	 * ranges. In both of these cases, we throw an exception with a message that
	 * the caller can log if desired.
	 * 
	 * @param selection the program selection
	 * @return true if the selection range is valid
	 * @throws InvalidInputException
	 */
	private boolean isSelectionRangeValid(ProgramSelection selection) throws InvalidInputException {
		Set<String> blockNames = new HashSet<>();
		AddressRangeIterator iter = selection.getAddressRanges();
		while (iter.hasNext()) {
			AddressRange range = iter.next();
			Address addr = range.getMinAddress();
			MemoryBlock block = getCurrentProgram().getMemory().getBlock(addr);
			blockNames.add(block.getName());
		}
		if (blockNames.size() > 1) {
			throw new InvalidInputException("Selection range cannot span memory blocks");
		}

		if (selection.getNumAddressRanges() > 1) {
			throw new InvalidInputException("Selection cannot contain multiple address ranges");
		}
		return selection.getNumAddressRanges() == 1;
	}

	private void createActions() {
		searchAction = new NavigatableContextAction(SEARCH_ACTION_NAME, getName()) {
			@Override
			public void actionPerformed(NavigatableActionContext context) {
				showSearchDialog(context);
			}

			@Override
			protected boolean isEnabledForContext(NavigatableActionContext context) {
				return !(context instanceof RestrictedAddressSetContext);
			}

		};
		searchAction.addToWindowWhen(NavigatableActionContext.class);
		searchAction.setHelpLocation(new HelpLocation("Search", "Instruction_Pattern_Search"));
		searchAction.setMenuBarData(
			new MenuData(new String[] { ToolConstants.MENU_SEARCH, "For Instruction Patterns" },
				null, "search for"));
		searchAction.setDescription("Construct searches using selected instructions");
		tool.addAction(searchAction);
	}

	/**
	 * Creates a new instruction search dialog and displays it, loading any
	 * instructions that have been selected.
	 * 
	 * @param context the navigatable context
	 */
	private void showSearchDialog(NavigatableActionContext context) {
		searchDialog = new InstructionSearchDialog(this, DIALOG_TITLE, taskMonitor);
		searchDialog.showDialog(context.getComponentProvider());
	}

	@Override
	protected void programActivated(Program program) {
		if (searchDialog != null) {
			searchDialog.clear();
		}
	}
}
