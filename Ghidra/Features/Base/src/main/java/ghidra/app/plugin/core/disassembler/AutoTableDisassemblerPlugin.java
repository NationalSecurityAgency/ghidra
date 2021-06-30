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
package ghidra.app.plugin.core.disassembler;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.widgets.table.GTable;
import docking.widgets.table.threaded.ThreadedTableModelListener;
import ghidra.app.CorePluginPackage;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.app.util.HelpTopics;
import ghidra.app.util.PseudoDisassembler;
import ghidra.framework.cmd.CompoundBackgroundCommand;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.*;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.SEARCH,
	shortDescription = "Search for Address Tables",
	description = "This plugin identifies possible 32-bit address tables and" +
			" allows the user to disassemble starting at address references" +
			" in the table. The search is done on the entire program or a selection.",
	servicesRequired = { GoToService.class }
)
//@formatter:on
public class AutoTableDisassemblerPlugin extends ProgramPlugin implements DomainObjectListener {

	private AddressTableDialog addressTableDialog;
	private AutoTableDisassemblerModel model;

	private boolean automaticLabel;
	private int offsetLen;
	private DockingAction findTableAction;
	final static String SEARCH_ACTION_NAME = "Search for Address Tables";

	public AutoTableDisassemblerPlugin(PluginTool tool) {
		super(tool, true, true);
	}

	@Override
	protected void init() {
		createActions();
	}

	Program getProgram() {
		return currentProgram;
	}

	private void startDialog() {
		int size = currentProgram.getAddressFactory().getDefaultAddressSpace().getSize();
		if (size != 32 && size != 64 && size != 24) {
			Msg.showWarn(getClass(), null, "Search For Address Tables",
				"Cannot search for Address tables on " + size + "-bit memory!");
			return;
		}

		if (addressTableDialog == null) {
			model = new AutoTableDisassemblerModel(tool, this);
			addressTableDialog = new AddressTableDialog(this);
			addressTableDialog.setHasSelection(currentSelection != null);
		}

		if (addressTableDialog.isVisible()) {
			addressTableDialog.toFront();
		}
		else {
			tool.showDialog(addressTableDialog);
		}
	}

	void dialogDismissed() {

		addressTableDialog.dispose();
		addressTableDialog = null;
		if (model != null) {
			model.dispose();
			model = null;
		}
	}

	int getMinimumTableSize() {
		return addressTableDialog.getMinTableSize();
	}

	int getAlignment() {
		return addressTableDialog.getAlignment();
	}

	int getSkipLength() {
		return addressTableDialog.getSkipLength();
	}

	boolean isShiftAddresses() {
		return addressTableDialog.getShiftedAddresses();
	}

	AddressSetView getSelection() {

		if (!addressTableDialog.isSearchSelection()) {
			return currentProgram.getMemory();
		}

		return currentSelection;
	}

	private void createActions() {
		findTableAction = new DockingAction(SEARCH_ACTION_NAME, getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				startDialog();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return currentProgram != null;
			}
		};
		findTableAction.setHelpLocation(
			new HelpLocation(HelpTopics.SEARCH, findTableAction.getName()));
		findTableAction.setMenuBarData(new MenuData(
			new String[] { ToolConstants.MENU_SEARCH, "For Address Tables" }, null, "search for"));
		findTableAction.setDescription(getPluginDescription().getDescription());
		findTableAction.addToWindowWhen(NavigatableActionContext.class);
		tool.addAction(findTableAction);

	} // end of createActions()

	void findTablesInSet(GTable table, boolean searchSelection) {

		if (searchSelection && (currentSelection == null || currentSelection.isEmpty())) {
			addressTableDialog.setDialogText("Please make a selection to search.");
			return;
		}

		int minimumTableSize = addressTableDialog.getMinTableSize();
		if (minimumTableSize < 2) {
			addressTableDialog.setDialogText(
				"Please enter a valid minimum search length. Must be >= 2");
			return;
		}

		int alignment = addressTableDialog.getAlignment();
		if (alignment <= 0 || alignment > 8) {
			addressTableDialog.setDialogText(
				"Please enter a valid alignment value. Must be > 0 and <= 8");
			return;
		}

		addressTableDialog.enableSearchButton(false);

		model.addInitialLoadListener(new ThreadedTableModelListener() {

			@Override
			public void loadPending() {
				// don't care
			}

			@Override
			public void loadingStarted() {
				// don't care
			}

			@Override
			public void loadingFinished(boolean wasCancelled) {
				if (addressTableDialog != null) {
					addressTableDialog.searchComplete(wasCancelled);
				}
			}
		});

		model.reload();
	}

	// do this when the Disassemble button is selected
	void disassembleTable(int[] selectedRows) {
		if ((currentProgram == null) || (currentLocation == null)) {
			return;
		}

		// if addresses are selected in the list - put them in the array
		Address[] selectedAddresses = new Address[selectedRows.length];
		for (int i = 0; i < selectedRows.length; i++) {
			selectedAddresses[i] = model.getAddress(selectedRows[i]);
		}

		CompoundBackgroundCommand backCmd =
			new CompoundBackgroundCommand("Disassemble Address Tables", false, true);
		offsetLen = addressTableDialog.getOffset();

		// loop over selected table addresses
		for (int i = 0; i < selectedRows.length; i++) {
			Address currentAddress = selectedAddresses[i];
			if (model.containsKey(currentAddress)) {
				createDisassemblyCommandsForAddress(backCmd, currentAddress);
			}
		}
		if (backCmd.isEmpty()) {
			Msg.showError(this, addressTableDialog.getComponent(),
				"Disassemble Address Tables Failed", "No undefined/aligned code units were found");
			return;
		}

		tool.executeBackgroundCommand(backCmd, currentProgram);
	}

	private void createDisassemblyCommandsForAddress(CompoundBackgroundCommand backCmd,
			Address currentAddress) {

		Listing listing = currentProgram.getListing();
		int align = currentProgram.getLanguage().getInstructionAlignment();

		AddressTable addrTable = model.get(currentAddress);
		Address[] elements = addrTable.getTableElements();
		for (int i = offsetLen; i < elements.length; i++) {
			Address addr = elements[i];

			// check the normalized address where disassembly will actually occur
			Address targetAddr =
				PseudoDisassembler.getNormalizedDisassemblyAddress(currentProgram, addr);
			if ((targetAddr.getOffset() % align) != 0) {
				continue; // not aligned
			}

			if (listing.getUndefinedDataAt(targetAddr) == null) {
				continue;
			}

			// need to create a context for each one.  Also disassembleCmd will align the address to disassemble
			DisassembleCommand disassembleCmd = new DisassembleCommand(addr, null, true);
			RegisterValue rval = PseudoDisassembler.getTargetContextRegisterValueForDisassembly(
				currentProgram, addr);
			disassembleCmd.setInitialContext(rval);
			backCmd.add(disassembleCmd);
		}
	}

	// does this when the make table button is selected
	void makeTable(int[] selectedRows) {

		if (currentProgram == null) {
			return;
		}

		if (!validateSelectionOffsets()) {
			return;
		}

		SystemUtilities.assertTrue(selectedRows.length > 0,
			"Cannot make address " + "tables when the find dialog's table contains no selection");

		automaticLabel = addressTableDialog.getAutomaticLabel();

		Address[] selectedAddresses = new Address[selectedRows.length];
		for (int i = 0; i < selectedRows.length; i++) {
			selectedAddresses[i] = model.getAddress(selectedRows[i]);
		}

		MakeTablesTask task = new MakeTablesTask(selectedAddresses);
		addressTableDialog.executeProgressTask(task, 500);
	}

	private int makeTables(Address[] addresses, TaskMonitor monitor) {

		monitor.initialize(addresses.length);
		monitor.setMessage("Make Address Tables...");

		int collisionCount = 0;

		for (int i = 0; i < addresses.length; i++) {
			if (monitor.isCancelled()) {
				break;
			}
			Address currentAddress = addresses[i];
			AddressTable addrTable = model.get(currentAddress);
			if (addrTable == null) {
				continue;
			}
			monitor.setProgress(i);
			boolean madeTable = addrTable.makeTable(currentProgram, offsetLen,
				addrTable.getNumberAddressEntries(), automaticLabel);
			if (!madeTable) {
				++collisionCount;
			}
		}
		return collisionCount;
	}

	/**
	 * @see ghidra.app.plugin.ProgramPlugin#programDeactivated(Program)
	 */
	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(this);

		if (addressTableDialog != null) {
			addressTableDialog.close();
		}
	}

	/**
	 * @see ghidra.app.plugin.ProgramPlugin#programActivated(Program)
	 */
	@Override
	protected void programActivated(Program program) {
		program.addListener(this);
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (model == null) {
			return;
		}

		if (addressTableDialog.isRunningTask()) {
			return;
		}

		refreshModel();
	}

	private void refreshModel() {
		if (addressTableDialog == null) {
			// can happen if we dispose while there is a task running
			return;
		}

		model.refresh();
	}

	/**
	 * @see ghidra.app.plugin.ProgramPlugin#selectionChanged(ProgramSelection)
	 */
	@Override
	protected void selectionChanged(ProgramSelection sel) {
		if (addressTableDialog != null) {
			addressTableDialog.setHasSelection(!(sel == null || sel.isEmpty()));
		}
	}

	void updateOffsetString(int[] selectedRows) {
		if (addressTableDialog == null) {
			return;
		}

		// now rows selected, disable and exit
		if (selectedRows.length <= 0) {
			addressTableDialog.clearMakeTableOptions();
			return;
		}

		if (!validateSelectionOffsets()) {
			return;
		}

		// make sure the options are enabled when there is a selection
		addressTableDialog.setEnableMakeTableOptions(true);

		// if there is only one row, then put the address at that row in the offset text field
		String offsetText = " ";
		int offset = addressTableDialog.getOffset();

		if (selectedRows.length == 1) {
			Address addr = model.getAddress(selectedRows[0]);
			Address addressWithOffset = addr.addWrap(offset * 4);
			offsetText = addressWithOffset.toString();
		}

		offsetLen = offset;
		addressTableDialog.setDialogText("");
		addressTableDialog.setOffsetText(offsetText);
	}

	boolean validateSelectionOffsets() {
		int[] selectedRows = addressTableDialog.getSelectedRows();
		int shortestAddressTableRow = getIndexOfShortestAddressTable(selectedRows);
		Address addr = model.getAddress(selectedRows[shortestAddressTableRow]);
		int offset = addressTableDialog.getOffset();
		AddressTable addrTable = model.get(addr);
		int len = 0;
		if (addrTable != null) {
			len = addrTable.getTableElements().length;
		}

		if (offset >= 0 && offset < len) {
			return true; // offset is in range
		}

		// bad offset
		addressTableDialog.setEnableMakeTableButtons(false);
		String dialogText =
			"Invalid offset length - check table length, " + "must be >= 0 and < " + len;
		addressTableDialog.setDialogText(dialogText);
		addressTableDialog.setOffsetText("");
		offsetLen = 0;

		return false;
	}

	// change the max allows offset to be the length-1 of the smallest 
	// address table in the selected rows
	private int getIndexOfShortestAddressTable(int[] selectedRows) {

		if (selectedRows.length < 0) {
			throw new AssertionError(
				"There must be rows selected in " + "order to process multiple rows.");
		}

		int shortestRowIndex = selectedRows[0];
		int shortestLength = Integer.MAX_VALUE;
		for (int i = 0; i < selectedRows.length; i++) {
			int row = selectedRows[i];
			int length = model.getTableLength(row);
			if (length < shortestLength) {
				shortestLength = length;
				shortestRowIndex = i;
			}
		}

		return shortestRowIndex;
	}

	private class MakeTablesTask extends Task {

		private Address[] addresses;
		private int collisionCount;
		private String collisionMessage = "Address Table(s) could not be created due to " +
			"collisions with existing\ndata. Check the Address Table for those tables not created.";

		private MakeTablesTask(Address[] addresses) {
			super("Make Tables", true, true, false);
			this.addresses = addresses;
		}

		@Override
		public void run(final TaskMonitor monitor) {
			Program program = currentProgram;
			int transactionID = program.startTransaction("Make Address Table");
			boolean commit = false;
			try {
				collisionCount = makeTables(addresses, monitor);
				commit = true;
			}
			catch (Exception e) {
				if (!(e instanceof DomainObjectException)) {
					Msg.showError(this, null, null, null, e);
				}
			}
			finally {
				program.endTransaction(transactionID, commit);
			}

			SystemUtilities.runSwingLater(() -> {

				AddressTableDialog tempDialog = addressTableDialog;
				if (tempDialog == null) {
					return; // closed/disposed
				}

				tempDialog.makeTablesCompleted();
				if (collisionCount > 0) {
					Msg.showWarn(getClass(), tempDialog.getComponent(),
						"Collisions while Making Tables", collisionMessage);
				}

				refreshModel();
			});
		}

	}

	AutoTableDisassemblerModel getModel() {
		return model;
	}
}
