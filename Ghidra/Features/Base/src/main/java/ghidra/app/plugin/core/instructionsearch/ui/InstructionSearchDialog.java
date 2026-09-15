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

import java.awt.BorderLayout;
import java.awt.Color;
import java.util.*;

import javax.swing.*;

import docking.ComponentProvider;
import docking.ReusableDialogComponentProvider;
import generic.theme.GColor;
import generic.theme.GThemeDefaults.Colors.Messages;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin;
import ghidra.app.plugin.core.instructionsearch.model.InstructionMetadata;
import ghidra.app.plugin.core.instructionsearch.model.InstructionSearchData;
import ghidra.app.plugin.core.instructionsearch.model.InstructionSearchData.UpdateType;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.services.GoToService;
import ghidra.app.util.HelpTopics;
import ghidra.app.util.query.TableService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.*;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.table.AddressArrayTableModel;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

/**
 * The GUI component for the {@link InstructionSearchPlugin}.
 */
public class InstructionSearchDialog extends ReusableDialogComponentProvider implements Observer {

	private static final Color BG_COLOR_MARKERS =
		new GColor("color.bg.plugin.instructionsearch.search.markers");

	// Panel containing the {@link InstructionTable} and {@link PreviewTable}.
	private InstructionSearchMainPanel tablePanel;

	// Panel containing widgets for applying search criteria.
	private ControlPanel controlPanel;

	// Panel for displaying error messages.
	private MessagePanel messagePanel;

	// The parent plugin object.
	private InstructionSearchPlugin plugin;

	private JButton searchAllButton;

	protected InstructionSearchData searchData;

	/**
	 * Constructor
	 *
	 * @param plugin the instruction search plugin
	 * @param title the title of the dialog
	 * @param taskMonitor the task monitor
	 */
	public InstructionSearchDialog(InstructionSearchPlugin plugin, String title,
			TaskMonitor taskMonitor) {

		super(title, false, true, true, true);
		this.plugin = plugin;
		this.messagePanel = new MessagePanel();

		setHelpLocation(new HelpLocation(HelpTopics.SEARCH, "Instruction_Pattern_Search"));

		// First create a data model for the dialog.
		searchData = new InstructionSearchData();

		// Add ourselves as an observer of the model so when it changes we can update the UI.
		searchData.addObserver(this);

		try {
			revalidate();
			loadInstructions();
		}
		catch (InvalidInputException e) {
			Msg.error(this, "Error loading instructions: " + e);
		}
	}

	public InstructionSearchData getSearchData() {
		return searchData;
	}

	/**
	 * Loads the currently-selected set of instructions in the listing and displays them in
	 * the given dialog.
	 *
	 * @throws InvalidInputException if there's a problem loading instructions
	 */
	public void loadInstructions() throws InvalidInputException {
		loadInstructions(plugin.getProgramSelection());
	}

	/**
	 * Loads the instructions in the given selection and displays them in the gui.
	 *
	 * @param selection the current selection
	 */
	public void loadInstructions(ProgramSelection selection) {

		MessagePanel msg = getMessagePanel();
		if (selection == null && msg != null) {
			msg.setMessageText(
				"Select instructions from the listing (and hit reload) to populate the table.",
				Messages.NORMAL);
			return;
		}

		if (plugin.isSelectionValid(selection, this)) {

			ControlPanel panel = getControlPanel();
			if (panel != null) {
				SelectionScopeWidget rangeWidget = panel.getRangeWidget();
				rangeWidget.updateSearchRangeBySelection();
			}

			// Load the instructions, but note that we only allow a single selection range.  If
			// there's more than one we will process the FIRST one, and display a warning message.
			populateSearchData(plugin.getCurrentProgram(), selection);
		}
	}

	/**
	 * Adds the instructions in the given selection and displays them in the gui.
	 *
	 * @param selection the current selection
	 */
	public void addToInstructions(ProgramSelection selection) {

		MessagePanel msg = getMessagePanel();
		if (selection == null && msg != null) {
			msg.setMessageText(
				"Select instructions from the listing (and hit add) to update the table.",
				Messages.NORMAL);
		}

		if (selection != null && plugin.isSelectionValid(selection, this)) {
			addToSearchData(plugin.getCurrentProgram(), selection);
		}
	}

	/**
	 * Loads instructions at the given program/selection and populates the search
	 * data object.
	 *
	 * @param currentProgram the current program
	 * @param selection the current selection
	 */
	public void populateSearchData(Program currentProgram, ProgramSelection selection) {

		if (selection == null || currentProgram == null) {
			return;
		}

		try {
			getSearchData().load(currentProgram, selection.getFirstRange());
		}
		catch (InvalidInputException e) {
			Msg.error(this, "Error loading new search data", e);
		}
	}

	private void addToSearchData(Program currentProgram, ProgramSelection selection) {

		if (selection == null || currentProgram == null) {
			return;
		}

		try {
			getSearchData().add(currentProgram, selection);
		}
		catch (InvalidInputException e) {
			Msg.error(this, "Error adding to search data", e);
		}
	}

	public ControlPanel getControlPanel() {
		return controlPanel;
	}

	public MessagePanel getMessagePanel() {
		return this.messagePanel;
	}

	public InstructionTablePanel getTablePanel() {
		if (tablePanel != null) {
			return tablePanel.getInstructionTablePanel();
		}

		return null;
	}

	public PreviewTablePanel getPreviewTablePanel() {
		if (tablePanel != null) {
			return tablePanel.getPreviewTablePanel();
		}
		return null;
	}

	/**
	 * Displays this dialog.
	 *
	 * @param provider the component provider
	 */
	public void showDialog(ComponentProvider provider) {
		clearStatusText();
		PluginTool tool = plugin.getTool();
		tool.showDialog(InstructionSearchDialog.this, provider);
	}

	/**
	 * Loads the given bytes into the manual entry field and populates the instruction table.
	 *
	 * @param bytes binary or hex string
	 */
	public void loadBytes(String bytes) {
		tablePanel.getInstructionTable().getInsertBytesWidget().loadBytes(bytes);
	}

	/**
	 * Loads the bytes found at the given address set, in whatever program is currently loaded.
	 *
	 * @param addrSet the address of the bytes to load
	 */
	public void loadBytes(AddressSet addrSet) {

		// Create a selection object based on the address set given.
		ProgramSelection selection =
			new ProgramSelection(addrSet.getMinAddress(), addrSet.getMaxAddress());

		plugin.firePluginEvent(new ProgramSelectionPluginEvent(plugin.getName(), selection,
			plugin.getCurrentProgram()));

		Swing.runLater(() -> {

			goToLocation(selection.getMinAddress());

			try {
				loadInstructions(selection);
			}
			catch (Exception e) {
				Msg.error(this, "Error loading instructions", e);
			}
		});
	}

	/**
	 * Clears any text in the message panel.
	 */
	public void clearMessage() {
		if (messagePanel == null) {
			return;
		}

		messagePanel.clear();
	}

	/**
	 * Clears out all instructions in the dialog.
	 */
	public void clear() {
		getSearchData().clearAndReload();
	}

	void deleteInstruction(int index) {
		InstructionSearchData data = getSearchData();
		InstructionTablePanel panel = getTablePanel();
		InstructionTable table = panel.getTable();
		data.deleteInstruction(table, index);
	}

	/**
	 * Displays a message with the given text and color (severity).
	 *
	 * @param message the message to display
	 * @param status the severity of the message
	 */
	public void displayMessage(String message, Color status) {
		if (messagePanel == null) {
			return;
		}

		messagePanel.setMessageText(message, status);
	}

	/**
	 * Invoked whenever the data model changes; when this happens we need to rebuild the
	 * UI to reflect the new instruction set, or simply update the preview panel in the case
	 * where the user has simply changed the model by toggling masks.
	 */
	@SuppressWarnings("deprecation")
	@Override
	public void update(Observable o, Object arg) {
		if (arg instanceof UpdateType) {
			UpdateType type = (UpdateType) arg;
			switch (type) {
				case RELOAD:
					revalidate();
					break;
				case UPDATE:
					tablePanel.buildPreview();
					break;
			}
		}
	}

	/*********************************************************************************************
	 * PROTECTED METHODS
	 ********************************************************************************************/

	/**
	 * Updates the GUI when the user has made a new selection.  For simplicity, this
	 * removes the entire work panel and recreates it with the new instructions.
	 */
	protected void revalidate() {
		removeExistingGuiComponents();
		createGuiComponents();
	}

	@Override
	protected void applyCallback() {
		searchButtonActionPerformed();
	}

	protected JPanel createWorkPanel() {

		// Create the main panel; use a border layout so all components
		// will adjust to fill the given space, allocating all leftover
		// space to the central tables.
		JPanel mainPanel = new JPanel();
		mainPanel.setLayout(new BorderLayout());

		// Create the table panel, which contains both the instruction and
		// preview tables.
		tablePanel = new InstructionSearchMainPanel(plugin, this);
		mainPanel.add(tablePanel, BorderLayout.CENTER);

		JPanel lowerPanel = new JPanel();
		lowerPanel.setLayout(new BoxLayout(lowerPanel, BoxLayout.Y_AXIS));

		// Create the control panel, which contains the options for
		// searching the whole program or the current selection.
		if (controlPanel == null) {
			controlPanel = new ControlPanel(plugin, this);
		}
		controlPanel.getAccessibleContext().setAccessibleName("Control");
		messagePanel.getAccessibleContext().setAccessibleName("Message");
		lowerPanel.add(controlPanel);
		lowerPanel.add(messagePanel);
		lowerPanel.getAccessibleContext().setAccessibleName("Control and Message");
		mainPanel.add(lowerPanel, BorderLayout.SOUTH);
		mainPanel.getAccessibleContext().setAccessibleName("Instruction Search");
		return mainPanel;
	}

	/*********************************************************************************************
	 * PRIVATE METHODS
	 ********************************************************************************************/

	private void createGuiComponents() {
		addWorkPanel(createWorkPanel());
		createButtons();

		if (tablePanel == null) {
			return;
		}
		tablePanel.buildPreview();
		tablePanel.revalidate();

		// Now, if there were new instructions added to the table, enable the search button.  This
		// is here in the case where the user selects something in the listing that contains
		// no instructions.  If that's the case, nothing will be in the table so the search
		// button should be disabled.
		if (applyButton == null || searchAllButton == null) {
			return;
		}
		applyButton.setEnabled(tablePanel.getPreviewTable().getRowCount() > 0);
		searchAllButton.setEnabled(tablePanel.getPreviewTable().getRowCount() > 0);
	}

	/**
	 * Removes the working panel and any buttons on the GUI.
	 */
	private void removeExistingGuiComponents() {
		removeWorkPanel();
		if (applyButton != null) {
			removeButton(applyButton);
		}
		if (cancelButton != null) {
			removeButton(cancelButton);
		}
		if (searchAllButton != null) {
			removeButton(searchAllButton);
		}
	}

	/**
	 * Creates the search, search all, and cancel buttons at the bottom of the gui.
	 */
	private void createButtons() {

		addApplyButton();
		applyButton.setText("Search");

		searchAllButton = new JButton("Search All");
		searchAllButton.addActionListener(ev -> searchAllButtonActionPerformed());
		searchAllButton.setName("Search All");
		searchAllButton.getAccessibleContext().setAccessibleName("Search All");
		addButton(searchAllButton);

		addCancelButton();
	}

	/**
	 * Invoked when the search button is clicked.
	 */
	private void searchButtonActionPerformed() {

		// First clear out anything on the message panel.
		messagePanel.clear();

		// Now create a task to perform the search.
		SearchInstructionsTask searchTask = new SearchInstructionsTask(this, plugin);
		new TaskLauncher(searchTask, getFocusComponent());
	}

	/**
	 * Performs a search and displays all results in a separate window.
	 */
	private void searchAllButtonActionPerformed() {

		if (messagePanel == null || tablePanel == null || plugin == null) {
			return;
		}

		// Clear out any messages that might be in the panel.
		messagePanel.clear();
		searchData.applyMasks(tablePanel.getInstructionTable());

		// And create a task to perform the search.
		SearchAllInstructionsTask searchTask = new SearchAllInstructionsTask(this, plugin);
		new TaskLauncher(searchTask, getFocusComponent());
	}

	public void displaySearchResults(List<InstructionMetadata> searchResults) {

		TableService ts = plugin.getTool().getService(TableService.class);
		if (ts == null) {
			Msg.error(null, "Unable to show addresses, no table service available");
			return;
		}

		Address[] tableArray = new Address[searchResults.size()];
		for (int i = 0; i < searchResults.size(); i++) {
			tableArray[i] = searchResults.get(i).getAddr();
		}

		// The results window can be set to allow selection of multiple search results,
		// provided the results are all the same size.  This should be the case for us and
		// as we're matching bytes, the size should always be divisible by 8.  But do a check
		// anyway.
		int matchSize = 1;
		if (searchData.getValueString().length() % 8 == 0) {
			matchSize = searchData.getValueString().length() / 8;
		}
		show("Addresses", ts, tableArray, matchSize);
	}

	/**
	 * Displays the search results dialog.
	 *
	 * @param title the title of the search dialog
	 * @param table the table service to use
	 * @param addresses the list of addresses to display
	 * @param matchSize the size of each match in the results table, in bytes
	 */
	private void show(String title, TableService table, Address[] addresses, int matchSize) {

		Swing.runLater(() -> {

			InstructionSearchTableModel model =
				new InstructionSearchTableModel(addresses, matchSize);

			TableComponentProvider<Address> tableProvider =
				table.showTableWithMarkers(title + " " + model.getName(),
					"Instruction Search Results", model, BG_COLOR_MARKERS, null,
					"Search", null);
			tableProvider.installRemoveItemsAction();
		});
	}

	private void goToLocation(Address addr) {
		GoToService gs = plugin.getTool().getService(GoToService.class);
		gs.goTo(addr);
	}

	public InstructionSearchPlugin getPlugin() {
		return plugin;
	}

	private class InstructionSearchTableModel extends AddressArrayTableModel {

		private int matchSize;

		public InstructionSearchTableModel(Address[] addrs, int matchSize) {
			super("Instruction Pattern Search", plugin.getTool(), plugin.getCurrentProgram(),
				addrs);
			this.matchSize = matchSize;
		}

		@Override
		public ProgramSelection getProgramSelection(int[] rows) {
			if (matchSize == 1) {
				return super.getProgramSelection(rows);
			}

			int addOn = matchSize - 1;
			AddressSet addressSet = new AddressSet();
			for (int element : rows) {
				Address minAddr = getAddress(element);
				Address maxAddr = minAddr;
				try {
					maxAddr = minAddr.addNoWrap(addOn);
					addressSet.addRange(minAddr, maxAddr);
				}
				catch (AddressOverflowException e) {
					Msg.debug(this,
						"Unable to add address range for addresses: " + minAddr + ", " + maxAddr);
				}
			}
			return new ProgramSelection(addressSet);
		}

	}
}
