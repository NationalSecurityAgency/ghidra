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

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.ReusableDialogComponentProvider;
import docking.action.DockingAction;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import docking.widgets.textfield.HintTextField;
import ghidra.app.util.HelpTopics;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.HelpLocation;
import ghidra.util.table.*;
import ghidra.util.table.actions.MakeProgramSelectionAction;
import ghidra.util.task.Task;

public class AddressTableDialog extends ReusableDialogComponentProvider {
	private static final int DEFAULT_MINIMUM_TABLE_SIZE = 3;
	private static final String DIALOG_NAME = "Search For Address Tables";

	private JPanel mainPanel;
	private String[] blockData;
	private AutoTableDisassemblerPlugin plugin;
	private GhidraTable resultsTable;
	private JButton disassembleTableButton;
	private JButton makeTableButton;
	private JTextField offsetField;
	private HintTextField viewOffset;
	private JLabel offsetLabel;
	private JCheckBox autoLabelCB;
	private JTextField minLengthField;
	private JLabel skipLabel;
	private JTextField skipField;
	private JLabel alignLabel;
	private JTextField alignField;
	private JCheckBox selectionButton;
	private JCheckBox shiftedAddressButton;
	private JButton searchButton;
	private SelectionNavigationAction selectionNavigationAction;
	private GhidraThreadedTablePanel<AddressTable> resultsTablePanel;

	public AddressTableDialog(AutoTableDisassemblerPlugin plugin) {
		super(DIALOG_NAME, false, true, true, true);
		setHelpLocation(
			new HelpLocation(HelpTopics.SEARCH, AutoTableDisassemblerPlugin.SEARCH_ACTION_NAME));
		this.plugin = plugin;
		blockData = new String[0];
		addWorkPanel(buildMainPanel());
		addDismissButton();

		createAction();

		setDefaultButton(searchButton);
	}

	protected JPanel buildMainPanel() {
		mainPanel = new JPanel(new BorderLayout());
		mainPanel.getAccessibleContext().setAccessibleName("Address Table");

		// Find Button
		searchButton = new JButton("Search");
		searchButton.addActionListener(e -> searchSelection());
		searchButton.getAccessibleContext().setAccessibleName("Search");

		// right panel for populating results and selecting tables to disassemble
		JPanel resultsPanel = new JPanel(new BorderLayout());
		resultsPanel.setPreferredSize(new Dimension(600, 300));
		resultsPanel.setBorder(BorderFactory.createTitledBorder("Possible Address Tables"));
		resultsPanel.getAccessibleContext().setAccessibleName("Results");

		// create right side query results table with three columns
		resultsTablePanel = new GhidraThreadedTablePanel<>(plugin.getModel());
		resultsTable = resultsTablePanel.getTable();
		resultsTable.installNavigation(plugin.getTool());
		resultsTable.getAccessibleContext().setAccessibleName("Results");

		ListSelectionModel selModel = resultsTable.getSelectionModel();
		selModel.addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}

			updateMakeTableOptionsEnabledState();
		});

		resultsTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				clearStatusText();
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				plugin.updateOffsetString(resultsTable.getSelectedRows());
			}
		});

		resultsPanel.add(resultsTablePanel, BorderLayout.CENTER);

		// make button panel for right panel
		JPanel makeTablePanel = new JPanel(new FlowLayout());
		makeTablePanel.getAccessibleContext().setAccessibleName("Make Table");
		makeTableButton = new JButton("Make Table");
		makeTableButton.setToolTipText("Make a table of addresses at the selected location(s).");
		makeTableButton.getAccessibleContext().setAccessibleName("Make Table");
		makeTablePanel.add(makeTableButton);
		makeTableButton.setEnabled(false);
		makeTableButton.addActionListener(e -> plugin.makeTable(resultsTable.getSelectedRows()));

		JPanel disassemblePanel = new JPanel(new FlowLayout());
		disassemblePanel.getAccessibleContext().setAccessibleName("Disassemble");
		disassembleTableButton = new JButton("Disassemble");
		disassembleTableButton.setToolTipText(
			"Disassemble at all locations pointed to by the selected address table(s) members.");
		disassembleTableButton.getAccessibleContext().setAccessibleName("Dissasemble");
		disassembleTableButton.setEnabled(false);
		disassemblePanel.add(disassembleTableButton);
		disassembleTableButton
				.addActionListener(e -> plugin.disassembleTable(resultsTable.getSelectedRows()));

		// make bottom of right panel

		JPanel myButtonPanel = new JPanel(new FlowLayout());
		myButtonPanel.add(makeTablePanel);
		myButtonPanel.add(disassemblePanel);
		myButtonPanel.getAccessibleContext().setAccessibleName("Buttons");

		// search options panel   
		JPanel searchOptionsPanel = new JPanel(new BorderLayout());
		searchOptionsPanel.setBorder(BorderFactory.createTitledBorder("Search Options"));
		searchOptionsPanel.getAccessibleContext().setAccessibleName("Search Options");

		JLabel minLengthLabel = new GLabel("Minimum Length: ");
		minLengthLabel.setToolTipText(
			"The minimum number of consecutive addresses that will make an address table.");
		minLengthField = new JTextField(5);
		minLengthField.setName("Minimum Length");
		minLengthField.setText(Integer.toString(DEFAULT_MINIMUM_TABLE_SIZE));
		minLengthField.getAccessibleContext().setAccessibleName("Minimum Length for Table");

		JPanel minLengthPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		minLengthPanel.add(minLengthLabel);
		minLengthPanel.add(minLengthField);
		minLengthPanel.getAccessibleContext().setAccessibleName("Minimum Length");

		alignLabel = new GDLabel("Alignment: ");
		alignField = new JTextField(5);
		alignField.setName("Alignment");
		alignField.getAccessibleContext().setAccessibleName("Alignment");
		alignLabel.setToolTipText(
			"Alignment that address tables and what they are pointing to must satisfy.");
		int align = plugin.getProgram().getLanguage().getInstructionAlignment();
		if (PseudoDisassembler.hasLowBitCodeModeInAddrValues(plugin.getProgram())) {
			align = 1;
		}
		alignField.setText("" + align);

		skipLabel = new GDLabel("Skip Length: ");
		skipField = new JTextField(5);
		skipField.setName("Skip");
		skipField.getAccessibleContext().setAccessibleName("Skip");
		skipLabel.setToolTipText("Number of bytes to skip between found addresses in a table.");
		skipField.setText("0");

		JPanel alignPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		alignPanel.add(alignLabel);
		alignPanel.add(alignField);
		alignPanel.getAccessibleContext().setAccessibleName("Alignment");

		JPanel skipPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		skipPanel.add(skipLabel);
		skipPanel.add(skipField);
		skipPanel.getAccessibleContext().setAccessibleName("Skip");

		JPanel optPanel = new JPanel(new GridLayout(3, 1));
		optPanel.add(minLengthPanel);
		optPanel.add(alignPanel);
		optPanel.add(skipPanel);
		optPanel.getAccessibleContext().setAccessibleName("Options");

		selectionButton = new GCheckBox("Search Selection");
		selectionButton.setSelected(false);
		selectionButton.setToolTipText("If checked, search only the current selection.");
		selectionButton.getAccessibleContext().setAccessibleName("Use Selection");
		JPanel searchOptionsWestPanel = new JPanel(new GridLayout(2, 1));
		searchOptionsWestPanel.getAccessibleContext().setAccessibleDescription("Search Options");
		searchOptionsWestPanel.add(selectionButton);

		shiftedAddressButton = new GCheckBox("Shifted Addresses");
		shiftedAddressButton.getAccessibleContext().setAccessibleName("Shifted Addresses");

		boolean allowShiftedAddresses =
			plugin.getProgram().getDataTypeManager().getDataOrganization().getPointerShift() != 0;
		if (allowShiftedAddresses) {
			shiftedAddressButton.setSelected(true);
			shiftedAddressButton.setVisible(true);
		}
		else {
			shiftedAddressButton.setSelected(false);
			shiftedAddressButton.setVisible(false);
		}

		shiftedAddressButton.setToolTipText(
			"Search for tables of four byte values that when shifted left by two, are valid " +
				"addresses in the current program.");
		searchOptionsWestPanel.add(shiftedAddressButton);

		searchOptionsPanel.add(optPanel, BorderLayout.EAST);
		searchOptionsPanel.add(searchOptionsWestPanel, BorderLayout.WEST);
		JPanel findPanel = new JPanel(new FlowLayout());
		findPanel.add(searchButton);
		findPanel.getAccessibleContext().setAccessibleName("Find");
		searchOptionsPanel.add(findPanel, BorderLayout.SOUTH);

		JPanel makeOptionsPanel = new JPanel(new BorderLayout());
		makeOptionsPanel.setBorder(BorderFactory.createTitledBorder("Make Table Options"));
		makeOptionsPanel.getAccessibleContext().setAccessibleName("Make Table Options");

		autoLabelCB = new GCheckBox("Auto Label");
		autoLabelCB.setSelected(true);
		autoLabelCB.setEnabled(false);
		autoLabelCB
				.setToolTipText("Label the top of the address table and all members of the table.");
		autoLabelCB.getAccessibleContext().setAccessibleName("Auto Label");

		offsetLabel = new GDLabel("Offset: ");
		offsetLabel.setToolTipText("Offset from the beginning of the selected table(s)");
		offsetLabel.setEnabled(false);
		offsetLabel.getAccessibleContext().setAccessibleName("Offset");

		JLabel viewOffsetLabel = new GDLabel("  ");
		viewOffsetLabel.setEnabled(false);
		viewOffsetLabel.getAccessibleContext().setAccessibleName("View Offset");

		viewOffset = new HintTextField("<table start address>");
		viewOffset.setName("viewOffset");
		viewOffset.getAccessibleContext().setAccessibleName("View Offset");
		viewOffset.setToolTipText("Address of the selected table starting at the given offset");
		viewOffset.setColumns(20);
		viewOffset.setEnabled(false);

		offsetField = new JTextField(2);
		offsetField.setName("offset");
		offsetField.getAccessibleContext().setAccessibleName("Offset");
		offsetField.setToolTipText("Offset from the beginning of the selected table(s)");
		offsetField.setText("0");
		offsetField.setEnabled(false);
		offsetField
				.addActionListener(e -> plugin.updateOffsetString(resultsTable.getSelectedRows()));
		offsetField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				plugin.updateOffsetString(resultsTable.getSelectedRows());
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				plugin.updateOffsetString(resultsTable.getSelectedRows());
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				plugin.updateOffsetString(resultsTable.getSelectedRows());
			}
		});

		JPanel offsetPanel = new JPanel();
		offsetPanel.setLayout(new BoxLayout(offsetPanel, BoxLayout.LINE_AXIS));
		offsetPanel.add(autoLabelCB);
		offsetPanel.add(offsetLabel);
		offsetPanel.add(offsetField);
		offsetPanel.add(viewOffsetLabel);
		offsetPanel.add(viewOffset);
		offsetPanel.getAccessibleContext().setAccessibleName("Offset");

		makeOptionsPanel.add(offsetPanel, BorderLayout.NORTH);
		makeOptionsPanel.add(myButtonPanel, BorderLayout.SOUTH);

		// add panels to left panel
		JPanel optionsPanel = new JPanel(new GridLayout(1, 2));

		optionsPanel.add(searchOptionsPanel);
		optionsPanel.add(makeOptionsPanel);
		optionsPanel.getAccessibleContext().setAccessibleName("Options");

		// put sub-panels onto main panel    
		mainPanel.add(resultsPanel, BorderLayout.CENTER);
		mainPanel.add(optionsPanel, BorderLayout.SOUTH);

		return mainPanel;
	}

	void clearMakeTableOptions() {
		setOffsetText(" ");
		setDialogText("");
		setEnableMakeTableOptions(false);
	}

	void setDialogText(String text) {
		setStatusText(text);
	}

	private void searchSelection() {

		if (selectionButton.isSelected()) {
			// get Address Set of selected area
			this.setStatusText("Searching selected area...");
			plugin.findTablesInSet(resultsTable, true);
			return;
		}

		searchAll();

	}

	private void searchAll() {
		setStatusText("Searching entire program...");
		plugin.findTablesInSet(resultsTable, false);
	}

	void setBlockData(String[] data) {
		this.blockData = data;
	}

	void refresh(Program currentProgram) {

		MemoryBlock[] currentBlocks = currentProgram.getMemory().getBlocks();
		blockData = new String[currentBlocks.length];
		for (int i = 0; i < currentBlocks.length; i++) {
			blockData[i] = currentBlocks[i].getName();
		}
	}

	@Override
	public void close() {
		if (!isShowing()) {
			return;
		}

		cancelCurrentTask();
		super.close();
		resultsTablePanel.dispose();
		plugin.dialogDismissed();
	}

	boolean getAutomaticLabel() {
		return autoLabelCB.isSelected();
	}

	int getMinTableSize() {
		try {
			Integer ilen = Integer.decode(minLengthField.getText());
			int len = ilen.intValue();
			return len;
		}
		catch (NumberFormatException e) {
			return 0;
		}
	}

	int getAlignment() {

		try {
			Integer ilen = Integer.decode(alignField.getText());
			int len = ilen.intValue();
			return len;
		}
		catch (NumberFormatException e) {
			return 1;
		}
	}

	int getSkipLength() {

		try {
			Integer ilen = Integer.decode(skipField.getText());
			int len = ilen.intValue();
			return len;
		}
		catch (NumberFormatException e) {
			return 0;
		}
	}

	boolean getShiftedAddresses() {
		if (shiftedAddressButton.isSelected()) {
			return true;
		}
		return false;
	}

	int getOffset() {
		try {
			Integer ilen = Integer.decode(offsetField.getText());
			int len = ilen.intValue();
			return len;
		}
		catch (NumberFormatException e) {
			return -1;
		}

	}

	boolean isSearchSelection() {
		return selectionButton.isSelected();
	}

	void setOffsetText(String str) {
		viewOffset.setText(str);
	}

	void clearOffset() {
		offsetField.setText("0");
		setOffsetText(" ");
	}

	void setHasSelection(boolean b) {
		selectionButton.setSelected(b);
		selectionButton.setEnabled(b);
	}

	void enableSearchButton(boolean enabled) {
		searchButton.setEnabled(enabled);
	}

	void setEnableMakeTableOptions(boolean b) {
		autoLabelCB.setEnabled(b);
		setEnableOffsetField(b);
		setEnableMakeTableButtons(b);
	}

	void setEnableOffsetField(boolean b) {
		offsetLabel.setEnabled(b);
		offsetField.setEnabled(b);
	}

	void setEnableMakeTableButtons(boolean b) {
		makeTableButton.setEnabled(b);
		disassembleTableButton.setEnabled(b);
	}

	// overridden for access
	@Override
	protected void executeProgressTask(Task task, int delay) {
		super.executeProgressTask(task, delay);
	}

	private void searchComplete() {
		stopProgressTimer();
		searchButton.setEnabled(true);

		resultsTable.requestFocusInWindow();
	}

	void searchComplete(boolean wasCancelled) {
		searchComplete();

		if (wasCancelled) {
			setStatusText("Find address tables was cancelled");
		}

		int resultCount = resultsTable.getRowCount();
		if (resultCount > 0) {
			setStatusText(selectionButton.isSelected() ? "Finished searching current selection"
					: "Finished Searching Entire Program");
		}
		else {
			setStatusText(
				selectionButton.isSelected() ? "No address tables found in this selection!"
						: "No address tables found in the entire program!");
		}
	}

	void makeTablesCompleted() {
		stopProgressTimer();
		updateMakeTableOptionsEnabledState();
	}

	private void updateMakeTableOptionsEnabledState() {
		boolean hasSelection = resultsTable.getSelectedRowCount() > 0;
		setEnableMakeTableOptions(hasSelection);
	}

	int[] getSelectedRows() {
		return resultsTable.getSelectedRows();
	}

	public void setSelectedRows(int[] selectedRows) {
		resultsTable.clearSelection();

		boolean wasEnabled = selectionNavigationAction.isEnabled();
		selectionNavigationAction.setEnabled(false);
		for (int element : selectedRows) {
			resultsTable.addRowSelectionInterval(element, element);
		}

		selectionNavigationAction.setEnabled(wasEnabled);
	}

	@Override
	public void taskCancelled(Task task) {
		super.taskCancelled(task);
		searchComplete();
	}

	@Override
	public void taskCompleted(Task task) {
		super.taskCompleted(task);
		searchComplete();
	}

	@Override
	protected void cancelCurrentTask() {
		super.cancelCurrentTask();
	}

	private void createAction() {

		DockingAction selectAction = new MakeProgramSelectionAction(plugin, resultsTable);

		selectionNavigationAction = new SelectionNavigationAction(plugin, resultsTable);
		selectionNavigationAction.setHelpLocation(
			new HelpLocation(HelpTopics.SEARCH, "AddressTables_Selection_Navigation"));
		addAction(selectionNavigationAction);
		addAction(selectAction);
	}
}
