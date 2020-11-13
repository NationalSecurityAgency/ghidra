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
package ghidra.app.plugin.core.string;

import java.awt.*;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.ActionContext;
import docking.DockingUtils;
import docking.action.*;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GLabel;
import docking.widgets.table.*;
import docking.widgets.table.threaded.ThreadedTableModel;
import docking.widgets.textfield.IntegerTextField;
import ghidra.app.services.GoToService;
import ghidra.app.util.HelpTopics;
import ghidra.docking.settings.SettingsImpl;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.util.ProgramSelection;
import ghidra.program.util.string.FoundString;
import ghidra.program.util.string.FoundString.DefinedState;
import ghidra.util.*;
import ghidra.util.exception.AssertException;
import ghidra.util.layout.VerticalLayout;
import ghidra.util.table.*;
import ghidra.util.table.actions.MakeProgramSelectionAction;
import ghidra.util.task.TaskLauncher;
import resources.ResourceManager;

/**
 * Component provider for the Search -&gt; For Strings... result dialog.
 */
public class StringTableProvider extends ComponentProviderAdapter implements DomainObjectListener {
	private static final ImageIcon ICON = ResourceManager.loadImage("images/kmessedwords.png");
	private static final Icon PARITALLY_DEFINED_ICON =
		ResourceManager.loadImage("images/dialog-warning.png");
	private static final Icon SHOW_UNDEFINED_ICON =
		ResourceManager.loadImage("images/magnifier.png");
	private static final Icon SHOW_DEFINED_ICON = ResourceManager.loadImage("images/font.png");
	private static final Icon SHOW_WORDS_ICON = ResourceManager.loadImage("images/view-filter.png");
	private static final Icon CONFLICTS_ICON =
		ResourceManager.loadImage("images/dialog-warning_red.png");
	private static final Icon REFRESH_ICON = ResourceManager.loadImage("images/reload.png");
	private static final Icon REFRESH_NOT_NEEDED_ICON =
		ResourceManager.getDisabledIcon(REFRESH_ICON);
	private static final Icon EXPAND_ICON = ResourceManager.loadImage("images/expand.gif");
	private static final Icon COLLAPSE_ICON = ResourceManager.loadImage("images/collapse.gif");

	private StringTablePlugin plugin;
	private JPanel mainPanel;
	private Program currentProgram;
	private StringTableOptions options;
	private boolean makeStringsOptionsShowing = true;

	private GhidraTable table;
	private StringTableModel stringModel;
	private GhidraThreadedTablePanel<FoundString> threadedTablePanel;
	private GhidraTableFilterPanel<FoundString> filterPanel;

	private JCheckBox autoLabelCheckbox;
	private JCheckBox addAlignmentBytesCheckbox;
	private JCheckBox allowTruncationCheckbox;
	private JPanel makeStringsOptionsPanel;
	private JButton toggleShowMakeStringOptionsButton;
	private JButton makeStringButton;
	private JButton makeCharArrayButton;
	private IntegerTextField offsetField;
	private JTextField preview;

	private ToggleDockingAction showDefinedAction;
	private ToggleDockingAction showUndefinedAction;
	private ToggleDockingAction selectionNavigationAction;
	private ToggleDockingAction showPartialDefinedAction;
	private ToggleDockingAction showConflictsAction;
	private ToggleDockingAction showIsWordAction;
	private DockingAction makeCharArrayAction;
	private DockingAction refreshAction;
	private DockingAction makeStringAction;

	public StringTableProvider(StringTablePlugin plugin, StringTableOptions options,
			boolean isTransient) {
		super(plugin.getTool(), "Strings", plugin.getName());
		this.plugin = plugin;
		this.options = options;

		mainPanel = createMainPanel();
		if (isTransient) {
			setTransient();
			updateSubTitle();
			setTitle(options.isPascalRequired() ? "Pascal String Search" : "String Search");
			setWindowMenuGroup("String Search");
			setWindowGroup("String Search");
			setTabText("String Search - " + DateUtils.formatCurrentTime());
		}
		setIcon(ICON);
		setHelpLocation(new HelpLocation(HelpTopics.SEARCH, "String_Search_Results"));
		addToTool();
		createActions();
	}

	void dispose() {
		threadedTablePanel.dispose();
		filterPanel.dispose();
		table.dispose();
	}

	private void updateSubTitle() {
		StringBuilder builder = new StringBuilder();

		int rowCount = stringModel.getRowCount();
		int unfilteredCount = stringModel.getUnfilteredRowCount();

		builder.append(rowCount);
		builder.append(" items");
		if (rowCount != unfilteredCount) {
			builder.append(" (of ").append(unfilteredCount).append(")");
		}

		if (isTransient()) {
			builder.append(" - [");
			if (currentProgram != null) {
				builder.append(currentProgram.getName());
				builder.append(", ");
			}

			builder.append("Minimum size = ");
			builder.append(options.getMinStringSize());
			builder.append(", Align = ");
			builder.append(options.getAlignment());
			if (options.getAddressSet() != null) {
				builder.append(", ");
				builder.append(options.getAddressSet().toString());
			}
			builder.append("]");
		}
		setSubTitle(builder.toString());

	}

	private void createActions() {

		HelpLocation filterHelp = new HelpLocation(HelpTopics.SEARCH, "String_Filters");

		showDefinedAction = new ToggleDockingAction("Show Defined Strings", getOwner()) {
			@Override
			public void actionPerformed(ActionContext context) {
				options = options.copy();
				options.setIncludeDefinedStrings(isSelected());
				stringModel.setOptions(options);
				reload();
			}

		};
		showDefinedAction.setToolBarData(new ToolBarData(SHOW_DEFINED_ICON, "AA"));
		showDefinedAction.setSelected(true);
		showDefinedAction.setHelpLocation(filterHelp);
		addLocalAction(showDefinedAction);

		showUndefinedAction = new ToggleDockingAction("Show Undefined Strings", getOwner()) {
			@Override
			public void actionPerformed(ActionContext context) {
				options = options.copy();
				options.setIncludeUndefinedStrings(isSelected());
				stringModel.setOptions(options);
				reload();
			}

		};
		showUndefinedAction.setToolBarData(new ToolBarData(SHOW_UNDEFINED_ICON, "AA"));
		addLocalAction(showUndefinedAction);
		showUndefinedAction.setHelpLocation(filterHelp);
		showUndefinedAction.setSelected(true);

		showPartialDefinedAction =
			new ToggleDockingAction("Show Partially Defined Strings", getOwner()) {
				@Override
				public void actionPerformed(ActionContext context) {
					options = options.copy();
					options.setIncludePartiallyDefinedStrings(isSelected());
					stringModel.setOptions(options);
					reload();
				}

			};
		showPartialDefinedAction.setToolBarData(new ToolBarData(PARITALLY_DEFINED_ICON, "AA"));
		addLocalAction(showPartialDefinedAction);
		showPartialDefinedAction.setHelpLocation(filterHelp);
		showPartialDefinedAction.setSelected(true);

		showConflictsAction = new ToggleDockingAction(
			"Show Strings That Conflict With Existing Instructions/Data", getOwner()) {
			@Override
			public void actionPerformed(ActionContext context) {
				options = options.copy();
				options.setIncludeConflictingStrings(isSelected());
				stringModel.setOptions(options);
				reload();
			}

		};
		showConflictsAction.setToolBarData(new ToolBarData(CONFLICTS_ICON, "AA"));
		showConflictsAction.setHelpLocation(filterHelp);
		addLocalAction(showConflictsAction);
		showConflictsAction.setSelected(true);

		if (options.getWordModelInitialized()) {
			showIsWordAction = new ToggleDockingAction(
				"Filter: Only Show High Confidence Word Strings", getOwner()) {
				@Override
				public void actionPerformed(ActionContext context) {
					options = options.copy();
					options.setOnlyShowWordStrings(isSelected());
					stringModel.setOptions(options);
					reload();
				}
			};
			showIsWordAction.setToolBarData(new ToolBarData(SHOW_WORDS_ICON, "AB"));
			showIsWordAction.setSelected(false);
			showIsWordAction.setHelpLocation(filterHelp);
			addLocalAction(showIsWordAction);
		}

		refreshAction = new DockingAction("Refresh Strings Table", getOwner()) {
			@Override
			public void actionPerformed(ActionContext context) {
				stringModel.reload();
				refreshAction.getToolBarData().setIcon(REFRESH_NOT_NEEDED_ICON);
			}

		};
		refreshAction.setToolBarData(new ToolBarData(REFRESH_NOT_NEEDED_ICON, "AC"));
		refreshAction.setHelpLocation(new HelpLocation(HelpTopics.SEARCH, "Refresh"));

		addLocalAction(refreshAction);

		makeStringAction = new DockingAction("Make String", getOwner()) {
			@Override
			public void actionPerformed(ActionContext context) {
				makeString(false);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return makeStringButton.isEnabled();
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}
		};
		makeStringAction.setPopupMenuData(new MenuData(new String[] { "Make String" }, "Make"));
		makeStringAction.setKeyBindingData(new KeyBindingData(
			KeyStroke.getKeyStroke(KeyEvent.VK_M, DockingUtils.CONTROL_KEY_MODIFIER_MASK)));
		HelpLocation makeStringHelp = new HelpLocation(HelpTopics.SEARCH, "Make_String_Options");
		makeStringAction.setHelpLocation(makeStringHelp);
		addLocalAction(makeStringAction);

		makeCharArrayAction = new DockingAction("Make Char Array", getOwner()) {
			@Override
			public void actionPerformed(ActionContext context) {
				makeString(true);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return makeCharArrayButton.isEnabled();
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}

		};
		makeCharArrayAction.setPopupMenuData(
			new MenuData(new String[] { "Make Char Array" }, "Make"));
		makeCharArrayAction.setHelpLocation(makeStringHelp);
		addLocalAction(makeCharArrayAction);

		DockingAction selectAction = new MakeProgramSelectionAction(plugin, table) {
			@Override
			protected ProgramSelection makeSelection(ActionContext context) {
				ProgramSelection selection = super.makeSelection(context);

				// Also make sure this plugin keeps track of the new selection, since it will
				// not receive this new event.
				// TODO this should not be necessary; old code perhaps?
				plugin.setSelection(selection);
				return selection;
			}
		};

		selectionNavigationAction = new SelectionNavigationAction(plugin, table);

		addLocalAction(selectionNavigationAction);
		addLocalAction(selectAction);

	}

	private JPanel createMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(buildTablePanel(), BorderLayout.CENTER);
		makeStringsOptionsPanel = buildMakeStringOptionsPanel();
		panel.add(makeStringsOptionsPanel, BorderLayout.SOUTH);
		panel.setPreferredSize(new Dimension(900, 600));
		return panel;

	}

	private JPanel buildMakeStringOptionsPanel() {
		JPanel panel = new JPanel(new VerticalLayout(0));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		panel.add(buildOffsetPanel());
		panel.add(buildButtonPanel());

		return panel;
	}

	private Component buildOffsetPanel() {
		offsetField = new IntegerTextField(4, 0L);
		offsetField.setAllowNegativeValues(false);
		offsetField.addChangeListener(e -> updatePreview());

		preview = new JTextField(5);
		preview.setEditable(false);
		preview.setEnabled(false);
		autoLabelCheckbox = new GCheckBox("Auto Label");
		addAlignmentBytesCheckbox = new GCheckBox("Include Alignment Nulls");
		allowTruncationCheckbox = new GCheckBox("Truncate If Needed");
		autoLabelCheckbox.setSelected(false); // discourage labeling since dynamic labels are preferred

		JPanel panel = new JPanel(new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridy = 0;
		gbc.gridx = 0;
		gbc.anchor = GridBagConstraints.WEST;
		panel.add(autoLabelCheckbox, gbc);

		gbc.gridx = 1;
		panel.add(Box.createHorizontalStrut(60), gbc);

		gbc.gridx = 2;
		panel.add(new GLabel("Offset: "), gbc);

		gbc.gridx = 3;
		panel.add(offsetField.getComponent(), gbc);

		gbc.gridx = 4;
		panel.add(Box.createHorizontalStrut(20), gbc);

		gbc.gridx = 5;
		panel.add(new GLabel("Preview: "), gbc);

		gbc.weightx = 1;
		gbc.gridx = 6;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		panel.add(preview, gbc);

		gbc.gridx = 0;
		gbc.gridy = 1;
		gbc.weightx = 0;
		gbc.fill = GridBagConstraints.NONE;
		panel.add(addAlignmentBytesCheckbox, gbc);

		gbc.gridy = 2;
		panel.add(allowTruncationCheckbox, gbc);

		return panel;
	}

	private Component buildButtonPanel() {
		makeStringButton = new JButton("Make String");
		makeCharArrayButton = new JButton("Make Char Array");
		makeStringButton.setEnabled(false);
		makeCharArrayButton.setEnabled(false);

		makeStringButton.addActionListener(e -> makeString(false));

		makeCharArrayButton.addActionListener(e -> makeString(true));

		JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 40, 0));
		buttonPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
		buttonPanel.add(makeStringButton);
		buttonPanel.add(makeCharArrayButton);
		return buttonPanel;
	}

	protected void makeString(boolean makeArray) {
		List<FoundString> foundStrings = new ArrayList<>();

		int[] selectedRows = table.getSelectedRows();
		FoundString nextItemToSelect = findNextItemToSelect(selectedRows);

		for (int selectedRow : selectedRows) {
			FoundString string = stringModel.getRowObject(selectedRow);
			if (!string.isDefined()) {
				foundStrings.add(string);
			}
		}

		boolean autoLabel = autoLabelCheckbox.isSelected();
		boolean addAlignmentBytes = addAlignmentBytesCheckbox.isSelected();
		boolean allowTruncate = allowTruncationCheckbox.isSelected();

		int offset = offsetField.getIntValue();

		MakeStringsTask task = new MakeStringsTask(currentProgram, foundStrings, offset,
			options.getAlignment(), autoLabel, addAlignmentBytes, allowTruncate, makeArray);

		new TaskLauncher(task, getComponent());

		List<StringEvent> stringEvents = task.getStringEvents();
		StringEventsTask eventsTask = new StringEventsTask(stringModel, options, stringEvents);
		new TaskLauncher(eventsTask, getComponent());

		if (task.hasErrors()) {
			String message =
				"One or more strings could not be created due to collisions with existing" +
					"\ndata or instructions. Check the String Table for those strings not created.";

			Msg.showInfo(this, getComponent(), "Error Making String(s)", message);
		}

		updateSelection(nextItemToSelect);

	}

	private FoundString findNextItemToSelect(int[] selectedRows) {
		if (selectedRows.length != 1) {
			return null;
		}

		int nextRow = selectedRows[0] + 1;
		if (nextRow >= stringModel.getRowCount()) {
			return null;
		}

		return stringModel.getRowObject(nextRow);
	}

	private void updateSelection(FoundString next) {
		if (next == null) {
			return;
		}

		int nextRow = stringModel.getRowIndex(next);
		setSelectedRowAndNavigate(nextRow);
	}

	/**
	 * Sets the given row as a selection in the table.  Note, this method assumes that the given
	 * row was obtained by getting the selected row from the table and not somehow
	 * obtained from the model.
	 *
	 * @param row the row in the table to select
	 */
	void setSelectedRowAndNavigate(int row) {
		if (row < 0 || table.getRowCount() <= row) {
			// 'row' is sometimes invalid as strings get made in the background
			return;
		}

		table.setRowSelectionInterval(row, row);
		Rectangle rect = table.getCellRect(row, 0, true);
		table.scrollRectToVisible(rect);

		if (!selectionNavigationAction.isSelected()) {
			return; // only navigate if the action is selected
		}

		// force navigation; navigation usually happens when selections take place, but this
		// component has widgets that take focus, which interferes with the table's navigation
		if (!table.isFocusOwner()) {
			table.navigate(row, 0);
		}
	}

	private class StringTable extends GhidraTable {
		public StringTable(ThreadedTableModel<FoundString, ?> model) {
			super(model);
		}

//		@Override
//		protected <T> SelectionManager createSelectionManager(TableModel tableModel) {
//			return null;
//		}

	}

	private JComponent buildTablePanel() {
		stringModel = new StringTableModel(tool, options);

		threadedTablePanel = new GhidraThreadedTablePanel<>(stringModel, 1000) {
			@Override
			protected GTable createTable(ThreadedTableModel<FoundString, ?> model) {
				return new StringTable(model);
			}
		};
		table = threadedTablePanel.getTable();
		table.setActionsEnabled(true);
		table.setName("DataTable");
		table.setPreferredScrollableViewportSize(new Dimension(350, 150));
		table.getSelectionModel().addListSelectionListener(e -> tableSelectionChanged());

		stringModel.addTableModelListener(e -> updateSubTitle());

		GoToService goToService = tool.getService(GoToService.class);
		table.installNavigation(goToService, goToService.getDefaultNavigatable());
		table.setDefaultRenderer(FoundString.DefinedState.class, new DefinedColumnRenderer());

		filterPanel = new GhidraTableFilterPanel<>(table, stringModel);

		toggleShowMakeStringOptionsButton = new JButton(COLLAPSE_ICON);
		toggleShowMakeStringOptionsButton.setToolTipText("Toggle Make Strings Panel On/Off");
		toggleShowMakeStringOptionsButton.addActionListener(e -> toggleShowMakeStringOptions());

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(threadedTablePanel, BorderLayout.CENTER);
		JPanel bottomPanel = new JPanel(new BorderLayout());
		bottomPanel.add(filterPanel, BorderLayout.CENTER);
		bottomPanel.add(toggleShowMakeStringOptionsButton, BorderLayout.EAST);
		panel.add(bottomPanel, BorderLayout.SOUTH);

		return panel;
	}

	protected void tableSelectionChanged() {
		notifyContextChanged();
		boolean enabled = hasAtLeastOneUndefinedStringSelected();
		makeStringButton.setEnabled(enabled);
		makeCharArrayButton.setEnabled(enabled);

		updatePreview();
	}

	private void updatePreview() {
		int rowCount = table.getSelectedRowCount();
		if (rowCount == 1) {
			int charOffset = offsetField.getIntValue();
			FoundString foundString = stringModel.getRowObject(table.getSelectedRow());
			MemBuffer membuf =
				new DumbMemBufferImpl(currentProgram.getMemory(), foundString.getAddress());
			StringDataInstance stringInstance =
				StringDataInstance.getStringDataInstance(foundString.getDataType(), membuf,
					SettingsImpl.NO_SETTINGS, foundString.getLength());
			if (charOffset != 0) {
				stringInstance = stringInstance.getCharOffcut(charOffset);
			}

			preview.setText(stringInstance.getStringRepresentation());
		}
		else {
			preview.setText("");
		}
	}

	private boolean hasAtLeastOneUndefinedStringSelected() {
		int[] selectedRows = table.getSelectedRows();
		for (int selectedRow : selectedRows) {
			FoundString string = stringModel.getRowObject(selectedRow);
			if (string.isUndefined() || string.isPartiallyDefined()) {
				return true;
			}
		}
		return false;
	}

	protected void toggleShowMakeStringOptions() {
		makeStringsOptionsShowing = !makeStringsOptionsShowing;

		if (makeStringsOptionsShowing) {
			toggleShowMakeStringOptionsButton.setIcon(COLLAPSE_ICON);
			mainPanel.add(makeStringsOptionsPanel, BorderLayout.SOUTH);
		}
		else {
			toggleShowMakeStringOptionsButton.setIcon(EXPAND_ICON);
			mainPanel.remove(makeStringsOptionsPanel);
		}
		mainPanel.validate();
	}

	private void notifyContextChanged() {
		tool.contextChanged(this);
	}

	private void reload() {
		stringModel.reload();
	}

	public void setProgram(Program program) {
		if (program == currentProgram) {
			return;
		}
		if (currentProgram != null) {
			currentProgram.removeListener(this);
		}

		currentProgram = program;

		if (currentProgram != null) {
			currentProgram.addListener(this);
		}

		if (isVisible()) {
			stringModel.setProgram(program);
			stringModel.reload();
		}
		if (isTransient()) {
			updateSubTitle();
		}
	}

	@Override
	public void componentHidden() {
		stringModel.setProgram(null);
		if (isTransient()) {
			plugin.removeTransientProvider(this);
		}
	}

	@Override
	public void componentShown() {
		stringModel.setProgram(currentProgram);
		stringModel.reload();
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		refreshAction.getToolBarData().setIcon(REFRESH_ICON);
		table.repaint();
	}

	private class DefinedColumnRenderer extends GTableCellRenderer {

		public DefinedColumnRenderer() {
			setHorizontalAlignment(SwingConstants.CENTER);
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			super.getTableCellRendererComponent(data);

			Object value = data.getValue();

			setHorizontalAlignment(SwingConstants.CENTER);
			setText("");

			FoundString.DefinedState state = (FoundString.DefinedState) value;
			Icon icon = getIcon(state);
			setIcon(icon);
			setToolTipText(state.toString());

			return this;
		}

		private Icon getIcon(DefinedState state) {
			switch (state) {
				case DEFINED:
					return SHOW_DEFINED_ICON;
				case NOT_DEFINED:
					return SHOW_UNDEFINED_ICON;
				case PARTIALLY_DEFINED:
					return PARITALLY_DEFINED_ICON;
				case CONFLICTS:
					return CONFLICTS_ICON;
				default:
					throw new AssertException("Missing case:");
			}
		}
	}

	public void programClosed(Program program) {
		if (program == currentProgram) {
			closeComponent();
		}
	}

}
