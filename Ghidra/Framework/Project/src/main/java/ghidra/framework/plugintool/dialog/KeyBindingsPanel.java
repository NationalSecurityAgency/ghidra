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
package ghidra.framework.plugintool.dialog;

import java.awt.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableColumn;

import org.apache.commons.lang3.StringUtils;

import docking.*;
import docking.action.DockingActionIf;
import docking.actions.*;
import docking.tool.util.DockingToolConstants;
import docking.widgets.*;
import docking.widgets.label.GIconLabel;
import docking.widgets.table.*;
import generic.theme.Gui;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.*;
import ghidra.util.layout.PairLayout;
import ghidra.util.layout.VerticalLayout;
import gui.event.MouseBinding;
import help.Help;
import help.HelpService;
import resources.Icons;

/**
 * Panel to show the key bindings for the plugin actions.
 */
public class KeyBindingsPanel extends JPanel {

	private static final int STATUS_LABEL_HEIGHT = 60;

	private final static int ACTION_NAME = 0;
	private final static int KEY_BINDING = 1;
	private final static int PLUGIN_NAME = 2;

	private static final String FONT_ID = "font.keybindings.status";

	private JTextPane statusLabel;
	private GTable actionTable;
	private JPanel infoPanel;
	private MultiLineLabel collisionLabel;
	private KeyBindingsTableModel tableModel;
	private ActionBindingListener actionBindingListener = new ActionBindingListener();
	private ActionBindingPanel actionBindingPanel;
	private GTableFilterPanel<DockingActionIf> tableFilterPanel;
	private EmptyBorderButton helpButton;

	private KeyBindings keyBindings;
	private boolean unappliedChanges;

	private PluginTool tool;
	private boolean firingTableDataChanged;
	private PropertyChangeListener propertyChangeListener;

	public KeyBindingsPanel(PluginTool tool) {
		this.tool = tool;

		this.keyBindings = new KeyBindings(tool);

		createPanelComponents();

		initializeTableWidth();
	}

	public void setOptionsPropertyChangeListener(PropertyChangeListener listener) {
		this.propertyChangeListener = listener;
	}

	public void dispose() {
		tableFilterPanel.dispose();
		propertyChangeListener = null;
	}

	public void apply() {
		keyBindings.applyChanges();
		changesMade(false);
	}

	public void cancel() {
		keyBindings.cancelChanges();
		tableModel.fireTableDataChanged();
	}

	public void reload() {
		Swing.runLater(() -> {
			// clear the action to avoid the appearance of editing while restoring
			actionTable.clearSelection();

			restoreDefaultKeybindings();
		});
	}

	public String getStatusText() {
		return statusLabel.getText();
	}

	private void initializeTableWidth() {

		String longestName = keyBindings.getLongestActionName();

		Font f = actionTable.getFont();
		FontMetrics fm = actionTable.getFontMetrics(f);
		int maxWidth = 0;
		for (int i = 0; i < longestName.length(); i++) {
			char c = longestName.charAt(i);
			maxWidth += fm.charWidth(c);
		}
		TableColumn col = actionTable.getColumnModel().getColumn(ACTION_NAME);
		col.setPreferredWidth(maxWidth);
		tableModel.fireTableDataChanged();
	}

	private void createPanelComponents() {
		setLayout(new BorderLayout(10, 10));

		tableModel = new KeyBindingsTableModel(new ArrayList<>(keyBindings.getUniqueActions()));
		actionTable = new GTable(tableModel);

		JScrollPane sp = new JScrollPane(actionTable);
		actionTable.setPreferredScrollableViewportSize(new Dimension(400, 100));
		actionTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		actionTable.setHTMLRenderingEnabled(true);

		adjustTableColumns();

		// middle panel - filter field and import/export buttons
		JPanel importExportPanel = createImportExportPanel();
		tableFilterPanel = new GTableFilterPanel<>(actionTable, tableModel);
		JPanel middlePanel = new JPanel(new BorderLayout());
		middlePanel.add(tableFilterPanel, BorderLayout.NORTH);
		middlePanel.add(importExportPanel, BorderLayout.SOUTH);

		// contains the upper panel (table) and the middle panel)
		JPanel centerPanel = new JPanel(new BorderLayout());
		centerPanel.add(sp, BorderLayout.CENTER);
		centerPanel.add(middlePanel, BorderLayout.SOUTH);

		// lower panel - key entry panel and status panel
		JPanel keyPanel = createKeyEntryPanel();
		JComponent statusPanel = createStatusPanel(keyPanel);

		add(centerPanel, BorderLayout.CENTER);
		add(statusPanel, BorderLayout.SOUTH);

		actionTable.getSelectionModel().addListSelectionListener(new TableSelectionListener());
	}

	private JPanel createStatusPanel(JPanel keyPanel) {

		statusLabel = new JTextPane();
		statusLabel.setEnabled(false);
		DockingUtils.setTransparent(statusLabel);
		statusLabel.setBorder(BorderFactory.createEmptyBorder(5, 10, 0, 5));
		statusLabel.setContentType("text/html"); // render any HTML we find in descriptions

		// make sure the label gets enough space
		statusLabel.setPreferredSize(new Dimension(0, STATUS_LABEL_HEIGHT));
		statusLabel.setFont(Gui.getFont(FONT_ID));

		helpButton = new EmptyBorderButton(Icons.HELP_ICON);
		helpButton.setEnabled(false);
		helpButton.addActionListener(e -> {
			DockingActionIf action = getSelectedAction();
			HelpService hs = Help.getHelpService();
			hs.showHelp(action, false, KeyBindingsPanel.this);
		});

		JPanel helpButtonPanel = new JPanel();
		helpButtonPanel.setLayout(new BoxLayout(helpButtonPanel, BoxLayout.PAGE_AXIS));
		helpButtonPanel.add(helpButton);
		helpButtonPanel.add(Box.createVerticalGlue());

		JPanel lowerStatusPanel = new JPanel();
		lowerStatusPanel.setLayout(new BoxLayout(lowerStatusPanel, BoxLayout.X_AXIS));
		lowerStatusPanel.add(helpButtonPanel);
		lowerStatusPanel.add(statusLabel);

		JPanel panel = new JPanel(new VerticalLayout(5));
		panel.add(keyPanel);
		panel.add(lowerStatusPanel);
		return panel;
	}

	private JPanel createKeyEntryPanel() {
		actionBindingPanel = new ActionBindingPanel(actionBindingListener);

		// this is the lower panel that holds the key entry text field
		JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT));
		p.add(actionBindingPanel);

		JPanel keyPanel = new JPanel(new BorderLayout());

		JPanel defaultPanel = new JPanel(new BorderLayout());

		// the content of the left-hand side label
		MultiLineLabel mlabel =
			new MultiLineLabel("To add or change a key binding, select an action\n" +
				"and type any key combination.");
		JPanel labelPanel = new JPanel();
		labelPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 0, 0));
		BoxLayout bl = new BoxLayout(labelPanel, BoxLayout.X_AXIS);
		labelPanel.setLayout(bl);
		labelPanel.add(Box.createHorizontalStrut(5));
		labelPanel.add(new GIconLabel(Icons.INFO_ICON));
		labelPanel.add(Box.createHorizontalStrut(5));
		labelPanel.add(mlabel);

		// the default panel is the panel that holds left-hand side label
		defaultPanel.add(labelPanel, BorderLayout.NORTH);
		defaultPanel.setBorder(BorderFactory.createLoweredBevelBorder());

		// the info panel is the holds the right-hand label and is inside of
		// a scroll pane
		infoPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
		collisionLabel = new MultiLineLabel(" ");
		collisionLabel.setName("CollisionLabel");

		infoPanel.add(collisionLabel);
		JScrollPane sp = new JScrollPane(infoPanel);
		sp.setPreferredSize(defaultPanel.getPreferredSize());

		// inner panel holds the two label panels
		JPanel innerPanel = new JPanel(new PairLayout(2, 6));
		innerPanel.add(defaultPanel);
		innerPanel.add(sp);

		keyPanel.add(innerPanel, BorderLayout.CENTER);
		keyPanel.add(p, BorderLayout.SOUTH);
		return keyPanel;
	}

	private JPanel createImportExportPanel() {
		JButton importButton = new JButton("Import...");
		importButton.setToolTipText("Load key binding settings from a file");
		importButton.addActionListener(event -> {
			// prompt user to apply changes before importing
			boolean continueImport = showImportPrompt();

			if (!continueImport) {
				return;
			}

			// give Swing a chance to repaint
			Swing.runLater(() -> {
				// clear the action to avoid the appearance of editing while restoring
				actionTable.clearSelection();
				loadKeyBindingsFromImportedOptions(KeyBindingUtils.importKeyBindings());
			});
		});

		JButton exportButton = new JButton("Export...");
		exportButton.setToolTipText("Save key binding settings to a file");
		exportButton.addActionListener(event -> {

			// prompt user to apply changes before exporting
			boolean continueExport = showApplyPrompt();

			if (!continueExport) {
				return;
			}

			// give Swing a chance to repaint
			Swing.runLater(() -> {
				ToolOptions keyBindingOptions = tool.getOptions(DockingToolConstants.KEY_BINDINGS);
				KeyBindingUtils.exportKeyBindings(keyBindingOptions);
			});
		});

		JPanel containerPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		containerPanel.add(importButton);
		containerPanel.add(exportButton);

		return containerPanel;
	}

	private boolean showApplyPrompt() {
		boolean continueOperation = true;
		if (unappliedChanges) {
			int userChoice = OptionDialog.showYesNoCancelDialog(KeyBindingsPanel.this,
				"Apply Changes?", "Apply current key binding changes?");

			// Option One--'Yes'
			if (userChoice == OptionDialog.OPTION_ONE) {
				apply();
			}
			else if (userChoice == OptionDialog.CANCEL_OPTION) {
				continueOperation = false;
			}
		}

		return continueOperation;
	}

	private boolean showImportPrompt() {
		int userChoice = OptionDialog.showYesNoDialog(KeyBindingsPanel.this, "Continue Import?",
			"Importing key bindings will overwrite the current settings.\n" +
				"Do you want to continue?");

		// option one is the yes dialog
		return (userChoice == OptionDialog.OPTION_ONE);
	}

	// puts all of the key binding options from the given options object into
	// a mapping of the option name to the key stroke for that name
	private Map<String, KeyStroke> createActionNameToKeyStrokeMap(Options keyBindingOptions) {

		Map<String, KeyStroke> localActionMap = new HashMap<>();
		List<String> optionNames = keyBindingOptions.getOptionNames();
		for (String name : optionNames) {
			ActionTrigger actionTrigger = keyBindingOptions.getActionTrigger(name, null);
			KeyStroke optionsKs = null;
			if (actionTrigger != null) {
				optionsKs = actionTrigger.getKeyStroke();
			}
			localActionMap.put(name, optionsKs);
		}
		return localActionMap;
	}

	/**
	 * Size the columns.
	 */
	private void adjustTableColumns() {
		actionTable.doLayout();
		TableColumn column = actionTable.getColumn(actionTable.getColumnName(ACTION_NAME));
		column.setPreferredWidth(250);
		column = actionTable.getColumn(actionTable.getColumnName(KEY_BINDING));
		column.setPreferredWidth(100);
		column = actionTable.getColumn(actionTable.getColumnName(PLUGIN_NAME));
		column.setPreferredWidth(150);
	}

	private void restoreDefaultKeybindings() {
		keyBindings.restoreOptions();

		// let the table know that changes may have been made
		tableModel.fireTableDataChanged();
	}

	// signals that there are unapplied changes
	private void changesMade(boolean changes) {
		propertyChangeListener.propertyChange(
			new PropertyChangeEvent(this, "apply.enabled", unappliedChanges, changes));
		unappliedChanges = changes;
	}

	private DockingActionIf getSelectedAction() {
		if (actionTable.getSelectedRowCount() == 0) {
			return null;
		}
		int selectedRow = actionTable.getSelectedRow();
		return tableFilterPanel.getRowObject(selectedRow);
	}

	private String getSelectedActionName() {
		DockingActionIf action = getSelectedAction();
		if (action == null) {
			return null;
		}
		return action.getFullName();
	}

	private void showActionsMappedToKeyStroke(KeyStroke ks) {

		String text = keyBindings.getActionsForKeyStrokeText(ks);
		if (StringUtils.isBlank(text)) {
			text = " ";
		}
		updateCollisionPanel(text);
	}

	private void clearInfoPanel() {
		updateCollisionPanel(" ");
	}

	private void updateCollisionPanel(String text) {
		infoPanel.removeAll();
		infoPanel.repaint();
		collisionLabel = new MultiLineLabel(text);
		collisionLabel.setName("CollisionLabel");
		infoPanel.add(collisionLabel);
		infoPanel.invalidate();
		validate();
	}

	private void loadKeyBindingsFromImportedOptions(Options keyBindingOptions) {
		if (keyBindingOptions == null) {
			return;
		}

		Map<String, KeyStroke> keyStrokesByActionName =
			createActionNameToKeyStrokeMap(keyBindingOptions);

		boolean changes = false;

		// add each new key stroke mapping
		for (String name : keyStrokesByActionName.keySet()) {

			KeyStroke keyStroke = keyStrokesByActionName.get(name);
			keyStroke = KeyBindingUtils.validateKeyStroke(keyStroke);

			// prevent non-existing keybindings from being added (this can happen when actions exist
			// in the imported bindings, but have been removed from the tool
			if (!keyBindings.containsAction(name)) {
				continue;
			}

			// check to see if the key stroke results in a change and
			// record that value
			changes |= setActionKeyStroke(name, keyStroke);
		}

		if (changes) {
			changesMade(true);
			tableModel.fireTableDataChanged();
		}
	}

	/**
	 * Processes KeyStroke entry from the text field.
	 */
	private void updateKeyStroke(KeyStroke ks) {
		clearInfoPanel();

		DockingActionIf action = getSelectedAction();
		if (action == null) {
			statusLabel.setText("No action is selected.");
			return;
		}

		ToolActions toolActions = (ToolActions) tool.getToolActions();
		String errorMessage = toolActions.validateActionKeyBinding(action, ks);
		if (errorMessage != null) {
			actionBindingPanel.clearKeyStroke();
			statusLabel.setText(errorMessage);
			return;
		}

		String selectedActionName = action.getFullName();
		if (setActionKeyStroke(selectedActionName, ks)) {
			showActionsMappedToKeyStroke(ks);
			tableModel.fireTableDataChanged();
			changesMade(true);
		}
	}

	private void updateMouseBinding(MouseBinding mb) {

		clearInfoPanel();

		DockingActionIf action = getSelectedAction();
		if (action == null) {
			statusLabel.setText("No action is selected.");
			return;
		}

		String selectedActionName = action.getFullName();
		if (setMouseBinding(selectedActionName, mb)) {
			tableModel.fireTableDataChanged();
			changesMade(true);
		}
	}

	private boolean setMouseBinding(String actionName, MouseBinding mouseBinding) {

		if (keyBindings.isMouseBindingInUse(actionName, mouseBinding)) {

			String existingName = keyBindings.getActionForMouseBinding(mouseBinding);
			String message = """
					Mouse binding '%s' already in use by '%s'.
					The existing binding must be cleared before it can be used again.
					""".formatted(mouseBinding, existingName);
			Msg.showInfo(this, actionBindingPanel, "Mouse Binding In Use", message);
			actionBindingPanel.clearMouseBinding();
			return false;
		}

		return keyBindings.setActionMouseBinding(actionName, mouseBinding);
	}

	// returns true if the key stroke is a new value
	private boolean setActionKeyStroke(String actionName, KeyStroke keyStroke) {
		if (!isValidKeyStroke(keyStroke)) {
			actionBindingPanel.clearKeyStroke();
			return keyBindings.removeKeyStroke(actionName);
		}

		return keyBindings.setActionKeyStroke(actionName, keyStroke);
	}

	private boolean isValidKeyStroke(KeyStroke ks) {
		if (ks == null) {
			return false;
		}
		char keyChar = ks.getKeyChar();
		return !Character.isWhitespace(keyChar) &&
			Character.getType(keyChar) != Character.DIRECTIONALITY_LEFT_TO_RIGHT_OVERRIDE;
	}

	Map<String, KeyStroke> getKeyStrokeMap() {
		return keyBindings.getKeyStrokesByFullActionName();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================
	/**
	 * Selection listener class for the table model.
	 */
	private class TableSelectionListener implements ListSelectionListener {
		@Override
		public void valueChanged(ListSelectionEvent e) {
			if (e.getValueIsAdjusting() || firingTableDataChanged) {
				return;
			}

			helpButton.setEnabled(false);
			String fullActionName = getSelectedActionName();
			if (fullActionName == null) {
				statusLabel.setText("");
				actionBindingPanel.setEnabled(false);
				return;
			}

			actionBindingPanel.setEnabled(true);

			helpButton.setEnabled(true);
			clearInfoPanel();

			KeyStroke ks = keyBindings.getKeyStroke(fullActionName);
			if (ks != null) {
				showActionsMappedToKeyStroke(ks);
			}

			MouseBinding mb = keyBindings.getMouseBinding(fullActionName);
			actionBindingPanel.setKeyBindingData(ks, mb);

			// make sure the label gets enough space
			statusLabel.setPreferredSize(
				new Dimension(statusLabel.getPreferredSize().width, STATUS_LABEL_HEIGHT));

			DockingActionIf action = getSelectedAction();
			String description = action.getDescription();
			if (description == null || description.trim().isEmpty()) {
				description = action.getName();
			}

			statusLabel.setText("<html>" + HTMLUtilities.escapeHTML(description));
		}
	}

	private class KeyBindingsTableModel extends AbstractSortedTableModel<DockingActionIf> {
		private final String[] columnNames = { "Action Name", "KeyBinding", "Plugin Name" };

		private List<DockingActionIf> actions;

		KeyBindingsTableModel(List<DockingActionIf> actions) {
			super(0);
			this.actions = actions;
		}

		@Override
		public String getName() {
			return "Keybindings";
		}

		@Override
		public Object getColumnValueForRow(DockingActionIf action, int columnIndex) {

			String fullName = action.getFullName();
			switch (columnIndex) {
				case ACTION_NAME:
					return action.getName();
				case KEY_BINDING:
					String text = "";
					KeyStroke ks = keyBindings.getKeyStroke(fullName);
					if (ks != null) {
						text += KeyBindingUtils.parseKeyStroke(ks);
					}

					MouseBinding mb = keyBindings.getMouseBinding(fullName);
					if (mb != null) {
						text += " (" + mb.getDisplayText() + ")";
					}

					return text.trim();
				case PLUGIN_NAME:
					return action.getOwnerDescription();
			}
			return "Unknown Column!";
		}

		@Override
		public List<DockingActionIf> getModelData() {
			return actions;
		}

		@Override
		public boolean isSortable(int columnIndex) {
			return true;
		}

		@Override
		public String getColumnName(int column) {
			return columnNames[column];
		}

		@Override
		public int getColumnCount() {
			return columnNames.length;
		}

		@Override
		public int getRowCount() {
			return actions.size();
		}

		@Override
		public Class<?> getColumnClass(int columnIndex) {
			return String.class;
		}
	}

	private class ActionBindingListener implements DockingActionInputBindingListener {

		@Override
		public void keyStrokeChanged(KeyStroke ks) {
			updateKeyStroke(ks);
		}

		@Override
		public void mouseBindingChanged(MouseBinding mb) {
			updateMouseBinding(mb);
		}
	}
}
