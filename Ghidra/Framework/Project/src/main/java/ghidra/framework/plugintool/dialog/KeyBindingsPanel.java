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
import java.util.Map.Entry;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableColumn;

import docking.DockingUtils;
import docking.KeyEntryTextField;
import docking.action.DockingActionIf;
import docking.action.KeyBindingData;
import docking.actions.KeyBindingUtils;
import docking.help.Help;
import docking.help.HelpService;
import docking.tool.util.DockingToolConstants;
import docking.widgets.*;
import docking.widgets.label.GIconLabel;
import docking.widgets.table.*;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.*;
import ghidra.util.exception.AssertException;
import ghidra.util.layout.PairLayout;
import ghidra.util.layout.VerticalLayout;
import resources.Icons;
import resources.ResourceManager;

/**
 * Panel to show the key bindings for the plugin actions.
 */
public class KeyBindingsPanel extends JPanel {

	private static final int STATUS_LABEL_HEIGHT = 60;

	private final static int ACTION_NAME = 0;
	private final static int KEY_BINDING = 1;
	private final static int PLUGIN_NAME = 2;

	private static final int FONT_SIZE = 11;

	private JTextPane statusLabel;
	private GTable actionTable;
	private JPanel infoPanel;
	private MultiLineLabel collisionLabel;
	private KeyBindingsTableModel tableModel;
	private ListSelectionModel selectionModel;
	private Options options;

	private Map<String, List<DockingActionIf>> actionsByFullName;
	private Map<String, List<String>> actionNamesByKeyStroke = new HashMap<>();
	private Map<String, KeyStroke> keyStrokesByFullName = new HashMap<>();
	private Map<String, KeyStroke> originalValues = new HashMap<>(); // to know what has been changed
	private List<DockingActionIf> tableActions = new ArrayList<>();

	private KeyEntryTextField ksField;
	private boolean unappliedChanges;

	private PluginTool tool;
	private boolean firingTableDataChanged;
	private PropertyChangeListener propertyChangeListener;
	private GTableFilterPanel<DockingActionIf> tableFilterPanel;
	private EmptyBorderButton helpButton;

	public KeyBindingsPanel(PluginTool tool, Options options) {
		this.tool = tool;
		this.options = options;

		createPanelComponents();
		createActionMap();
		addListeners();
	}

	public void setOptionsPropertyChangeListener(PropertyChangeListener listener) {
		this.propertyChangeListener = listener;
	}

	public void dispose() {
		tableFilterPanel.dispose();
		propertyChangeListener = null;
	}

	public void apply() {
		Iterator<String> iter = keyStrokesByFullName.keySet().iterator();
		while (iter.hasNext()) {
			String actionName = iter.next();
			KeyStroke currentKeyStroke = keyStrokesByFullName.get(actionName);
			KeyStroke originalKeyStroke = originalValues.get(actionName);
			updateOptions(actionName, originalKeyStroke, currentKeyStroke);
		}

		changesMade(false);
	}

	private void updateOptions(String fullActionName, KeyStroke currentKeyStroke,
			KeyStroke newKeyStroke) {

		if (Objects.equals(currentKeyStroke, newKeyStroke)) {
			return;
		}

		options.setKeyStroke(fullActionName, newKeyStroke);
		originalValues.put(fullActionName, newKeyStroke);
		keyStrokesByFullName.put(fullActionName, newKeyStroke);

		List<DockingActionIf> actions = actionsByFullName.get(fullActionName);
		for (DockingActionIf action : actions) {
			action.setUnvalidatedKeyBindingData(new KeyBindingData(newKeyStroke));
		}

	}

	public void cancel() {
		Iterator<String> iter = originalValues.keySet().iterator();
		while (iter.hasNext()) {
			String actionName = iter.next();
			KeyStroke originalKS = originalValues.get(actionName);
			KeyStroke modifiedKS = keyStrokesByFullName.get(actionName);
			if (modifiedKS != null && !modifiedKS.equals(originalKS)) {
				keyStrokesByFullName.put(actionName, originalKS);
			}
		}
		tableModel.fireTableDataChanged();
	}

	public void reload() {
		Swing.runLater(() -> {
			// clear the current user key stroke so that it does not appear as though the 
			// user is editing while restoring
			actionTable.clearSelection();

			restoreDefaultKeybindings();
		});
	}

	private void createActionMap() {

		String longestName = "";

		actionsByFullName = KeyBindingUtils.getAllActionsByFullName(tool);
		Set<Entry<String, List<DockingActionIf>>> entries = actionsByFullName.entrySet();
		for (Entry<String, List<DockingActionIf>> entry : entries) {

			// pick one action, they are all conceptually the same
			List<DockingActionIf> actions = entry.getValue();
			DockingActionIf action = actions.get(0);
			tableActions.add(action);

			String actionName = entry.getKey();
			KeyStroke ks = options.getKeyStroke(actionName, null);
			keyStrokesByFullName.put(actionName, ks);
			addToKeyMap(ks, actionName);
			originalValues.put(actionName, ks);

			String shortName = action.getName();
			if (shortName.length() > longestName.length()) {
				longestName = shortName;
			}
		}

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

		tableModel = new KeyBindingsTableModel();
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
	}

	private JPanel createStatusPanel(JPanel keyPanel) {

		statusLabel = new JTextPane();
		statusLabel.setEnabled(false);
		DockingUtils.setTransparent(statusLabel);
		statusLabel.setBorder(BorderFactory.createEmptyBorder(5, 10, 0, 5));
		statusLabel.setContentType("text/html"); // render any HTML we find in descriptions

		// make sure the label gets enough space
		statusLabel.setPreferredSize(new Dimension(0, STATUS_LABEL_HEIGHT));

		Font f = new Font("SansSerif", Font.PLAIN, FONT_SIZE);
		statusLabel.setFont(f);

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
		ksField = new KeyEntryTextField(20, keyStroke -> processKeyStrokeEntry(keyStroke));

		// this is the lower panel that holds the key entry text field
		JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT));
		p.add(ksField);

		JPanel keyPanel = new JPanel(new BorderLayout());

		JPanel defaultPanel = new JPanel(new BorderLayout());

		// the content of the left-hand side label
		MultiLineLabel mlabel =
			new MultiLineLabel("To add or change a key binding, select an action\n" +
				"and type any key combination\n \n" +
				"To remove a key binding, select an action and\n" +
				"press <Enter> or <Backspace>");
		JPanel labelPanel = new JPanel();
		labelPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 0, 0));
		BoxLayout bl = new BoxLayout(labelPanel, BoxLayout.X_AXIS);
		labelPanel.setLayout(bl);
		labelPanel.add(Box.createHorizontalStrut(5));
		labelPanel.add(new GIconLabel(ResourceManager.loadImage("images/information.png")));
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
				// clear the current user key stroke so that it does not appear as though the 
				// user is editing while importing
				actionTable.clearSelection();
				processKeyBindingsFromOptions(KeyBindingUtils.importKeyBindings());
			});
		});

		JButton exportButton = new JButton("Export...");
		exportButton.setToolTipText("Save key binding settings to a file");
		exportButton.addActionListener(event -> {

			// prompt user to apply changes before exporting
			boolean continueExport = showExportPrompt();

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

	private boolean showExportPrompt() {
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

		for (String element : optionNames) {
			KeyStroke newKeyStroke = keyBindingOptions.getKeyStroke(element, null);
			localActionMap.put(element, newKeyStroke);
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
		Iterator<String> iter = keyStrokesByFullName.keySet().iterator();
		while (iter.hasNext()) {
			String actionName = iter.next();
			List<DockingActionIf> actions = actionsByFullName.get(actionName);
			if (actions.isEmpty()) {
				throw new AssertException("No actions defined for " + actionName);
			}

			// pick one action, they are all conceptually the same
			DockingActionIf action = actions.get(0);
			KeyStroke currentKeyStroke = keyStrokesByFullName.get(actionName);
			KeyBindingData defaultBinding = action.getDefaultKeyBindingData();
			KeyStroke newKeyStroke =
				(defaultBinding == null) ? null : defaultBinding.getKeyBinding();

			updateOptions(actionName, currentKeyStroke, newKeyStroke);
		}

		// let the table know that changes may have been made
		tableModel.fireTableDataChanged();
	}

	private void addListeners() {
		selectionModel = actionTable.getSelectionModel();
		selectionModel.addListSelectionListener(new TableSelectionListener());
	}

	private boolean checkAction(String actionName, KeyStroke keyStroke) {
		String ksName = KeyEntryTextField.parseKeyStroke(keyStroke);

		// remove old keystroke for action name
		KeyStroke oldKs = keyStrokesByFullName.get(actionName);
		if (oldKs != null) {
			String oldName = KeyEntryTextField.parseKeyStroke(oldKs);
			if (oldName.equals(ksName)) {
				return false;
			}
			removeFromKeyMap(oldKs, actionName);
		}
		addToKeyMap(keyStroke, actionName);

		keyStrokesByFullName.put(actionName, keyStroke);
		changesMade(true);
		return true;
	}

	// signals that there are unapplied changes
	private void changesMade(boolean changes) {
		propertyChangeListener.propertyChange(
			new PropertyChangeEvent(this, "apply.enabled", unappliedChanges, changes));
		unappliedChanges = changes;
	}

	private DockingActionIf getSelectedAction() {
		if (selectionModel.isSelectionEmpty()) {
			return null;
		}
		int selectedRow = actionTable.getSelectedRow();
		int modelRow = tableFilterPanel.getModelRow(selectedRow);
		return tableActions.get(modelRow);
	}

	private String getSelectedActionName() {
		DockingActionIf action = getSelectedAction();
		if (action == null) {
			return null;
		}
		return action.getFullName();
	}

	private void addToKeyMap(KeyStroke ks, String actionName) {
		if (ks == null) {
			return;
		}
		String ksName = KeyEntryTextField.parseKeyStroke(ks);
		List<String> list = actionNamesByKeyStroke.get(ksName);
		if (list == null) {
			list = new ArrayList<>();
			actionNamesByKeyStroke.put(ksName, list);
		}
		if (!list.contains(actionName)) {
			list.add(actionName);
		}
	}

	private void removeFromKeyMap(KeyStroke ks, String actionName) {
		if (ks == null) {
			return;
		}
		String ksName = KeyEntryTextField.parseKeyStroke(ks);
		List<String> list = actionNamesByKeyStroke.get(ksName);
		if (list != null) {
			list.remove(actionName);
			if (list.isEmpty()) {
				actionNamesByKeyStroke.remove(ksName);
			}
		}
	}

	private void showActionsMappedToKeyStroke(String ksName) {
		List<String> list = actionNamesByKeyStroke.get(ksName);
		if (list == null) {
			return;
		}
		if (list.size() > 0) {
			StringBuffer sb = new StringBuffer();
			sb.append("Actions mapped to key " + ksName + ":\n");
			for (int i = 0; i < list.size(); i++) {
				sb.append("  ");
				sb.append(list.get(i));
				if (i < list.size() - 1) {
					sb.append("\n");
				}
			}
			updateInfoPanel(sb.toString());
		}
		else {
			clearInfoPanel();
		}
	}

	private void clearInfoPanel() {
		updateInfoPanel(" ");
	}

	private void updateInfoPanel(String text) {
		infoPanel.removeAll();
		infoPanel.repaint();
		collisionLabel = new MultiLineLabel(text);
		collisionLabel.setName("CollisionLabel");
		infoPanel.add(collisionLabel);
		infoPanel.invalidate();
		validate();
	}

	private void processKeyBindingsFromOptions(Options keyBindingOptions) {
		if (keyBindingOptions == null) {
			return;
		}

		Map<String, KeyStroke> keyBindingsMap = createActionNameToKeyStrokeMap(keyBindingOptions);
		if (keyBindingsMap == null) {
			return;
		}

		boolean changes = false;

		// add each new key stroke mapping
		Iterator<String> iterator = keyBindingsMap.keySet().iterator();
		while (iterator.hasNext()) {

			String name = iterator.next();
			KeyStroke keyStroke = keyBindingsMap.get(name);
			keyStroke = KeyBindingUtils.validateKeyStroke(keyStroke);

			// prevent non-existing keybindings from being added to Ghidra (this can happen
			// when actions exist in the imported bindings, but have been removed from
			// Ghidra
			if (!keyStrokesByFullName.containsKey(name)) {
				continue;
			}

			// check to see if the key stroke results in a change and
			// record that value
			changes |= processKeyStroke(name, keyStroke);
		}

		if (changes) {
			changesMade(true);
		}
	}

	/**
	 * Processes KeyStroke entry from the text field.
	 */
	private void processKeyStrokeEntry(KeyStroke ks) {
		clearInfoPanel();

		// An action must be selected
		if (selectionModel.isSelectionEmpty()) {
			statusLabel.setText("No action is selected.");
			return;
		}

		if (ks != null && ReservedKeyBindings.isReservedKeystroke(ks)) {
			statusLabel.setText(KeyEntryTextField.parseKeyStroke(ks) + " is a reserved keystroke");
			ksField.clearField();
			return;
		}

		String selectedActionName = getSelectedActionName();
		if (selectedActionName != null) {
			if (processKeyStroke(selectedActionName, ks)) {
				String keyStrokeText = KeyEntryTextField.parseKeyStroke(ks);
				showActionsMappedToKeyStroke(keyStrokeText);
				tableModel.fireTableDataChanged();
			}
		}
	}

	// returns true if the key stroke is a new value
	private boolean processKeyStroke(String actionName, KeyStroke keyStroke) {
		// Clear entry if enter or backspace
		if (keyStroke == null) {
			removeKeystroke(actionName);
		}
		else {
			char keyChar = keyStroke.getKeyChar();
			if (Character.isWhitespace(keyChar) ||
				Character.getType(keyChar) == Character.DIRECTIONALITY_LEFT_TO_RIGHT_OVERRIDE) {
				removeKeystroke(actionName);
			}
			else {
				// check the action to see if is different than the current value
				return checkAction(actionName, keyStroke);
			}
		}

		return false;
	}

	private void removeKeystroke(String selectedActionName) {
		ksField.setText("");

		if (keyStrokesByFullName.containsKey(selectedActionName)) {
			KeyStroke stroke = keyStrokesByFullName.get(selectedActionName);
			if (stroke == null) {
				// nothing to remove; nothing has changed
				return;
			}

			removeFromKeyMap(stroke, selectedActionName);
			keyStrokesByFullName.put(selectedActionName, null);
			tableModel.fireTableDataChanged();
			changesMade(true);
		}
	}

	Map<String, KeyStroke> getKeyStrokeMap() {
		return keyStrokesByFullName;
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
				return;
			}

			helpButton.setEnabled(true);
			KeyStroke ks = keyStrokesByFullName.get(fullActionName);
			String ksName = "";
			clearInfoPanel();

			if (ks != null) {
				ksName = KeyEntryTextField.parseKeyStroke(ks);
				showActionsMappedToKeyStroke(ksName);
			}

			ksField.setText(ksName);

			// make sure the label gets enough space
			statusLabel.setPreferredSize(
				new Dimension(statusLabel.getPreferredSize().width, STATUS_LABEL_HEIGHT));

			// pick one action, they are all conceptually the same
			List<DockingActionIf> actions = actionsByFullName.get(fullActionName);
			DockingActionIf action = actions.get(0);
			String description = action.getDescription();
			if (description == null || description.trim().isEmpty()) {
				description = action.getName();
			}

			statusLabel.setText("<html>" + HTMLUtilities.escapeHTML(description));
		}
	}

	private class KeyBindingsTableModel extends AbstractSortedTableModel<DockingActionIf> {
		private final String[] columnNames =
			{ "Action Name", "KeyBinding", "Plugin Name" };

		KeyBindingsTableModel() {
			super(0);
		}

		@Override
		public String getName() {
			return "Keybindings";
		}

		@Override
		public Object getColumnValueForRow(DockingActionIf action, int columnIndex) {

			switch (columnIndex) {
				case ACTION_NAME:
					return action.getName();
				case KEY_BINDING:
					KeyStroke ks = keyStrokesByFullName.get(action.getFullName());
					if (ks != null) {
						return KeyEntryTextField.parseKeyStroke(ks);
					}
					return "";
				case PLUGIN_NAME:
					return action.getOwnerDescription();
			}
			return "Unknown Column!";
		}

		@Override
		public List<DockingActionIf> getModelData() {
			return tableActions;
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
			return tableActions.size();
		}

		@Override
		public Class<?> getColumnClass(int columnIndex) {
			return String.class;
		}
	}
}
