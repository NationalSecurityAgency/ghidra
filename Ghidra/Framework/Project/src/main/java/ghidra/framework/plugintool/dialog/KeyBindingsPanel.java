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
import docking.widgets.MultiLineLabel.VerticalAlignment;
import docking.widgets.table.*;
import generic.theme.Gui;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.util.Msg;
import ghidra.util.Swing;
import gui.event.MouseBinding;
import help.Help;
import help.HelpService;
import resources.Icons;

/**
 * Panel to show the key bindings for the plugin actions.
 */
public class KeyBindingsPanel extends JPanel {

	private static final String GETTING_STARTED_MESSAGE =
		"<html><i>Select an action to change a keybinding";

	private final static int ACTION_NAME = 0;
	private final static int KEY_BINDING = 1;
	private final static int PLUGIN_NAME = 2;

	private static final String FONT_ID = "font.keybindings.status";

	private JTextPane statusLabel;
	private GTable actionTable;
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

	private JPanel gettingStartedPanel;
	private JPanel activeActionPanel;

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

			restoreDefaultKeyBindings();
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

		// A stub panel to take up about the same amount of space as the active panel.  This stub 
		// panel will get swapped for the active panel when a selection is made in the table.  Using
		// the stub panel is easier than trying to visually disable the editing widgets.
		gettingStartedPanel = new JPanel();
		activeActionPanel = createActiveActionPanel();

		tableModel = new KeyBindingsTableModel(new ArrayList<>(keyBindings.getUniqueActions()));
		actionTable = new GTable(tableModel);

		JScrollPane actionsScroller = new JScrollPane(actionTable);
		actionTable.setPreferredScrollableViewportSize(new Dimension(400, 100));
		actionTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		actionTable.setHTMLRenderingEnabled(true);
		actionTable.getSelectionModel().addListSelectionListener(new TableSelectionListener());

		adjustTableColumns();

		// middle panel - filter field and import/export buttons
		JPanel importExportPanel = createImportExportPanel();
		tableFilterPanel = new GTableFilterPanel<>(actionTable, tableModel);
		JPanel filterAndExportsPanel = new JPanel(new BorderLayout());
		filterAndExportsPanel.add(tableFilterPanel, BorderLayout.NORTH);
		filterAndExportsPanel.add(importExportPanel, BorderLayout.SOUTH);

		// contains the upper panel (table and the middle panel)
		JPanel centerPanel = new JPanel(new BorderLayout());
		centerPanel.add(actionsScroller, BorderLayout.CENTER);
		centerPanel.add(filterAndExportsPanel, BorderLayout.SOUTH);

		add(centerPanel, BorderLayout.CENTER);
		add(gettingStartedPanel, BorderLayout.SOUTH);

		// make both panels the same size so that as we swap them, the UI doesn't jump
		Dimension preferredSize = activeActionPanel.getPreferredSize();
		gettingStartedPanel.setPreferredSize(preferredSize);
	}

	private JPanel createActiveActionPanel() {

		// lower panel - key entry panel and status panel
		JPanel keyPanel = createKeyEntryPanel();
		JPanel collisionAreaPanel = createCollisionArea();

		JPanel parentPanel = new JPanel(new BorderLayout());
		parentPanel.add(keyPanel, BorderLayout.NORTH);
		parentPanel.add(collisionAreaPanel, BorderLayout.SOUTH);
		return parentPanel;
	}

	private JPanel createStatusPanel() {

		statusLabel = new JTextPane();
		statusLabel.setEnabled(false);
		DockingUtils.setTransparent(statusLabel);
		statusLabel.setBorder(BorderFactory.createEmptyBorder(5, 10, 0, 5));
		statusLabel.setContentType("text/html"); // render any HTML we find in descriptions
		statusLabel.setText(GETTING_STARTED_MESSAGE);

		// make the label wide enough to show a line of text, but set a limit to force wrapping
		statusLabel.setPreferredSize(new Dimension(300, 30));
		statusLabel.setFont(Gui.getFont(FONT_ID));

		helpButton = new EmptyBorderButton(Icons.HELP_ICON);
		helpButton.setEnabled(false);
		helpButton.addActionListener(e -> {
			DockingActionIf action = getSelectedAction();
			HelpService hs = Help.getHelpService();
			hs.showHelp(action, false, KeyBindingsPanel.this);
		});

		JPanel statusPanel = new JPanel();
		statusPanel.setLayout(new BoxLayout(statusPanel, BoxLayout.LINE_AXIS));
		statusPanel.add(helpButton);
		statusPanel.add(statusLabel);

		statusPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 0, 0));

		return statusPanel;
	}

	private JPanel createKeyEntryPanel() {
		actionBindingPanel = new ActionBindingPanel(actionBindingListener);

		// add some space at the bottom of the input area to separate it from the info area
		actionBindingPanel.setBorder(BorderFactory.createEmptyBorder(10, 0, 20, 0));

		JPanel keyPanel = new JPanel(new BorderLayout());
		keyPanel.add(actionBindingPanel, BorderLayout.NORTH);
		return keyPanel;
	}

	private JPanel createCollisionArea() {

		collisionLabel = new MultiLineLabel(" ");
		collisionLabel.setVerticalAlignment(VerticalAlignment.TOP);
		collisionLabel.setName("CollisionLabel");
		JScrollPane collisionScroller = new JScrollPane(collisionLabel);
		int height = 100; // enough to show the typical number of collisions without scrolling
		collisionScroller.setPreferredSize(new Dimension(400, height));

		// note: we add a strut so that when the scroll pane is hidden, the size does not change
		JPanel parentPanel = new JPanel(new BorderLayout());
		parentPanel.add(collisionScroller, BorderLayout.CENTER);
		parentPanel.add(Box.createVerticalStrut(height), BorderLayout.WEST);

		JPanel alignmentPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		alignmentPanel.add(parentPanel);

		return alignmentPanel;
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

		JPanel statusPanel = createStatusPanel();

		JPanel buttonPanel = new JPanel();
		buttonPanel.add(importButton);
		buttonPanel.add(exportButton);

		JPanel parentPanel = new JPanel(new BorderLayout());
		parentPanel.add(statusPanel, BorderLayout.WEST);
		parentPanel.add(buttonPanel, BorderLayout.EAST);
		return parentPanel;
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

	private void restoreDefaultKeyBindings() {
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

		// Hide the scroll pane when there is nothing to show
		Container parent = collisionLabel.getParent().getParent();
		if (text.isBlank()) {
			parent.setVisible(false);
		}
		else {
			parent.setVisible(true);
		}

		collisionLabel.setLabel(text);
		collisionLabel.invalidate();
		validate();
		repaint();
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
			statusLabel.setText(GETTING_STARTED_MESSAGE);
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
			fireRowChanged();
			changesMade(true);
		}
	}

	private void updateMouseBinding(MouseBinding mb) {

		clearInfoPanel();

		DockingActionIf action = getSelectedAction();
		if (action == null) {
			statusLabel.setText(GETTING_STARTED_MESSAGE);
			return;
		}

		String selectedActionName = action.getFullName();
		if (setMouseBinding(selectedActionName, mb)) {
			fireRowChanged();
			changesMade(true);
		}
	}

	private void fireRowChanged() {
		int viewRow = actionTable.getSelectedRow();
		int modelRow = tableFilterPanel.getModelRow(viewRow);
		tableModel.fireTableRowsUpdated(modelRow, modelRow);
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

	private void swapView(JComponent newView) {

		// the lower panel we want to swap is at index 1 (index 0 is the table area)
		Component component = getComponent(1);
		if (component == newView) {
			return; // nothing to do
		}

		remove(component);
		add(newView, BorderLayout.SOUTH);
		Container parent = getParent();
		parent.validate();
		parent.repaint();
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

			DockingActionIf action = getSelectedAction();
			if (action == null) {
				swapView(gettingStartedPanel);

				statusLabel.setText(GETTING_STARTED_MESSAGE);
				actionBindingPanel.setEnabled(false);
				helpButton.setToolTipText("Select action in table for help");
				return;
			}

			String fullActionName = getSelectedActionName();

			swapView(activeActionPanel);

			actionBindingPanel.setEnabled(true);
			helpButton.setEnabled(true);
			clearInfoPanel();

			KeyStroke ks = keyBindings.getKeyStroke(fullActionName);
			if (ks != null) {
				showActionsMappedToKeyStroke(ks);
			}

			MouseBinding mb = keyBindings.getMouseBinding(fullActionName);
			actionBindingPanel.setKeyBindingData(ks, mb);

			String description = action.getDescription();
			if (StringUtils.isBlank(description)) {
				description = action.getName();
			}

			// Not sure why we escape the html here. Probably just to be safe.
			statusLabel.setText("<html>" + description);
			helpButton.setToolTipText("Help for " + action.getName());
		}
	}

	private class KeyBindingsTableModel
			extends GDynamicColumnTableModel<DockingActionIf, Object> {

		private List<DockingActionIf> actions;

		public KeyBindingsTableModel(List<DockingActionIf> actions) {
			super(new ServiceProviderStub());
			this.actions = actions;
		}

		@Override
		protected TableColumnDescriptor<DockingActionIf> createTableColumnDescriptor() {
			TableColumnDescriptor<DockingActionIf> descriptor = new TableColumnDescriptor<>();
			descriptor.addVisibleColumn("Action Name", String.class, a -> a.getName(), 1, true);
			descriptor.addVisibleColumn("Key Binding", String.class, a -> {
				String text = "";
				String fullName = a.getFullName();
				KeyStroke ks = keyBindings.getKeyStroke(fullName);
				if (ks != null) {
					text += KeyBindingUtils.parseKeyStroke(ks);
				}

				MouseBinding mb = keyBindings.getMouseBinding(fullName);
				if (mb != null) {
					text += " (" + mb.getDisplayText() + ")";
				}

				return text.trim();
			});
			descriptor.addVisibleColumn("Owner", String.class, a -> a.getOwnerDescription());
			descriptor.addHiddenColumn("Description", String.class, a -> a.getDescription());
			return descriptor;
		}

		@Override
		public String getName() {
			return "Key Bindings";
		}

		@Override
		public List<DockingActionIf> getModelData() {
			return actions;
		}

		@Override
		public Object getDataSource() {
			return null;
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
