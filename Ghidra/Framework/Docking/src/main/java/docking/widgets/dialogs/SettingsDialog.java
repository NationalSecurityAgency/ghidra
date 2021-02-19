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
package docking.widgets.dialogs;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellEditor;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GComboBox;
import docking.widgets.table.AbstractSortedTableModel;
import docking.widgets.table.GTable;
import ghidra.docking.settings.*;
import ghidra.util.HelpLocation;
import ghidra.util.exception.AssertException;

public class SettingsDialog extends DialogComponentProvider {

	private final static int WIDTH = 300;
	private final static int HEIGHT = 150;

	private SettingsDefinition[] settingsDefs;
	private Settings settings;

	private SettingsTableModel settingsTableModel;
	private GTable settingsTable;

	public SettingsDialog(HelpLocation help) {
		super("Settings", true, false, true, false);
		if (help != null) {
			setHelpLocation(help);
		}

		setTransient(true);
		addWorkPanel(buildWorkPanel());
		addDismissButton();

		setHelpLocation(new HelpLocation("Tables/GhidraTableHeaders.html", "ColumnSettings"));
	}

	public void show(Component parent, String title, SettingsDefinition[] newSettingsDefs,
			Settings newSettings) {
		this.settingsDefs = newSettingsDefs;
		this.settings = newSettings;
		setTitle(title);

		settingsTableModel.setSettingsDefinitions(settingsDefs);
		DockingWindowManager.showDialog(parent, this);
	}

	public void dispose() {
		settingsTable.editingStopped(null);
		settingsTable.dispose();

		close();
		settingsDefs = null;
		settings = null;
	}

	private JPanel buildWorkPanel() {
		JPanel workPanel = new JPanel(new BorderLayout());
		workPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

		settingsTableModel = new SettingsTableModel();
		settingsTable = new GTable(settingsTableModel);
		settingsTable.setAutoscrolls(true);
		settingsTable.setRowSelectionAllowed(false);
		settingsTable.setColumnSelectionAllowed(false);

		// disable sorting and column adding (we don't expect enough data to require sort changes)
		settingsTable.getTableHeader().setReorderingAllowed(false);
		settingsTable.setColumnHeaderPopupEnabled(false);
		settingsTable.setUserSortingEnabled(false);

		settingsTable.setDefaultRenderer(Settings.class, new DefaultTableCellRenderer());
		settingsTable.setDefaultEditor(Settings.class, new SettingsEditor());

		JScrollPane scrollpane = new JScrollPane(settingsTable);
		scrollpane.setPreferredSize(new Dimension(WIDTH, HEIGHT));

		workPanel.add(scrollpane, BorderLayout.CENTER);

		return workPanel;
	}

	@Override
	protected void cancelCallback() {
		dispose();
	}

	public GTable getTable() {
		return settingsTable;
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private class SettingsRowObject {

		private SettingsDefinition definition;

		SettingsRowObject(SettingsDefinition definition) {
			this.definition = definition;
		}

		public String getName() {
			return definition.getName();
		}

		Object getSettingsChoices() {
			if (definition instanceof EnumSettingsDefinition) {
				EnumSettingsDefinition def = (EnumSettingsDefinition) definition;
				StringChoices choices = new StringChoices(def.getDisplayChoices(settings));
				choices.setSelectedValue(def.getChoice(settings));
				return choices;
			}
			else if (definition instanceof BooleanSettingsDefinition) {
				BooleanSettingsDefinition def = (BooleanSettingsDefinition) definition;
				return Boolean.valueOf(def.getValue(settings));
			}
			return "<Unsupported>";
		}

		boolean setSettingsChoice(Object value) {
			if (definition instanceof EnumSettingsDefinition) {
				EnumSettingsDefinition def = (EnumSettingsDefinition) definition;
				StringChoices choices = (StringChoices) value;
				def.setChoice(settings, choices.getSelectedValueIndex());
				return true;
			}
			else if (definition instanceof BooleanSettingsDefinition) {
				BooleanSettingsDefinition def = (BooleanSettingsDefinition) definition;
				def.setValue(settings, ((Boolean) value).booleanValue());
				return true;
			}

			return false;
		}

		void clear(Settings s) {
			definition.clear(s);
		}
	}

	private class SettingsTableModel extends AbstractSortedTableModel<SettingsRowObject> {

		private List<SettingsRowObject> rows = new ArrayList<>();

		void setSettingsDefinitions(SettingsDefinition[] settingsDefs) {
			for (SettingsDefinition sd : settingsDefs) {
				rows.add(new SettingsRowObject(sd));
			}

			settingsTableModel.fireTableDataChanged();
		}

		@Override
		public List<SettingsRowObject> getModelData() {
			return rows;
		}

		@Override
		public String getName() {
			return "Settings Definition Model";
		}

		@Override
		public boolean isSortable(int columnIndex) {
			return columnIndex == 0;
		}

		@Override
		public boolean isCellEditable(int row, int col) {
			return col != 0;
		}

		@Override
		public int getColumnCount() {
			return 2;
		}

		@Override
		public String getColumnName(int col) {
			switch (col) {
				case 0:
					return "Name";
				case 1:
					return "Settings";
			}
			return null;
		}

		@Override
		public Class<?> getColumnClass(int col) {
			switch (col) {
				case 0:
					return String.class;
				case 1:
					return Settings.class;
			}
			return null;
		}

		@Override
		public Object getColumnValueForRow(SettingsRowObject t, int columnIndex) {
			switch (columnIndex) {
				case 0:
					return t.getName();
				case 1:
					return t.getSettingsChoices();
			}
			return null;
		}

		@Override
		public void setValueAt(Object value, int row, int col) {
			SettingsRowObject rowObject = rows.get(row);
			switch (col) {
				case 1:
					if (rowObject.setSettingsChoice(value)) {
						fireTableDataChanged();
					}
					break;
				case 2:
					if (((Boolean) value).booleanValue()) {
						rowObject.clear(settings);
						fireTableDataChanged();
					}
					break;
			}
		}
	}

	private class SettingsEditor extends AbstractCellEditor
			implements TableCellEditor, PopupMenuListener {

		final static int ENUM = 0;
		final static int BOOLEAN = 1;

		private int mode;
		private GComboBox<String> comboBox = new GComboBox<>();
		private GCheckBox checkBox = new GCheckBox();

		private final Runnable editStopped = () -> fireEditingStopped();

		SettingsEditor() {
			super();
			comboBox.addPopupMenuListener(this);
		}

		@Override
		public Object getCellEditorValue() {
			switch (mode) {
				case ENUM:
					return getComboBoxEnum();
				case BOOLEAN:
					return checkBox.isSelected();
			}
			throw new AssertException();
		}

		private StringChoices getComboBoxEnum() {
			String[] items = new String[comboBox.getItemCount()];
			for (int i = 0; i < items.length; i++) {
				items[i] = comboBox.getItemAt(i);
			}
			StringChoices choices = new StringChoices(items);
			choices.setSelectedValue(comboBox.getSelectedIndex());
			return choices;
		}

		@Override
		public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected,
				int row, int column) {
			if (value instanceof StringChoices) {
				initComboBox((StringChoices) value);
				return comboBox;
			}
			else if (value instanceof Boolean) {
				initCheckBox((Boolean) value);
				return checkBox;
			}
			throw new AssertException(
				"SettingsEditor: " + value.getClass().getName() + " not supported");
		}

		private void initCheckBox(Boolean b) {
			mode = BOOLEAN;
			checkBox.setSelected(b.booleanValue());
		}

		private void initComboBox(StringChoices choices) {
			mode = ENUM;
			comboBox.removeAllItems();
			String[] items = choices.getValues();
			for (String item : items) {
				comboBox.addItem(item);
			}
			comboBox.setSelectedIndex(choices.getSelectedValueIndex());
		}

		@Override
		public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
			// stub
		}

		@Override
		public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
			SwingUtilities.invokeLater(editStopped);
		}

		@Override
		public void popupMenuCanceled(PopupMenuEvent e) {
			// stub
		}

	}
}
