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

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.table.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.table.DefaultSortedTableModel;
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

	/**
	 * Construct instance settings dialog.
	 */
	public SettingsDialog(HelpLocation help) {
		super("Settings", true, false, true, false);
		if (help != null) {
			setHelpLocation(help);
		}
		addWorkPanel(buildWorkPanel());
		addDismissButton();

		setHelpLocation(new HelpLocation("Tables/GhidraTableHeaders.html", "ColumnSettings"));
	}

	/**
	 * Show dialog for the specified set of settings definitions and settings storage.
	 */
	public void show(Component parent, String title, SettingsDefinition[] newSettingsDefs,
			Settings newSettings) {
		this.settingsDefs = newSettingsDefs;
		this.settings = newSettings;
		setTitle(title);
		settingsTableModel.fireTableDataChanged();
		DockingWindowManager.showDialog(parent, this);
	}

	public void dispose() {
		settingsTable.editingStopped(null);

		close();
		settingsDefs = null;
		settings = null;
	}

	private JPanel buildWorkPanel() {
		JPanel workPanel = new JPanel(new BorderLayout());
		workPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

		settingsTableModel = new SettingsTableModel();

		DefaultSortedTableModel sorter = new DefaultSortedTableModel(settingsTableModel);
		sorter.sortByColumn(SettingsTableModel.DEFAULT_SORT_COL);

		settingsTable = new GTable(sorter);
		settingsTable.setAutoscrolls(true);
		settingsTable.setRowSelectionAllowed(false);
		settingsTable.setColumnSelectionAllowed(false);

		// disable user sorting and column adding (we don't expect enough data to require sort
		// changes)
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

	/**
	 * @see ghidra.util.bean.GhidraDialog#cancelCallback()
	 */
	@Override
	protected void cancelCallback() {
		dispose();
	}

	class SettingsTableModel extends AbstractTableModel {

		static final int DEFAULT_SORT_COL = 0;

		@Override
		public int getColumnCount() {
			return 2;
		}

		@Override
		public int getRowCount() {
			return settingsDefs != null ? settingsDefs.length : 0;
		}

		@Override
		public Object getValueAt(int row, int col) {
			switch (col) {
				case 0:
					return settingsDefs[row].getName();
				case 1:
					if (settingsDefs[row] instanceof EnumSettingsDefinition) {
						EnumSettingsDefinition def = (EnumSettingsDefinition) settingsDefs[row];
						StringChoices choices = new StringChoices(def.getDisplayChoices(settings));
						choices.setSelectedValue(def.getChoice(settings));
						return choices;
					}
					else if (settingsDefs[row] instanceof BooleanSettingsDefinition) {
						BooleanSettingsDefinition def =
							(BooleanSettingsDefinition) settingsDefs[row];
						return new Boolean(def.getValue(settings));
					}
					return "<Unsupported>";
			}
			return null;
		}

		/**
		 * @see TableModel#setValueAt(Object, int, int)
		 */
		@Override
		public void setValueAt(Object value, int row, int col) {
			switch (col) {
				case 1:
					if (settingsDefs[row] instanceof EnumSettingsDefinition) {
						EnumSettingsDefinition def = (EnumSettingsDefinition) settingsDefs[row];
						StringChoices choices = (StringChoices) value;
						def.setChoice(settings, choices.getSelectedValueIndex());
						fireTableDataChanged();
					}
					else if (settingsDefs[row] instanceof BooleanSettingsDefinition) {
						BooleanSettingsDefinition def =
							(BooleanSettingsDefinition) settingsDefs[row];
						def.setValue(settings, ((Boolean) value).booleanValue());
						fireTableDataChanged();
					}
					break;

				case 2:
					if (((Boolean) value).booleanValue()) {
						settingsDefs[row].clear(settings);
						fireTableDataChanged();
					}
					break;
			}
		}

		/**
		 * @see TableModel#getColumnName(int)
		 */
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

		/**
		 * @see TableModel#getColumnClass(int)
		 */
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

		public boolean isColumnSortable(int col) {
			return col == 0;
		}

		/**
		 * @see TableModel#isCellEditable(int, int)
		 */
		@Override
		public boolean isCellEditable(int row, int col) {
			return col != 0;
		}

	}

	private class SettingsEditor extends AbstractCellEditor implements TableCellEditor,
			PopupMenuListener {

		final static int ENUM = 0;
		final static int BOOLEAN = 1;

		private int mode;
		private JComboBox comboBox = new JComboBox();
		private JCheckBox checkBox = new JCheckBox();

		private final Runnable editStopped = new Runnable() {
			@Override
			public void run() {
				fireEditingStopped();
			}
		};

		SettingsEditor() {
			super();
			comboBox.addPopupMenuListener(this);
		}

		/**
		 * @see javax.swing.CellEditor#getCellEditorValue()
		 */
		@Override
		public Object getCellEditorValue() {
			switch (mode) {
				case ENUM:
					return getComboBoxEnum();
				case BOOLEAN:
					return new Boolean(checkBox.isSelected());
			}
			throw new AssertException();
		}

		private StringChoices getComboBoxEnum() {
			String[] items = new String[comboBox.getItemCount()];
			for (int i = 0; i < items.length; i++) {
				items[i] = (String) comboBox.getItemAt(i);
			}
			StringChoices choices = new StringChoices(items);
			choices.setSelectedValue(comboBox.getSelectedIndex());
			return choices;
		}

		/**
		 * @see javax.swing.table.TableCellEditor#getTableCellEditorComponent(javax.swing.JTable, java.lang.Object, boolean, int, int)
		 */
		@Override
		public Component getTableCellEditorComponent(JTable table, Object value,
				boolean isSelected, int row, int column) {
			if (value instanceof StringChoices) {
				initComboBox((StringChoices) value);
				return comboBox;
			}
			else if (value instanceof Boolean) {
				initCheckBox((Boolean) value);
				return checkBox;
			}
			throw new AssertException("SettingsEditor: " + value.getClass().getName() +
				" not supported");
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

		/**
		 * @see javax.swing.event.PopupMenuListener#popupMenuWillBecomeVisible(javax.swing.event.PopupMenuEvent)
		 */
		@Override
		public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
		}

		/**
		 * @see javax.swing.event.PopupMenuListener#popupMenuWillBecomeInvisible(javax.swing.event.PopupMenuEvent)
		 */
		@Override
		public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
			SwingUtilities.invokeLater(editStopped);
		}

		/**
		 * @see javax.swing.event.PopupMenuListener#popupMenuCanceled(javax.swing.event.PopupMenuEvent)
		 */
		@Override
		public void popupMenuCanceled(PopupMenuEvent e) {
		}

	}
}
