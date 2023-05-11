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
package docking.theme.gui;

import java.awt.BorderLayout;
import java.awt.event.*;
import java.beans.PropertyChangeEvent;

import javax.swing.*;
import javax.swing.table.TableColumn;

import docking.ActionContext;
import docking.action.ActionContextProvider;
import docking.widgets.table.GFilterTable;
import docking.widgets.table.GTable;
import generic.theme.IconValue;
import generic.theme.ThemeManager;
import ghidra.util.Swing;

/**
 * Icon Table for Theme Dialog
 */
public class ThemeIconTable extends JPanel implements ActionContextProvider, ThemeTable {

	private ThemeIconTableModel iconTableModel;
	private IconValueEditor iconEditor = new IconValueEditor(this::iconValueChanged);
	private GTable table;
	private GFilterTable<IconValue> filterTable;
	private ThemeManager themeManager;

	public ThemeIconTable(ThemeManager themeManager, GThemeValuesCache valuesProvider) {
		super(new BorderLayout());
		this.themeManager = themeManager;
		iconTableModel = new ThemeIconTableModel(valuesProvider);
		filterTable = new GFilterTable<>(iconTableModel);
		table = filterTable.getTable();
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		table.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					IconValue iconValue = filterTable.getSelectedRowObject();
					if (iconValue != null) {
						iconEditor.editValue(iconValue);
					}
					e.consume();
				}
			}
		});

		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					IconValue value = filterTable.getItemAt(e.getPoint());

					int col = filterTable.getColumn(e.getPoint());
					TableColumn column = table.getColumnModel().getColumn(col);
					Object identifier = column.getIdentifier();
					if ("Current Icon".equals(identifier) || "Id".equals(identifier)) {
						iconEditor.editValue(value);
					}
				}
			}
		});
		add(filterTable, BorderLayout.CENTER);
	}

	@Override
	public void setShowSystemValues(boolean show) {
		iconTableModel.setShowSystemValues(show);
		reloadAll();
	}

	@Override
	public boolean isShowingSystemValues() {
		return iconTableModel.isShowingSystemValues();
	}

	void iconValueChanged(PropertyChangeEvent event) {
		// run later - don't rock the boat in the middle of a listener callback
		Swing.runLater(() -> {
			IconValue newValue = (IconValue) event.getNewValue();
			themeManager.setIcon(newValue);
		});
	}

	/**
	 * Reloads all the values displayed in the table
	 */
	public void reloadAll() {
		iconTableModel.reloadAll();
	}

	/**
	 * Returns the current values displayed in the table
	 */
	public void reloadCurrent() {
		iconTableModel.reloadCurrent();
	}

	@Override
	public ActionContext getActionContext(MouseEvent e) {
		if (e != null && e.getSource() == table) {
			IconValue currentValue = filterTable.getSelectedRowObject();
			if (currentValue == null) {
				return null;
			}
			String id = currentValue.getId();
			IconValue themeValue = iconTableModel.getThemeValue(id);
			return new ThemeTableContext<Icon>(currentValue, themeValue, this);
		}
		return null;
	}
}
