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

import javax.swing.JPanel;
import javax.swing.ListSelectionModel;
import javax.swing.table.TableColumn;

import docking.ActionContext;
import docking.action.ActionContextProvider;
import docking.widgets.table.GFilterTable;
import docking.widgets.table.GTable;
import generic.theme.ColorValue;
import generic.theme.ThemeManager;
import ghidra.util.Swing;

/**
 * Color Table for Theme Dialog
 */
public class ThemeColorTable extends JPanel implements ActionContextProvider, ThemeTable {

	private ThemeColorTableModel colorTableModel;
	private ColorValueEditor colorEditor = new ColorValueEditor(this::colorValueChanged);
	private GTable table;
	private GFilterTable<ColorValue> filterTable;
	private ThemeManager themeManager;

	public ThemeColorTable(ThemeManager themeManager, GThemeValuesCache valuesProvider) {
		super(new BorderLayout());
		this.themeManager = themeManager;
		colorTableModel = createModel(valuesProvider);

		filterTable = new GFilterTable<>(colorTableModel);
		table = filterTable.getTable();
		table.setSelectionMode(ListSelectionModel.SINGLE_INTERVAL_SELECTION);

		table.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					ColorValue colorValue = filterTable.getSelectedRowObject();
					if (colorValue != null) {
						colorEditor.editValue(colorValue);
					}
					e.consume();
				}
			}
		});

		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					ColorValue value = filterTable.getItemAt(e.getPoint());

					int col = filterTable.getColumn(e.getPoint());
					TableColumn column = table.getColumnModel().getColumn(col);
					Object identifier = column.getIdentifier();
					if ("Current Color".equals(identifier) || "Id".equals(identifier)) {
						colorEditor.editValue(value);
					}
				}
			}
		});

		add(filterTable, BorderLayout.CENTER);
	}

	ThemeColorTableModel createModel(GThemeValuesCache valuesProvider) {
		return new ThemeColorTableModel(valuesProvider);
	}

	@Override
	public void setShowSystemValues(boolean show) {
		colorTableModel.setShowSystemValues(show);
		reloadAll();
	}

	@Override
	public boolean isShowingSystemValues() {
		return colorTableModel.isShowingSystemValues();
	}

	void colorValueChanged(PropertyChangeEvent event) {
		// run later - don't rock the boat in the middle of a listener callback
		Swing.runLater(() -> {
			ColorValue newValue = (ColorValue) event.getNewValue();
			themeManager.setColor(newValue);
		});
	}

	/**
	 * Returns the current values displayed in the table
	 */
	public void reloadCurrent() {
		colorTableModel.reloadCurrent();
	}

	/**
	 * Reloads all the values displayed in the table
	 */
	public void reloadAll() {
		colorTableModel.reloadAll();
	}

	@Override
	public ActionContext getActionContext(MouseEvent e) {
		if (e != null && e.getSource() == table) {
			ColorValue currentValue = filterTable.getSelectedRowObject();
			if (currentValue == null) {
				return null;
			}
			String id = currentValue.getId();
			ColorValue themeValue = colorTableModel.getThemeValue(id);
			return new ThemeTableContext<>(currentValue, themeValue, this);
		}
		return null;
	}
}
