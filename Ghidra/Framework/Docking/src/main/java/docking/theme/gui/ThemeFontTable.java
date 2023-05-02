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
import java.awt.Font;
import java.awt.event.*;
import java.beans.PropertyChangeEvent;

import javax.swing.JPanel;
import javax.swing.ListSelectionModel;
import javax.swing.table.TableColumn;

import docking.ActionContext;
import docking.action.ActionContextProvider;
import docking.widgets.table.GFilterTable;
import docking.widgets.table.GTable;
import generic.theme.FontValue;
import generic.theme.ThemeManager;
import ghidra.util.Swing;

/**
 * Font Table for Theme Dialog
 */
public class ThemeFontTable extends JPanel implements ActionContextProvider, ThemeTable {

	private ThemeFontTableModel fontTableModel;
	private FontValueEditor fontEditor = new FontValueEditor(this::fontValueChanged);
	private GTable table;
	private GFilterTable<FontValue> filterTable;
	private ThemeManager themeManager;

	public ThemeFontTable(ThemeManager themeManager, GThemeValuesCache valuesProvider) {
		super(new BorderLayout());
		this.themeManager = themeManager;

		fontTableModel = new ThemeFontTableModel(valuesProvider);
		filterTable = new GFilterTable<>(fontTableModel);
		table = filterTable.getTable();
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		table.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					FontValue fontValue = filterTable.getSelectedRowObject();
					if (fontValue != null) {
						fontEditor.editValue(fontValue);
					}
					e.consume();
				}
			}
		});

		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					FontValue value = filterTable.getItemAt(e.getPoint());

					int col = filterTable.getColumn(e.getPoint());
					TableColumn column = table.getColumnModel().getColumn(col);
					Object identifier = column.getIdentifier();
					if ("Current Font".equals(identifier) || "Id".equals(identifier)) {
						fontEditor.editValue(value);
					}
				}
			}
		});
		add(filterTable, BorderLayout.CENTER);

	}

	@Override
	public void setShowSystemValues(boolean show) {
		fontTableModel.setShowSystemValues(show);
		reloadAll();
	}

	@Override
	public boolean isShowingSystemValues() {
		return fontTableModel.isShowingSystemValues();
	}

	void fontValueChanged(PropertyChangeEvent event) {
		// run later - don't rock the boat in the middle of a listener callback
		Swing.runLater(() -> {
			FontValue newValue = (FontValue) event.getNewValue();
			themeManager.setFont(newValue);
		});
	}

	/**
	 * Reloads all the values displayed in the table
	 */
	public void reloadAll() {
		fontTableModel.reloadAll();
	}

	/**
	 * Returns the current values displayed in the table
	 */
	public void reloadCurrent() {
		fontTableModel.reloadCurrent();
	}

	@Override
	public ActionContext getActionContext(MouseEvent e) {
		if (e != null && e.getSource() == table) {
			FontValue currentValue = filterTable.getSelectedRowObject();
			if (currentValue == null) {
				return null;
			}
			String id = currentValue.getId();
			FontValue themeValue = fontTableModel.getThemeValue(id);
			return new ThemeTableContext<Font>(currentValue, themeValue, this);
		}
		return null;
	}
}
