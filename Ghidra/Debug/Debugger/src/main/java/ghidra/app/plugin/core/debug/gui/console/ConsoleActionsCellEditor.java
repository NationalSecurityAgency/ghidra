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
package ghidra.app.plugin.core.debug.gui.console;

import java.awt.Color;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.table.TableCellEditor;

import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.app.plugin.core.debug.gui.console.DebuggerConsoleProvider.ActionList;
import ghidra.app.plugin.core.debug.gui.console.DebuggerConsoleProvider.BoundAction;

public class ConsoleActionsCellEditor extends AbstractCellEditor
		implements TableCellEditor, ActionListener {
	private static final ActionList EMPTY_ACTION_LIST = new ActionList();

	protected final JPanel box = new JPanel();
	protected final List<JButton> buttonCache = new ArrayList<>();

	protected ActionList value;

	protected Color bg = new Color(0); // Initial cached value

	public ConsoleActionsCellEditor() {
		ConsoleActionsCellRenderer.configureBox(box);
		Border innerBorder = BorderFactory.createEmptyBorder(0, 4, 0, 4);
		Border outerBorder = BorderFactory.createLineBorder(Palette.YELLOW, 1);
		box.setBorder(BorderFactory.createCompoundBorder(outerBorder, innerBorder));
	}

	@Override
	public Object getCellEditorValue() {
		return EMPTY_ACTION_LIST;
	}

	@Override
	public Component getTableCellEditorComponent(JTable table, Object v, boolean isSelected,
			int row, int column) {
		// I can't think of when you'd be "editing" a non-selected cell.
		if (bg.getRGB() != table.getSelectionBackground().getRGB()) {
			bg = new Color(table.getSelectionBackground().getRGB());
		}
		box.setBackground(bg);
		box.setOpaque(true);

		value = (ActionList) v;
		ConsoleActionsCellRenderer.populateBox(box, buttonCache, value,
			button -> button.addActionListener(this));
		return box;
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		int index = buttonCache.indexOf(e.getSource());
		BoundAction action = value.get(index);
		stopCellEditing();
		action.perform();
	}
}
