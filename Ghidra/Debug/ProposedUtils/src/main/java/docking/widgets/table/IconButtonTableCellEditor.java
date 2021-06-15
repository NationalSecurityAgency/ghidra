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
package docking.widgets.table;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.function.Consumer;

import javax.swing.*;
import javax.swing.table.TableCellEditor;

public class IconButtonTableCellEditor<R> extends AbstractCellEditor
		implements TableCellEditor, ActionListener {
	protected static final String BLANK = "";
	protected JButton button = new JButton(BLANK);

	private final GTableFilterPanel<R> filterPanel;
	private final Consumer<R> action;

	protected R row;

	public IconButtonTableCellEditor(GTableFilterPanel<R> filterPanel, Icon icon,
			Consumer<R> action) {
		this.filterPanel = filterPanel;
		button.setIcon(icon);
		this.action = action;
		button.addActionListener(this);
	}

	@Override
	public Object getCellEditorValue() {
		return BLANK;
	}

	@Override
	@SuppressWarnings("hiding")
	public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected,
			int row, int column) {
		this.row = filterPanel.getRowObject(row);
		button.setToolTipText(value.toString());
		return button;
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		fireEditingStopped();
		action.accept(row);
	}
}
