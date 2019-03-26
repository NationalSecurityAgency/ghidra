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
package ghidra.app.plugin.core.function.editor;

import java.awt.Component;
import java.awt.event.*;
import java.util.EventObject;

import javax.swing.*;
import javax.swing.table.TableCellEditor;

import docking.widgets.combobox.GhidraComboBox;

class VarnodeTypeCellEditor extends AbstractCellEditor implements TableCellEditor {
	private JComboBox<?> combo;
	private JTable jTable;
	private int editRow;
	private int editCol;

	VarnodeTypeCellEditor() {
	}

	@Override
	public Object getCellEditorValue() {
		return combo.getSelectedItem();
	}

	@Override
	public boolean isCellEditable(EventObject e) {
		if (e instanceof MouseEvent) {
			return ((MouseEvent) e).getClickCount() > 1;
		}
		return true;
	}

	@Override
	public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected,
			int row, int column) {

		this.jTable = table;
		this.editRow = row;
		this.editCol = column;

		combo = new GhidraComboBox<>(
			new Object[] { VarnodeType.Register, VarnodeType.Stack, VarnodeType.Memory });

		combo.setSelectedItem(value);

		combo.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				stopCellEditing();
				jTable.editCellAt(editRow, editCol + 1);
			}
		});

		SwingUtilities.invokeLater(new Runnable() {

			@Override
			public void run() {
				combo.showPopup();
				combo.requestFocus();
			}
		});
		return combo;
	}

}
