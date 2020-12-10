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
import java.awt.event.MouseEvent;
import java.math.BigInteger;
import java.util.EventObject;

import javax.swing.*;
import javax.swing.table.TableCellEditor;

import docking.widgets.textfield.IntegerTextField;

public class HexBigIntegerTableCellEditor extends AbstractCellEditor implements TableCellEditor {
	private IntegerTextField input;

	@Override
	public BigInteger getCellEditorValue() {
		return input.getValue();
	}

	@Override
	public boolean isCellEditable(EventObject e) {
		// If mouse event, require double-click
		if (e instanceof MouseEvent) {
			MouseEvent evt = (MouseEvent) e;
			return evt.getClickCount() >= 2 && super.isCellEditable(e);
		}
		return super.isCellEditable(e);
	}

	@Override
	public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected,
			int row, int column) {
		input = new IntegerTextField();
		input.getComponent().setBorder(UIManager.getBorder("Table.focusCellHighlightBorder"));
		input.setAllowNegativeValues(true);
		input.setHexMode();
		input.setAllowsHexPrefix(false);
		input.setShowNumberMode(true);

		if (value != null) {
			input.setValue((BigInteger) value);
			CellEditorUtils.onOneFocus(input.getComponent(), () -> input.selectAll());
		}
		input.addActionListener(e -> stopCellEditing());
		return input.getComponent();
	}
}
