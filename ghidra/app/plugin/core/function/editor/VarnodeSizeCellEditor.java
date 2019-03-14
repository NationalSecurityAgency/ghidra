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
import java.math.BigInteger;
import java.util.EventObject;

import javax.swing.AbstractCellEditor;
import javax.swing.JTable;
import javax.swing.table.TableCellEditor;

import docking.widgets.textfield.IntegerTextField;

class VarnodeSizeCellEditor extends AbstractCellEditor implements TableCellEditor {

	private IntegerTextField input;

	VarnodeSizeCellEditor() {

	}

	@Override
	public Object getCellEditorValue() {
		BigInteger value = input.getValue();
		if (value == null) {
			return null;
		}
		return Integer.valueOf(value.intValue());
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

		input = new IntegerTextField();
		input.setAllowNegativeValues(false);
		input.setDecimalMode();
		Integer size = (Integer) value;
		if (size != null) {
			input.setValue(size.longValue());
			FocusAdapter focusListener = new FocusAdapter() {
				@Override
				public void focusGained(FocusEvent e) {
					input.selectAll();
					input.getComponent().removeFocusListener(this);
				}
			};
			input.getComponent().addFocusListener(focusListener);
		}
		input.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				stopCellEditing();
			}
		});
		return input.getComponent();
	}

}
