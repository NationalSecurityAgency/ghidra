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
package ghidra.app.plugin.core.debug.gui.model;

import java.awt.Component;

import javax.swing.JTable;
import javax.swing.JTextField;

import docking.widgets.table.GTableTextCellEditor;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.trace.model.target.TraceObject;

public class ObjectsTablePanel extends AbstractQueryTablePanel<ValueRow, ObjectTableModel> {

	private static class PropertyEditor extends GTableTextCellEditor {
		private final JTextField textField;

		public PropertyEditor() {
			super(new JTextField());
			textField = (JTextField) getComponent();
		}

		@Override
		public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected,
				int row, int column) {
			super.getTableCellEditorComponent(table, value, isSelected, row, column);
			if (value instanceof ValueProperty<?> property) {
				textField.setText(property.getDisplay());
			}
			else {
				textField.setText(value.toString());
			}
			return textField;
		}

		@Override
		public Object getCellEditorValue() {
			Object value = super.getCellEditorValue();
			return new ValueFixedProperty<>(value);
		}
	}

	public ObjectsTablePanel(Plugin plugin) {
		super(plugin);
		table.setDefaultEditor(ValueProperty.class, new PropertyEditor());
	}

	@Override
	protected ObjectTableModel createModel(Plugin plugin) {
		return new ObjectTableModel(plugin);
	}

	public boolean trySelectAncestor(TraceObject successor) {
		ValueRow row = tableModel.findTraceObjectAncestor(successor);
		if (row == null) {
			return false;
		}
		setSelectedItem(row);
		return true;
	}
}
