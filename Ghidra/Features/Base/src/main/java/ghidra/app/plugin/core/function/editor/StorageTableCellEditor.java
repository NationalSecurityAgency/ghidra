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

import java.awt.Color;
import java.awt.Component;
import java.awt.event.MouseEvent;
import java.util.EventObject;

import javax.swing.*;
import javax.swing.table.TableCellEditor;

import docking.DockingWindowManager;
import ghidra.program.model.listing.VariableStorage;

class StorageTableCellEditor extends AbstractCellEditor implements TableCellEditor {

	private VariableStorage storage;
	private FunctionEditorModel model;

	public StorageTableCellEditor(FunctionEditorModel model) {
		this.model = model;
	}

	@Override
	public Object getCellEditorValue() {
		return storage;
	}

	@Override
	public boolean isCellEditable(EventObject e) {
		if (e instanceof MouseEvent) {
			return ((MouseEvent) e).getClickCount() > 1;
		}
		return true;
	}

	@Override
	public Component getTableCellEditorComponent(final JTable table, Object value,
			boolean isSelected, int row, int column) {
		String stringValue = value == null ? "" : value.toString();
		JTextField field = new JTextField(stringValue);
		field.setBackground(Color.yellow);
		field.setEditable(false);
		ParameterTableModel tableModel = (ParameterTableModel) table.getModel();
		FunctionVariableData rowData = tableModel.getRowObject(row);
		final StorageAddressEditorDialog dialog = new StorageAddressEditorDialog(model.getProgram(),
			model.getDataTypeManagerService(), (VariableStorage) value, rowData);
		SwingUtilities.invokeLater(new Runnable() {

			@Override
			public void run() {
				DockingWindowManager.showDialog(table, dialog);
				if (!dialog.wasCancelled()) {
					storage = dialog.getStorage();
				}
				TableCellEditor cellEditor = table.getCellEditor();
				if (cellEditor == null) {
					return;
				}
				if (storage == null) {
					cellEditor.cancelCellEditing();
				}
				else {
					cellEditor.stopCellEditing();
				}
			}
		});
		return field;
	}
}
