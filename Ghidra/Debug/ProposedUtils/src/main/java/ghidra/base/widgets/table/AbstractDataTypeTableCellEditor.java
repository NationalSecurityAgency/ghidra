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
package ghidra.base.widgets.table;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.util.EventObject;

import javax.swing.*;
import javax.swing.event.CellEditorListener;
import javax.swing.event.ChangeEvent;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableModel;

import docking.widgets.DropDownSelectionTextField;
import docking.widgets.table.*;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.datatype.DataTypeSelectionEditor;
import ghidra.program.model.data.*;
import ghidra.util.Swing;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;

public abstract class AbstractDataTypeTableCellEditor extends AbstractCellEditor
		implements TableCellEditor, FocusableEditor, GTableAccess {

	private DataTypeManagerService service;
	protected JTable table;

	private JPanel editorPanel;
	private DataTypeSelectionEditor editor;
	private DropDownSelectionTextField<DataType> textField;

	private DataType dt;

	private CellEditorListener cellEditorListener = new CellEditorListener() {
		@Override
		public void editingCanceled(ChangeEvent e) {
			cancelCellEditing();
		}

		@Override
		public void editingStopped(ChangeEvent e) {
			stopCellEditing();
		}
	};

	private JButton dataTypeChooserButton = new JButton("...") {
		@Override
		public Dimension getPreferredSize() {
			Dimension preferredSize = super.getPreferredSize();
			preferredSize.width = 15;
			return preferredSize;
		}
	};

	{
		dataTypeChooserButton.addActionListener(e -> Swing.runLater(() -> stopEdit()));
	}

	protected abstract DataTypeManagerService getService(TableModel model);

	protected AllowedDataTypes getAllowed(int row, int column) {
		return AllowedDataTypes.ALL;
	}

	protected DataTypeManager getPreferredDataTypeManager(int row, int column) {
		return null;
	}

	@Override
	public Component getTableCellEditorComponent(JTable newTable, Object value, boolean isSelected,
			int row, int column) {
		this.table = newTable;
		this.service = getService(getUnwrappedModel(newTable));
		if (service == null) {
			return null;
		}
		init(row, column);

		// LATER: Use this to verify lengths if variable-length is to be permitted.
		/*DataTypeInstance dti = (DataTypeInstance) value;
		if (dti != null) {
			dt = dti.getDataType();
		}
		else {
			dt = null;
		}*/
		dt = (DataType) value;

		editor.setCellEditorValue(dt);

		return editorPanel;
	}

	@Override
	public void focusEditor() {
		textField.requestFocusInWindow();
	}

	protected void init(int row, int column) {
		editor = new DataTypeSelectionEditor(getPreferredDataTypeManager(row, column), service,
			getAllowed(row, column));
		editor.setTabCommitsEdit(true);
		editor.setConsumeEnterKeyPress(false);

		textField = editor.getDropDownTextField();
		textField.setBorder(UIManager.getBorder("Table.focusCellHighlightBorder"));
		CellEditorUtils.onOneFocus(textField, () -> textField.selectAll());

		editor.addCellEditorListener(cellEditorListener);
		editorPanel = new JPanel(new BorderLayout());
		editorPanel.add(textField, BorderLayout.CENTER);
		editorPanel.add(dataTypeChooserButton, BorderLayout.EAST);
	}

	protected void stopEdit() {
		DataType dataType = service.promptForDataType((String) null);
		if (dataType != null) {
			editor.setCellEditorValue(dataType);
			editor.stopCellEditing();
		}
		else {
			editor.cancelCellEditing();
		}
	}

	@Override
	public DataType getCellEditorValue() {
		return dt;
	}

	protected boolean validateSelection(DataType dataType, TableModel model) {
		return true;
	}

	protected DataType resolveSelection(DataType dataType, TableModel model) {
		return dataType;
	}

	private boolean isEmptyEditorCell() {
		return editor.getCellEditorValueAsText().trim().isEmpty();
	}

	@Override
	public boolean stopCellEditing() {
		ListSelectionModel columnSelectionModel = table.getColumnModel().getSelectionModel();
		columnSelectionModel.setValueIsAdjusting(true);

		int editingColumn = table.getEditingColumn();

		try {
			if (!editor.validateUserSelection()) {
				return false;
			}
		}
		catch (InvalidDataTypeException e) {
			return false;
		}

		TableModel model = getUnwrappedModel(table);
		DataType dataType = resolveSelection(editor.getCellEditorValueAsDataType(), model);
		if (!isEmptyEditorCell() && !validateSelection(dataType, model)) {
			return false;
		}
		if (dataType != null) {
			if (dataType.equals(dt)) {
				fireEditingCanceled(); // no change
			}
			else {
				dt = dataType;
				fireEditingStopped();
			}
		}
		else {
			fireEditingCanceled();
		}

		columnSelectionModel.setAnchorSelectionIndex(editingColumn);
		columnSelectionModel.setLeadSelectionIndex(editingColumn);
		columnSelectionModel.setValueIsAdjusting(false);

		return true;
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
}
