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

import docking.widgets.DropDownSelectionTextField;
import docking.widgets.table.CellEditorUtils;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.datatype.DataTypeSelectionEditor;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.util.Swing;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;

public class DataTypeTableCellEditor extends AbstractCellEditor
		implements TableCellEditor {
	private final PluginTool tool;
	private DataTypeManagerService service;
	private JTable table;

	private JPanel editorPanel;
	private DataTypeSelectionEditor editor;

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

	protected DataTypeTableCellEditor(PluginTool tool, DataTypeManagerService service) {
		this.tool = tool;
		this.service = service;
	}

	public DataTypeTableCellEditor(DataTypeManagerService service) {
		this(null, service);
	}

	public DataTypeTableCellEditor(PluginTool tool) {
		// NOTE: Service will be updated on request
		this(tool, null);
	}

	private DataTypeManagerService updateService() {
		if (tool != null) {
			service = tool.getService(DataTypeManagerService.class);
		}
		return service;
	}

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
		init(row, column);

		// TODO: Use this to verify lengths if variable-length is to be permitted.
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

	protected void init(int row, int column) {
		updateService();
		editor = new DataTypeSelectionEditor(service, getAllowed(row, column));
		editor.setPreferredDataTypeManager(getPreferredDataTypeManager(row, column));
		editor.setTabCommitsEdit(true);
		editor.setConsumeEnterKeyPress(false);

		final DropDownSelectionTextField<DataType> textField = editor.getDropDownTextField();
		textField.setBorder(UIManager.getBorder("Table.focusCellHighlightBorder"));
		CellEditorUtils.onOneFocus(textField, () -> textField.selectAll());

		editor.addCellEditorListener(cellEditorListener);
		editorPanel = new JPanel(new BorderLayout()) {
			@Override
			public void requestFocus() {
				textField.requestFocus();
			}
		};
		editorPanel.add(textField, BorderLayout.CENTER);
		editorPanel.add(dataTypeChooserButton, BorderLayout.EAST);
	}

	protected void stopEdit() {
		updateService();
		DataType dataType = service.getDataType((String) null); // Why?
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

	protected boolean validateSelection(DataType dataType) {
		return true;
	}

	protected DataType resolveSelection(DataType dataType) {
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
		DataType dataType = resolveSelection(editor.getCellEditorValueAsDataType());
		if (!isEmptyEditorCell() && !validateSelection(dataType)) {
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
