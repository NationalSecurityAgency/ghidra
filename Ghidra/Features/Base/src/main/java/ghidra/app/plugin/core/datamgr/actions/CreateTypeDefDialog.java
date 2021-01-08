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
package ghidra.app.plugin.core.datamgr.actions;

import javax.swing.*;
import javax.swing.event.CellEditorListener;
import javax.swing.event.ChangeEvent;
import javax.swing.tree.TreePath;

import docking.DialogComponentProvider;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GLabel;
import docking.widgets.list.GListCellRenderer;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.tree.ArchiveNode;
import ghidra.app.plugin.core.datamgr.tree.DataTypeTreeNode;
import ghidra.app.util.datatype.DataTypeSelectionEditor;
import ghidra.program.model.data.*;
import ghidra.util.MessageType;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.layout.PairLayout;

public class CreateTypeDefDialog extends DialogComponentProvider {

	private final DataTypeManagerPlugin plugin;
	private final Category category;
	private JTextField nameTextField;
	private DataTypeSelectionEditor dataTypeEditor;
	private GhidraComboBox<DataTypeManager> dataTypeManagerBox;
	private boolean isCancelled;
	private final TreePath selectedTreePath;

	CreateTypeDefDialog(DataTypeManagerPlugin plugin, Category category, TreePath treePath) {
		super("Create TypeDef", true /*modal*/, true /*status*/, true /*buttons*/, false /*tasks*/);
		this.plugin = plugin;
		this.category = category;
		this.selectedTreePath = treePath;

		addWorkPanel(createWorkPanel());

		addOKButton();
		addCancelButton();
	}

	private JComponent createWorkPanel() {
		JPanel panel = new JPanel(new PairLayout());

		// category info
		panel.add(new GLabel("Category:"));
		panel.add(new GLabel(category.getCategoryPath().getPath()));

		// name info
		nameTextField = new JTextField(15);
		panel.add(new GLabel("Name:"));
		panel.add(nameTextField);

		// data type info
		dataTypeEditor =
			new DataTypeSelectionEditor(plugin.getTool(), AllowedDataTypes.ALL);
		panel.add(new GLabel("Data type:"));
		panel.add(dataTypeEditor.getEditorComponent());

		dataTypeEditor.addCellEditorListener(new CellEditorListener() {
			@Override
			public void editingStopped(ChangeEvent e) {
				setStatusText("");
			}

			@Override
			public void editingCanceled(ChangeEvent e) {
				setStatusText("");
			}
		});

		dataTypeEditor.setDefaultSelectedTreePath(selectedTreePath);

		dataTypeManagerBox = new GhidraComboBox<>();
		dataTypeManagerBox.setRenderer(
			GListCellRenderer.createDefaultCellTextRenderer(dtm -> dtm.getName()));

		DataTypeManager[] dataTypeManagers = plugin.getDataTypeManagers();
		for (DataTypeManager manager : dataTypeManagers) {
			if (manager instanceof BuiltInDataTypeManager) {
				continue; // can't add to built-in
			}
			dataTypeManagerBox.addToModel(manager);
		}

		Object itemToSelect = null;

		// select the manager from where the dialog was created
		Object lastPathComponent = selectedTreePath.getLastPathComponent();
		if (lastPathComponent instanceof DataTypeTreeNode) {
			DataTypeTreeNode dataTypeTreeNode = (DataTypeTreeNode) lastPathComponent;
			ArchiveNode archiveNode = dataTypeTreeNode.getArchiveNode();
			DataTypeManager manager = archiveNode.getArchive().getDataTypeManager();
			if (dataTypeManagerBox.containsItem(manager)) {
				itemToSelect = manager;
			}
		}

		dataTypeManagerBox.setSelectedItem(itemToSelect);

		panel.add(new GLabel("Archive:"));
		panel.add(dataTypeManagerBox);

		panel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

		return panel;
	}

	@Override
	protected void okCallback() {
		// are we valid?
		String name = nameTextField.getText();
		if (name == null || name.isEmpty()) {
			setStatusText("Name required", MessageType.ERROR);
			return;
		}

		if (!DataUtilities.isValidDataTypeName(name)) {
			setStatusText("Invalidate data type name: " + name, MessageType.ERROR);
			return;
		}

		// try to create any required data
		String dtTextValue = dataTypeEditor.getCellEditorValueAsText();
		if (dtTextValue == null || dtTextValue.isEmpty()) {
			setStatusText("Data type required" + dtTextValue, MessageType.ERROR);
			return;
		}

		try {
			if (!dataTypeEditor.validateUserSelection()) {
				setStatusText("Invalidate data type: " + dtTextValue, MessageType.ERROR);
				return;
			}
		}
		catch (InvalidDataTypeException e) {
			setStatusText("Invalidate data type: " + dtTextValue, MessageType.ERROR);
			return;
		}

		DataType dataType = getDataType();
		if (!DataTypeManagerPlugin.isValidTypeDefBaseType(getComponent(), dataType)) {
			setStatusText("Data type cannot be source of a typedef: " + dataType.getName(),
				MessageType.ERROR);
			return;
		}

		DataTypeManager manager = (DataTypeManager) dataTypeManagerBox.getSelectedItem();
		if (manager == null) {
			setStatusText("Must select an archive", MessageType.ERROR);
			return;
		}

		clearStatusText();
		close();
	}

	@Override
	protected void cancelCallback() {
		super.cancelCallback();
		isCancelled = true;
	}

	boolean isCancelled() {
		return isCancelled;
	}

	String getTypeDefName() {
		if (isCancelled) {
			return null;
		}
		return nameTextField.getText();
	}

	DataType getDataType() {
		DataType dataType = (DataType) dataTypeEditor.getCellEditorValue();
		if (dataType instanceof FunctionDefinition) {
			DataTypeManager dataTypeManager = dataType.getDataTypeManager();
			dataType = PointerDataType.getPointer(dataType, dataTypeManager);
		}
		return dataType;
	}

	DataTypeManager getDataTypeManager() {
		return (DataTypeManager) dataTypeManagerBox.getSelectedItem();
	}
}
