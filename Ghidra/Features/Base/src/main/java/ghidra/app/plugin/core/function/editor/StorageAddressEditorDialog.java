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

import java.awt.*;
import java.awt.event.*;
import java.util.Arrays;
import java.util.List;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.TableCellEditor;

import docking.DialogComponentProvider;
import docking.widgets.DropDownSelectionTextField;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import docking.widgets.table.GTable;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.layout.PairLayout;
import ghidra.util.layout.VerticalLayout;

public class StorageAddressEditorDialog extends DialogComponentProvider
		implements ModelChangeListener {
	private FunctionVariableData variableData;
	private StorageAddressModel model;
	private VarnodeTableModel varnodeTableModel;
	private ParameterDataTypeCellEditor dataTypeEditor;
	private GTable varnodeTable;
	private ListSelectionListener selectionListener;
	private JLabel sizeLabel;
	private JButton addButton;
	private JButton removeButton;
	private JButton upButton;
	private JButton downButton;
	private int size;
	private JLabel currentSizeLabel;
	private boolean cancelled = true;

	/**
	 * Constructor
	 * @param program
	 * @param service
	 * @param storage
	 * @param variableData
	 */
	public StorageAddressEditorDialog(Program program, DataTypeManagerService service,
			VariableStorage storage, FunctionVariableData variableData) {
		super("Storage Address Editor");
		this.variableData = variableData;
		model = new StorageAddressModel(program, storage, this);
		setDataType(variableData.getFormalDataType());
		setHelpLocation(new HelpLocation("FunctionPlugin", "Edit_Parameter_Storage"));
		addWorkPanel(buildMainPanel(service));
		addOKButton();
		addCancelButton();
		dataChanged();
	}

	/**
	 * Read-only use constructor for Help screenshot
	 * @param program
	 * @param service
	 * @param var function parameter to be displayed in editor dialog
	 * @param ordinal parameter ordinal (-1 for return)
	 */
	public StorageAddressEditorDialog(Program program, DataTypeManagerService service,
			final Variable var, final int ordinal) {
		this(program, service, var.getVariableStorage(), new FunctionVariableData() {

			@Override
			public void setStorage(VariableStorage storage) {
				// unsupported
			}

			@Override
			public void setName(String name) {
				// unsupported
			}

			@Override
			public void setFormalDataType(DataType dataType) {
				// unsupported
			}

			@Override
			public VariableStorage getStorage() {
				return var.getVariableStorage();
			}

			@Override
			public String getName() {
				return var.getName();
			}

			@Override
			public Integer getIndex() {
				return ordinal;
			}

			@Override
			public DataType getFormalDataType() {
				return var.getDataType();
			}
		});
	}

	@Override
	protected void okCallback() {
		if (varnodeTable.isEditing()) {
			if (!varnodeTable.getCellEditor().stopCellEditing()) {
				return;
			}
		}
		cancelled = false;
		close();
	}

	public VariableStorage getStorage() {
		return model.getStorage();
	}

	private JComponent buildMainPanel(DataTypeManagerService service) {
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(buildInfoPanel(service), BorderLayout.NORTH);
		panel.add(buildTablePanel(), BorderLayout.CENTER);
		return panel;
	}

	private void setDataType(DataType dt) {
		DataType dataType = variableData.getFormalDataType();
		size = dataType.getLength();
		boolean unconstrained =
			(dataType instanceof AbstractFloatDataType) || Undefined.isUndefined(dataType);
		model.setRequiredSize(size, unconstrained);
		if (sizeLabel != null) {
			sizeLabel.setText("" + size);
			dataChanged();
		}
	}

	private Component buildInfoPanel(DataTypeManagerService service) {
		JPanel panel = new JPanel(new PairLayout(10, 4));
		panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

		panel.add(new GLabel("Datatype: "));

		dataTypeEditor = new ParameterDataTypeCellEditor(this, service);

		dataTypeEditor.addCellEditorListener(new CellEditorListener() {

			@Override
			public void editingStopped(ChangeEvent e) {
				DataType dt = (DataType) dataTypeEditor.getCellEditorValue();
				variableData.setFormalDataType(dt);
				setDataType(dt);
			}

			@Override
			public void editingCanceled(ChangeEvent e) {
				// ignore
			}
		});

		final Component dataTypeEditComponent = dataTypeEditor.getTableCellEditorComponent(null,
			variableData.getFormalDataType(), false, 0, 0);

		final DropDownSelectionTextField<DataType> textField = dataTypeEditor.getTextField();
		textField.setBorder((new JTextField()).getBorder()); // restore default border

		JButton chooserButton = dataTypeEditor.getChooserButton();
		JButton defaultButton = new JButton(); // restore default border/background
		chooserButton.setBorder(defaultButton.getBorder());
		chooserButton.setBackground(defaultButton.getBackground());

		textField.addFocusListener(new FocusListener() {

			@Override
			public void focusLost(FocusEvent e) {
				if (!dataTypeEditor.stopCellEditing()) {
					Msg.showError(this, dataTypeEditComponent, "Invalid Datatype",
						"Previous datatype restored, invalid data type specified: " +
							textField.getText());
					dataTypeEditor.getEditor().setCellEditorValue(variableData.getFormalDataType());
					textField.requestFocus();
				}
			}

			@Override
			public void focusGained(FocusEvent e) {
				// ignore
			}
		});

		panel.add(dataTypeEditComponent);
		panel.add(new GLabel("Datatype Size: "));
		sizeLabel = new GDLabel("" + size);
		panel.add(sizeLabel);
		panel.add(new GLabel("Allocated Size:"));
		currentSizeLabel = new GDLabel("");
		panel.add(currentSizeLabel);

		setFocusComponent(textField);

		return panel;
	}

	private Component buildTablePanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createTitledBorder("Storage Locations"));
		varnodeTableModel = new VarnodeTableModel(model);
		varnodeTable = new GTable(varnodeTableModel);
		selectionListener = new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent e) {
				model.setSelectedVarnodeRows(varnodeTable.getSelectedRows());
			}
		};
		varnodeTable.getSelectionModel().addListSelectionListener(selectionListener);
		varnodeTable.setPreferredScrollableViewportSize(new Dimension(400, 150));
		varnodeTable.setDefaultEditor(VarnodeType.class, new VarnodeTypeCellEditor());
		varnodeTable.setDefaultEditor(Address.class, new VarnodeLocationCellEditor(model));
		varnodeTable.setDefaultEditor(Register.class, new VarnodeLocationCellEditor(model));
		varnodeTable.setDefaultEditor(Integer.class, new VarnodeSizeCellEditor());
		varnodeTable.setDefaultRenderer(Address.class, new VarnodeLocationTableCellRenderer());
		varnodeTable.setDefaultRenderer(Register.class, new VarnodeLocationTableCellRenderer());
		varnodeTable.getTableHeader().setReorderingAllowed(false);
		varnodeTable.setSurrendersFocusOnKeystroke(true);

		JScrollPane scroll = new JScrollPane(varnodeTable);
		panel.add(scroll, BorderLayout.CENTER);
		panel.add(buildButtonPanel(), BorderLayout.EAST);
		return panel;
	}

	private Component buildButtonPanel() {
		JPanel panel = new JPanel(new VerticalLayout(5));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		addButton = new JButton("Add");
		removeButton = new JButton("Remove");
		upButton = new JButton("Up");
		downButton = new JButton("Down");

		addButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				model.addVarnode();
			}
		});
		removeButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				model.removeVarnodes();
			}
		});
		upButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				model.moveSelectedVarnodeUp();
			}
		});
		downButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				model.moveSelectedVarnodeDown();
			}
		});

		panel.add(addButton);
		panel.add(removeButton);
		panel.add(new JSeparator());
		panel.add(upButton);
		panel.add(downButton);
		return panel;
	}

	@Override
	public void dataChanged() {
		updateDataType();
		updateCurrentSize();
		updateStatusText();
		updateOkButton();
		updateVarnodeTable();
		updateTableSelection();
		updateTableButtonEnablement();
	}

	private void updateTableButtonEnablement() {
		removeButton.setEnabled(model.canRemoveVarnodes());
		upButton.setEnabled(model.canMoveVarnodeUp());
		downButton.setEnabled(model.canMoveVarnodeDown());
	}

	private void updateTableSelection() {
		int[] selectedRows = model.getSelectedVarnodeRows();

		if (!Arrays.equals(selectedRows, varnodeTable.getSelectedRows())) {
			varnodeTable.clearSelection();
			for (int i : selectedRows) {
				varnodeTable.addRowSelectionInterval(i, i);
			}
		}
	}

	private void updateVarnodeTable() {
		List<VarnodeInfo> varnodeList = model.getVarnodes();
		List<VarnodeInfo> tableVarnodeList = varnodeTableModel.getVarnodes();
		if (!varnodeList.equals(tableVarnodeList)) {
			ListSelectionModel selectionModel = varnodeTable.getSelectionModel();
			selectionModel.removeListSelectionListener(selectionListener);
			varnodeTableModel.setVarnodes(varnodeList);
			selectionModel.addListSelectionListener(selectionListener);
		}

	}

	private void updateOkButton() {
		setOkEnabled(model.isValid());
	}

	private void updateStatusText() {
		setStatusText(model.getStatusText());
	}

	private void updateCurrentSize() {
		currentSizeLabel.setText("" + model.getCurrentSize());
	}

	private boolean adjustingDataType = false;

	private void updateDataType() {
		// If storage size has changed with an undefined datatype, 
		// alter the size of the undefined type
		if (adjustingDataType) {
			return;
		}
		adjustingDataType = true;
		try {
			int currentSize = model.getCurrentSize();
			if (currentSize > 0 && Undefined.isUndefined(variableData.getFormalDataType())) {
				DataType adjustedUndefinedtype = Undefined.getUndefinedDataType(currentSize);
				variableData.setFormalDataType(adjustedUndefinedtype);
				dataTypeEditor.getEditor().setCellEditorValue(adjustedUndefinedtype);
				setDataType(adjustedUndefinedtype);
			}
		}
		finally {
			adjustingDataType = false;
		}
	}

//	public static void main(String[] args) throws Exception {
////		DockingWindowsLookAndFeelUtils.setLookAndFeel("Metal");
//		ProgramBuilder builder = new ProgramBuilder();
//		builder.addMemory("1000", 1000);
//		Function fun = builder.addFunction("foo", "1000", 20, new VoidDataType());
//
//		Program program = builder.getProgram();
//		AddressSpace stackSpace = program.getAddressFactory().getStackSpace();
//		Address address = stackSpace.getAddress(4);
//		VariableStorage storage = new VariableStorage(program, address, 4);
//
//		DockingWindowManager dwm = new DockingWindowManager("Test", null, null);
//		dwm.showDialog(new StorageAddressEditorDialog(program, storage, 8));
//		System.exit(0);
//	}

	@Override
	public void tableRowsChanged() {
		TableCellEditor cellEditor = varnodeTable.getCellEditor();
		if (cellEditor != null) {
			if (!cellEditor.stopCellEditing()) {
				cellEditor.cancelCellEditing();
			}
		}
	}

	public boolean wasCancelled() {
		return cancelled;
	}
}
