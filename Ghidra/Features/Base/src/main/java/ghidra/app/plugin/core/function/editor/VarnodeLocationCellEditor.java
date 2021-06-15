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
import java.util.*;

import javax.swing.*;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.table.TableCellEditor;

import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.textfield.IntegerTextField;
import ghidra.app.util.AddressInput;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.util.Msg;

class VarnodeLocationCellEditor extends AbstractCellEditor implements TableCellEditor {
	private Program program;
	private VarnodeType type;
	private Component editorComponent;
	private GhidraComboBox<Register> combo;
	private AddressInput addressInput;
	private IntegerTextField offsetInput;

	private Comparator<Register> registerWrapperComparator = new Comparator<Register>() {
		@Override
		public int compare(Register r1, Register r2) {
			return r1.toString().compareToIgnoreCase(r2.toString());
		}
	};
	private VarnodeInfo currentVarnode;
	private int maxRegisterSize;

	VarnodeLocationCellEditor(StorageAddressModel model) {
		this.program = model.getProgram();
		this.maxRegisterSize = program.getDefaultPointerSize();
	}

	@Override
	public boolean isCellEditable(EventObject e) {
		if (e instanceof MouseEvent) {
			return ((MouseEvent) e).getClickCount() > 1;
		}
		return true;
	}

	@Override
	public boolean stopCellEditing() {
		switch (type) {
			case Register:
				Object selectedObj = combo.getSelectedItem();
				if (selectedObj instanceof String) {
					if (program.getRegister((String) selectedObj) == null) {
						Msg.showError(this, editorComponent, "Invalid Register",
							"Register does not exist: " + selectedObj);
						return false;
					}
				}
				break;

			case Stack:
				BigInteger value = offsetInput.getValue();
				if (value != null) {
					try {
						program.getAddressFactory().getStackSpace().getAddress(value.longValue());
					}
					catch (AddressOutOfBoundsException e) {
						Msg.showError(this, editorComponent, "Invalid Stack Offset",
							"Invalid stack offset: " + offsetInput.getText());
						return false;
					}
				}
				break;

			default:
		}
		fireEditingStopped();
		return true;
	}

	@Override
	public Object getCellEditorValue() {
		switch (type) {
			case Register:
				return combo.getSelectedItem();

			case Stack:
				BigInteger value = offsetInput.getValue();
				return value == null ? null
						: program.getAddressFactory().getStackSpace().getAddress(value.longValue());
			case Memory:
				return addressInput.getAddress();
		}
		return null;
	}

	@Override
	public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected,
			int row, int column) {

		VarnodeTableModel tableModel = (VarnodeTableModel) table.getModel();
		currentVarnode = tableModel.getRowObject(row);
		type = currentVarnode.getType();

		editorComponent = null;
		switch (type) {
			case Register:
				editorComponent = createRegisterCombo(currentVarnode);
				break;
			case Stack:
				editorComponent = createStackOffsetEditor(currentVarnode);
				break;
			case Memory:
				editorComponent = createAddressEditor(currentVarnode);
				break;
		}
		return editorComponent;
	}

	private Component createAddressEditor(VarnodeInfo varnode) {
		addressInput = new AddressInput();
		addressInput.setAddressFactory(program.getAddressFactory());
		Address address = varnode.getAddress();
		if (address != null) {
			addressInput.setAddress(address);
		}
		addressInput.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				stopCellEditing();
			}
		});
		return addressInput;
	}

	private Component createStackOffsetEditor(VarnodeInfo varnode) {
		offsetInput = new IntegerTextField();
		offsetInput.setHexMode();
		Address address = varnode.getAddress();
		if (address != null) {
			offsetInput.setValue(address.getOffset());
		}
		offsetInput.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				stopCellEditing();
			}
		});
		return offsetInput.getComponent();
	}

	private Component createRegisterCombo(VarnodeInfo varnode) {
		ProgramContext programContext = program.getProgramContext();

		List<Register> validItems = new ArrayList<>(programContext.getRegisters());

		for (Iterator<Register> iter = validItems.iterator(); iter.hasNext();) {
			Register register = iter.next();
			if (register.isProcessorContext() || register.isHidden()) {
				iter.remove();
			}
		}

		Collections.sort(validItems, registerWrapperComparator);
		Register[] registers = validItems.toArray(new Register[validItems.size()]);

		combo = new GhidraComboBox<>(registers);
		combo.setEditable(false);
		combo.setEnterKeyForwarding(true);
		Address address = varnode.getAddress();
		if (address != null && varnode.getSize() != null) {
			Register register = program.getRegister(address, varnode.getSize());
			combo.setSelectedItem(register);
		}

		combo.addPopupMenuListener(new PopupMenuListener() {

			@Override
			public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
				// ignore
			}

			@Override
			public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
				stopCellEditing();
			}

			@Override
			public void popupMenuCanceled(PopupMenuEvent e) {
				// ignore
			}
		});

		combo.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				stopCellEditing();
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
