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
import java.awt.event.MouseEvent;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;
import javax.swing.event.CellEditorListener;
import javax.swing.event.ChangeEvent;
import javax.swing.table.TableCellEditor;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.DropDownSelectionTextField;
import docking.widgets.table.FocusableEditor;
import docking.widgets.textfield.IntegerTextField;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.app.util.AddressInput;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.util.Msg;
import ghidra.util.Swing;

class VarnodeLocationCellEditor extends AbstractCellEditor
		implements TableCellEditor, FocusableEditor {
	private Program program;
	private VarnodeType type;
	private Component editorComponent;
	private DropDownSelectionTextField<Register> registerEntryTextField;
	private AddressInput addressInput;
	private IntegerTextField offsetInput;

	private Comparator<Register> registerWrapperComparator =
		(r1, r2) -> r1.toString().compareToIgnoreCase(r2.toString());
	private VarnodeInfo currentVarnode;

	VarnodeLocationCellEditor(StorageAddressModel model) {
		this.program = model.getProgram();
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
				String regName = registerEntryTextField.getText().trim();
				if (program.getRegister(regName) == null) {
					if (!StringUtils.isBlank(regName)) {
						Msg.showError(this, editorComponent, "Invalid Register",
							"Register does not exist: " + regName);
					}
					return false;
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
				return registerEntryTextField.getText();

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

	@Override
	public void focusEditor() {
		if (editorComponent instanceof AddressInput input) {
			input.focusEditor();
		}
		else {
			editorComponent.requestFocusInWindow();
		}
	}

	private Component createAddressEditor(VarnodeInfo varnode) {
		addressInput = new AddressInput(program);
		addressInput.setComponentBorders(BorderFactory.createEmptyBorder());

		Address address = varnode.getAddress();
		if (address != null) {
			addressInput.setAddress(address);
		}
		addressInput.addActionListener(e -> stopCellEditing());
		return addressInput;
	}

	private Component createStackOffsetEditor(VarnodeInfo varnode) {
		offsetInput = new IntegerTextField();
		offsetInput.setHexMode();
		Address address = varnode.getAddress();
		if (address != null) {
			offsetInput.setValue(address.getOffset());
		}
		offsetInput.addActionListener(e -> stopCellEditing());
		JComponent component = offsetInput.getComponent();
		component.setBorder(BorderFactory.createLineBorder(Palette.GRAY, 1));
		return component;
	}

	private Component createRegisterCombo(VarnodeInfo varnode) {
		ProgramContext programContext = program.getProgramContext();

		List<Register> registers = new ArrayList<>(programContext.getRegisters());

		for (Iterator<Register> iter = registers.iterator(); iter.hasNext();) {
			Register register = iter.next();
			if (register.isProcessorContext() || register.isHidden()) {
				iter.remove();
			}
		}

		Collections.sort(registers, registerWrapperComparator);
		//Register[] registers = validItems.toArray(new Register[validItems.size()]);

		RegisterDropDownSelectionDataModel registerModel =
			new RegisterDropDownSelectionDataModel(registers);
		registerEntryTextField = new DropDownSelectionTextField<>(registerModel);
		registerEntryTextField.setBorder(null);

		// this allows us to show the matching list when there is no text in the editor
		registerEntryTextField.setShowMatchingListOnEmptyText(true);

		AtomicReference<Register> currentReg = new AtomicReference<>();

		Address address = varnode.getAddress();
		if (address != null && varnode.getSize() != null) {
			Register register = program.getRegister(address, varnode.getSize());
			if (register != null) {
				currentReg.set(register);
				registerEntryTextField.setText(register.getName());
			}
		}

		registerEntryTextField.addCellEditorListener(new CellEditorListener() {

			@Override
			public void editingStopped(ChangeEvent e) {
				stopCellEditing();
			}

			@Override
			public void editingCanceled(ChangeEvent e) {
				cancelCellEditing();
			}
		});

		registerEntryTextField.addActionListener(e -> stopCellEditing());

		// Note: need to do this later.  At the time of construction, this text field is not yet
		// showing.  The text field has checks to avoid showing the list if it is not showing.  By
		// running later, this call will happen once the widget has been added to the table.
		Swing.runLater(() -> {
			registerEntryTextField.showMatchingList();
		});

		return registerEntryTextField;
	}
}
