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
package ghidra.feature.vt.gui.editors;

import java.awt.Component;
import java.awt.event.MouseEvent;
import java.util.EventObject;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.table.TableCellEditor;

import docking.DialogComponentProvider;
import docking.widgets.label.GDLabel;
import ghidra.feature.vt.api.main.VTMarkupItem;
import ghidra.feature.vt.api.main.VTMarkupItemDestinationAddressEditStatus;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;

public class AddressInputDialog extends AbstractCellEditor implements TableCellEditor {

	private DialogComponentProvider dialog;
	private JTable table;
	private Address address;
	private final VTController controller;

	public AddressInputDialog(VTController controller) {
		this.controller = controller;
	}

	@Override
	public Component getTableCellEditorComponent(JTable theTable, Object value, boolean isSelected,
			int row, int column) {

		this.table = theTable;
		EditableAddress editableAddress = (EditableAddress) value;
		address = editableAddress.getAddress();

		JLabel label = new GDLabel();
		label.setBorder(BorderFactory.createBevelBorder(BevelBorder.LOWERED));
		label.setText(editableAddress.getDisplayString());

		VTMarkupItem markupItem = editableAddress.getMarkupItem();
		VTMarkupItemDestinationAddressEditStatus status =
			markupItem.getDestinationAddressEditStatus();
		if (status != VTMarkupItemDestinationAddressEditStatus.EDITABLE) {
			final String description = status.getDescription();
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					fireEditingCanceled();
					Msg.showInfo(getClass(), table, "Cannot Edit Destination Address", description);
				}
			});
			return label;
		}

		dialog = new DialogProvider(editableAddress);
		dialog.setRememberSize(false);
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				controller.getTool().showDialog(dialog, label);
				stopCellEditing();
			}
		});

		return label;
	}

	@Override
	public void cancelCellEditing() {
		if (dialog instanceof DialogProvider) {
			((DialogProvider) dialog).cancelCallback();
		}
	}

	@Override
	public Object getCellEditorValue() {
		return ((DialogProvider) dialog).getAddress();
	}

	@Override
	public boolean stopCellEditing() {
		ListSelectionModel columnSelectionModel = table.getColumnModel().getSelectionModel();
		columnSelectionModel.setValueIsAdjusting(true);
		int columnAnchor = columnSelectionModel.getAnchorSelectionIndex();
		int columnLead = columnSelectionModel.getLeadSelectionIndex();

		dialog.close();

		Address newAddress = null;
		if (dialog instanceof DialogProvider) {
			newAddress = ((DialogProvider) dialog).getAddress();
		}
		if (newAddress == null) {
			// user must have cancelled
			fireEditingCanceled();
			return true;
		}

		if (newAddress.equals(address)) {
			fireEditingCanceled();
			return true;
		}

		address = newAddress;
		fireEditingStopped();

		columnSelectionModel.setAnchorSelectionIndex(columnAnchor);
		columnSelectionModel.setLeadSelectionIndex(columnLead);
		columnSelectionModel.setValueIsAdjusting(false);

		return true;
	}

	// only double-click edits
	@Override
	public boolean isCellEditable(EventObject anEvent) {
		if (anEvent instanceof MouseEvent) {
			return ((MouseEvent) anEvent).getClickCount() >= 2;
		}
		return true;
	}

//==================================================================================================
// Inner Classes    
//==================================================================================================

	private class DialogProvider extends DialogComponentProvider
			implements AddressEditorPanelListener {

		private EditableAddress editableAddress;
		private Address editedAddress;
		private AddressEditorPanel editorPanel;

		protected DialogProvider(EditableAddress address) {
			super(address.getEditorTitle(), true, true, true, false);
			this.editableAddress = address;
			editorPanel = editableAddress.getEditorPanel();
			editorPanel.setAddressPanelListener(this);
			addWorkPanel(editorPanel);
			addOKButton();
			addCancelButton();
		}

		@Override
		protected void cancelCallback() {
			super.cancelCallback();
		}

		@Override
		protected void okCallback() {
			Address newAddress;
			try {
				newAddress = editorPanel.getAddress();
				editedAddress = newAddress;
				close();
			}
			catch (InvalidInputException e) {
				setStatusText(e.getMessage());
			}
		}

		/**
		 * Gets the newly edited address.
		 * @return the address.
		 */
		Address getAddress() {
			return editedAddress;
		}

		/**
		 * An address edit action occurred in the panel so handle it as if ok button were pressed.
		 */
		@Override
		public void addressEdited() {
			okCallback();
		}
	}
}
