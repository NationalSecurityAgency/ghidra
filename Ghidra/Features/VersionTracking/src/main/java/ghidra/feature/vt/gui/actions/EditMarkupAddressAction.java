/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.feature.vt.gui.actions;

import ghidra.feature.vt.api.main.VTMarkupItem;
import ghidra.feature.vt.api.main.VTMarkupItemDestinationAddressEditStatus;
import ghidra.feature.vt.gui.editors.*;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.provider.markuptable.EditableListingAddress;
import ghidra.feature.vt.gui.task.SetMarkupItemDestinationAddressTask;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.exception.InvalidInputException;

import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import resources.ResourceManager;
import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.*;

public class EditMarkupAddressAction extends DockingAction {

	private static final String MENU_GROUP = VTPlugin.ADDRESS_EDIT_MENU_GROUP;
	private static final Icon EDIT_ADDRESS_ICON =
		ResourceManager.loadImage("images/edit-rename.png");
	private static final String ACTION_NAME = "Edit Markup Destination Address";

	final VTController controller;

	public EditMarkupAddressAction(VTController controller, boolean addToToolbar) {
		super(ACTION_NAME, VTPlugin.OWNER);
		this.controller = controller;
		setDescription("Edit Markup Destination Address");
		if (addToToolbar) {
			setToolBarData(new ToolBarData(EDIT_ADDRESS_ICON, MENU_GROUP));
		}
		MenuData menuData =
			new MenuData(new String[] { "Edit Destination Address" }, EDIT_ADDRESS_ICON, MENU_GROUP);
		setPopupMenuData(menuData);
		setEnabled(false);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin",
			"Edit_Markup_Item_Destination_Address"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		List<VTMarkupItem> markupItems = controller.getMarkupItems(context);
		for (VTMarkupItem markupItem : markupItems) {
			JComponent component = context.getComponentProvider().getComponent();
			editDestinationAddress(markupItem, component);
		}
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		List<VTMarkupItem> markupItems = controller.getMarkupItems(context);
		if (markupItems.size() != 1) {
			return false;
		}

		VTMarkupItem item = markupItems.get(0);
		VTMarkupItemDestinationAddressEditStatus status = item.getDestinationAddressEditStatus();
		return status == VTMarkupItemDestinationAddressEditStatus.EDITABLE;
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		List<VTMarkupItem> markupItems = controller.getMarkupItems(context);
		if (markupItems.size() != 1) {
			return false;
		}

		return true;
	}

	private void editDestinationAddress(final VTMarkupItem markupItem, final JComponent component) {

		VTMarkupItemDestinationAddressEditStatus status =
			markupItem.getDestinationAddressEditStatus();
		if (status != VTMarkupItemDestinationAddressEditStatus.EDITABLE) {
			final String description = status.getDescription();
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					Msg.showInfo(getClass(), component, "Cannot Edit Destination Address",
						description);
				}
			});
			return;
		}

		final Address destinationAddress = markupItem.getDestinationAddress();
		Program destinationProgram = controller.getDestinationProgram();
		final EditableAddress editableAddress =
			new EditableListingAddress(destinationProgram, destinationAddress, markupItem);
		final DialogProvider dialog = new DialogProvider(editableAddress);
		dialog.setRememberSize(false);
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				controller.getTool().showDialog(dialog, component);
				Address newDestinationAddress = dialog.getAddress();
				if (SystemUtilities.isEqual(destinationAddress, newDestinationAddress)) {
					return;
				}

				ArrayList<VTMarkupItem> arrayList = new ArrayList<VTMarkupItem>();
				arrayList.add(markupItem);
				SetMarkupItemDestinationAddressTask task =
					new SetMarkupItemDestinationAddressTask(controller.getSession(), arrayList,
						newDestinationAddress);
				controller.runVTTask(task);
			}
		});

	}

//==================================================================================================
// Inner Classes    
//==================================================================================================

	private class DialogProvider extends DialogComponentProvider implements
			AddressEditorPanelListener {

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
