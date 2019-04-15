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
package ghidra.feature.vt.gui.provider.markuptable;

import java.awt.event.ActionListener;

import javax.swing.JLabel;

import docking.widgets.label.GDLabel;
import ghidra.app.util.AddressInput;
import ghidra.feature.vt.api.main.VTMarkupItem;
import ghidra.feature.vt.gui.editors.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.layout.PairLayout;

public class EditableListingAddress extends DisplayableListingAddress implements EditableAddress {

	private final VTMarkupItem markupItem;

	public EditableListingAddress(Program program, Address currentListingAddress,
			VTMarkupItem markupItem) {
		super(program, currentListingAddress);
		this.markupItem = markupItem;
	}

	@Override
	public AddressEditorPanel getEditorPanel() {
		return new ListingAddressEditorPanel();
	}

	class ListingAddressEditorPanel extends AddressEditorPanel {

		private AddressInput addressField;
		private AddressEditorPanelListener addressPanelListener;

		ListingAddressEditorPanel() {
			buildPanel();
		}

		private void buildPanel() {
			setLayout(new PairLayout(5, 5, 50));

			addressField = new AddressInput();
			addressField.setAddressFactory(program.getAddressFactory());
			if (address != null) {
				addressField.setAddress(address);
			}
			addressField.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(java.awt.event.ActionEvent e) {
					if (addressPanelListener != null) {
						addressPanelListener.addressEdited();
					}
				}
			});
			JLabel label = new GDLabel("Address: ");
			add(label);
			add(addressField);
		}

		@Override
		public Address getAddress() throws InvalidInputException {
			Address selectedAddress = addressField.getAddress();
			if (selectedAddress == null) {
				throw new InvalidInputException(
					"\"" + addressField.getValue() + "\" is not a valid address.");
			}
			if (!program.getMemory().contains(selectedAddress)) {
				throw new InvalidInputException(
					"\"" + selectedAddress.toString() + "\" is not an address in the program.");
			}
			address = selectedAddress;
			return address;
		}

		@Override
		public void setAddressPanelListener(AddressEditorPanelListener addressPanelListener) {
			this.addressPanelListener = addressPanelListener;
		}
	}

	@Override
	public String getEditorTitle() {
		return "Enter Address";
	}

	@Override
	public VTMarkupItem getMarkupItem() {
		return markupItem;
	}
}
