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
package ghidra.feature.vt.gui.provider.markuptable;

import ghidra.feature.vt.api.main.VTMarkupItem;
import ghidra.feature.vt.gui.editors.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.util.exception.InvalidInputException;

import java.awt.BorderLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.*;
import javax.swing.event.ListDataListener;

public class EditableParameterAddress extends DisplayableParameterAddress implements
		EditableAddress {

	private final VTMarkupItem markupItem;

	public EditableParameterAddress(Function function, Address currentParameterAddress,
			VTMarkupItem markupItem) {
		super(function, currentParameterAddress);
		this.markupItem = markupItem;
	}

	@Override
	public AddressEditorPanel getEditorPanel() {
		return new ParameterAddressEditorPanel();
	}

	class ParameterAddressEditorPanel extends AddressEditorPanel {

		private JList jList;
		private AddressEditorPanelListener addressPanelListener;

		ParameterAddressEditorPanel() {
			buildPanel();
		}

		private void buildPanel() {
			setLayout(new BorderLayout());
			final Parameter[] parameters = function.getParameters();
			jList = new JList(new ListModel() {

				@Override
				public void addListDataListener(ListDataListener l) {
					// no-op
				}

				@Override
				public Object getElementAt(int index) {
					if (index == 0) {
						return NO_ADDRESS;
					}
					if (index <= parameters.length) {
						return getDisplayValue(parameters[index - 1]);
					}
					return null;
				}

				@Override
				public int getSize() {
					return parameters.length + 1;
				}

				@Override
				public void removeListDataListener(ListDataListener l) {
					// no-op
				}
			});
			jList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
			int defaultListIndex = getListIndex(parameterAddress, parameters);
			jList.setSelectedIndex(defaultListIndex);

			JScrollPane scrollPane = new JScrollPane(jList);
			add(scrollPane, BorderLayout.CENTER);

			jList.addMouseListener(new MouseAdapter() {
				@Override
				public void mouseReleased(MouseEvent e) {
					int index = jList.locationToIndex(e.getPoint());
					if (index >= 0) {
						if (e.getClickCount() == 2) {
							if (addressPanelListener != null) {
								addressPanelListener.addressEdited();
							}
						}
					}
				}
			});

			setBorder(BorderFactory.createEmptyBorder(2, 5, 5, 5));
		}

		private int getListIndex(Address desiredParameterAddress, Parameter[] parameters) {
			for (int i = 0; i < parameters.length; i++) {
				if (parameters[i].getMinAddress().equals(desiredParameterAddress)) {
					return i + 1;
				}
			}
			return 0;
		}

		@Override
		public Address getAddress() throws InvalidInputException {
			int selectedIndex = jList.getSelectedIndex();
			if (selectedIndex == -1) {
				throw new InvalidInputException("No list item was selected.");
			}
			if (selectedIndex == 0) {
				return Address.NO_ADDRESS; // "No Address" was selected in the list.
			}
			final Parameter[] parameters = function.getParameters();
			Parameter parameter = null;
			if (selectedIndex >= 1 && selectedIndex <= parameters.length) {
				parameter = parameters[selectedIndex - 1];
			}
//			Parameter parameter = (Parameter) jList.getSelectedValue();
			if (parameter == null) {
				return null;
			}
			Address storageAddress = parameter.getMinAddress();
			if (storageAddress == null) {
				return null;
			}
			parameterAddress = storageAddress;
			return parameterAddress;
		}

		@Override
		public void setAddressPanelListener(AddressEditorPanelListener addressPanelListener) {
			this.addressPanelListener = addressPanelListener;
		}
	}

	@Override
	public String getEditorTitle() {
		return "Select Parameter Address";
	}

	@Override
	public VTMarkupItem getMarkupItem() {
		return markupItem;
	}
}
