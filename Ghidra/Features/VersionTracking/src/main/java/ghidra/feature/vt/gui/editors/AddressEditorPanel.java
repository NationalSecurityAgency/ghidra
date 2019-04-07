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
package ghidra.feature.vt.gui.editors;

import ghidra.program.model.address.Address;
import ghidra.util.exception.InvalidInputException;

import java.awt.LayoutManager;

import javax.swing.JPanel;

/**
 * AddressEditorPanel should be extended to create a new panel for editing a specific type of 
 * mark-up item destination address.
 */
public abstract class AddressEditorPanel extends JPanel {

	public AddressEditorPanel() {
		super();
	}

	public AddressEditorPanel(boolean isDoubleBuffered) {
		super(isDoubleBuffered);
	}

	public AddressEditorPanel(LayoutManager layout, boolean isDoubleBuffered) {
		super(layout, isDoubleBuffered);
	}

	public AddressEditorPanel(LayoutManager layout) {
		super(layout);
	}

	/**
	 * Gets the address the user entered into the address editor panel.
	 * @return the address
	 * @throws InvalidInputException if the panel doesn't currently have a valid address specified.
	 */
	public abstract Address getAddress() throws InvalidInputException;

	/**
	 * Specifies the listener for this address editor panel. The listener gets notified of 
	 * address edit changes when double click or <Enter> key actions occur.
	 * The listener can then call the getAddress() on the editor panel for the current 
	 * address value.
	 * @param addressPanelListener the address edit action listener.
	 */
	public abstract void setAddressPanelListener(AddressEditorPanelListener addressPanelListener);
}
