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
package ghidra.app.plugin.core.references;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GComboBox;
import docking.widgets.label.GLabel;
import ghidra.app.util.AddressInput;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.layout.PairLayout;

/**
 * Dialog to prompt for base address and the size of the data type that
 * will be used in creating an offset table.
 * 
 * 
 */
public class OffsetTableDialog extends DialogComponentProvider {

	private AddressInput addrInput;
	private JComboBox<String> comboBox;
	private Address defaultAddress;
	private JCheckBox signedCheckBox;
	boolean canceled = false;

	/**
	 * Construct a new dialog
	 * @param defaultAddress address to put in the address field as a default
	 * @param program the program
	 */
	OffsetTableDialog(Address defaultAddress, Program program) {
		super("Create Offset References", true);
		this.defaultAddress = defaultAddress;
		addWorkPanel(buildMainPanel(program));
		addOKButton();
		addCancelButton();
		setHelpLocation(new HelpLocation(HelpTopics.REFERENCES, "Create_Offset_References"));
	}

	/* (non Javadoc)
	 * @see ghidra.util.bean.GhidraDialog#cancelCallback()
	 */
	@Override
	protected void cancelCallback() {
		canceled = true;
		close();
	}

	/* (non Javadoc)
	 * @see ghidra.util.bean.GhidraDialog#okCallback()
	 */
	@Override
	protected void okCallback() {
		if (addrInput.getAddress() != null) {
			close();
		}
		else {
			setStatusText("Please enter a valid address");
		}
	}

	void setSelectedSize(int size) {
		comboBox.setSelectedItem(Integer.toString(size));
	}

	/**
	 * Displays the dialog for specifying the information for offset table references.
	 * @throws CancelledException if the user cancels the dialog.
	 */
	void showDialog(PluginTool tool) throws CancelledException {
		canceled = false;
		tool.showDialog(this);
		if (canceled) {
			throw new CancelledException();
		}
	}

	/**
	 * Get the selected size of the data type.
	 */
	int getSelectedSize() {
		String sel = (String) comboBox.getSelectedItem();
		return Integer.parseInt(sel);
	}

	public Address getBaseAddress() {
		return addrInput.getAddress();
	}

	public void setBaseAddress(Address address) {
		addrInput.setAddress(address);
	}

	boolean isSigned() {
		return signedCheckBox.isSelected();
	}

	void setSigned(boolean isSigned) {
		signedCheckBox.setSelected(isSigned);
	}

	private JPanel buildMainPanel(Program program) {
		JPanel panel = new JPanel(new PairLayout(10, 5));
		panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 10, 20));
		addrInput = new AddressInput(program, a -> clearStatusText());
		addrInput.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				okCallback();
			}
		});
		addrInput.setAddress(defaultAddress);

		panel.add(new GLabel("Enter Base Address:", SwingConstants.RIGHT));
		panel.add(addrInput);

		comboBox = new GComboBox<>(new String[] { "1", "2", "4", "8" });
		int pointerSize = defaultAddress.getPointerSize();
		comboBox.setSelectedItem(Integer.toString(pointerSize));
		comboBox.getAccessibleContext().setAccessibleName("Address");
		panel.add(new GLabel("Select Data Size (Bytes):", SwingConstants.RIGHT));
		panel.add(comboBox);

		signedCheckBox = new GCheckBox("Signed Data Value(s)", true);
		signedCheckBox.getAccessibleContext().setAccessibleName("Signed Data Value");
		panel.add(signedCheckBox);
		panel.getAccessibleContext().setAccessibleName("Offset Table");
		return panel;
	}
}
