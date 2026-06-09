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
package ghidra.app.plugin.core.select;

import java.awt.*;
import java.math.BigInteger;

import javax.swing.*;

import docking.ComponentProvider;
import docking.ReusableDialogComponentProvider;
import docking.widgets.button.GRadioButton;
import docking.widgets.label.GLabel;
import docking.widgets.textfield.IntegerTextField;
import ghidra.app.nav.Navigatable;
import ghidra.app.nav.NavigationUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.layout.PairLayout;

/**
 * Dialog for making program selections
 */
class SelectBytesDialog extends ReusableDialogComponentProvider {

	private PluginTool tool;
	private Navigatable navigatable;

	private JTextField toAddressField;
	private IntegerTextField lengthField;
	private JRadioButton forwardButton;
	private JRadioButton backwardButton;
	private JRadioButton allButton;
	private JRadioButton toButton;

	SelectBytesDialog(PluginTool tool, Navigatable navigatable) {
		super("Select Bytes", false, true, true, false);
		this.tool = tool;
		this.navigatable = navigatable;

		addWorkPanel(buildPanel());
		addOKButton();
		setOkButtonText("Select Bytes");
		addDismissButton();
		setHelpLocation(new HelpLocation("SelectBytesPlugin", "Select_Bytes_Help"));

		setItemsEnabled(false);
		forwardButton.doClick();
	}

	private JPanel buildPanel() {
		setDefaultButton(okButton);
		JPanel mainPanel = new JPanel();
		mainPanel.setLayout(new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.insets = new Insets(2, 2, 2, 2);
		gbc.gridx = 0;
		gbc.gridy = 0;
		mainPanel.add(buildMethodPanel(), gbc);
		gbc.gridx++;
		mainPanel.add(buildInputPanel(), gbc);
		return mainPanel;
	}

	private JPanel buildInputPanel() {
		JPanel main = new JPanel();
		main.setBorder(BorderFactory.createTitledBorder("Byte Selection"));

		main.setLayout(new PairLayout());

		main.add(new GLabel("Ending Address:"));
		toAddressField = new JTextField(10);
		toAddressField.getAccessibleContext().setAccessibleName("To Address");
		main.add(toAddressField);

		main.add(new GLabel("Length: "));
		lengthField = new IntegerTextField(10);
		lengthField.getComponent().getAccessibleContext().setAccessibleName("Number Input");
		lengthField.setMinValue(BigInteger.ZERO);
		return main;
	}

	private JPanel buildMethodPanel() {
		ButtonGroup buttonGroup = new ButtonGroup();
		JPanel main = new JPanel();
		main.setBorder(BorderFactory.createTitledBorder("By Method"));
		main.setLayout(new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.insets = new Insets(2, 2, 2, 2);
		gbc.anchor = GridBagConstraints.WEST;

		forwardButton = new GRadioButton("Select Forward", true);
		forwardButton.setName("forwardButton");
		forwardButton.getAccessibleContext().setAccessibleName("Forward");
		forwardButton.addActionListener(ae -> {
			setStatusText("Enter number of bytes to select");
			setAddressFieldEnabled(false);
			setLengthInputEnabled(true);
		});
		buttonGroup.add(forwardButton);
		backwardButton = new GRadioButton("Select Backward");
		backwardButton.setName("backwardButton");
		backwardButton.getAccessibleContext().setAccessibleName("Backward");
		backwardButton.addActionListener(ae -> {
			setStatusText("Enter number of bytes to select");
			setAddressFieldEnabled(false);
			setLengthInputEnabled(true);
		});
		buttonGroup.add(backwardButton);
		allButton = new GRadioButton("Select All");
		allButton.setName("allButton");
		allButton.getAccessibleContext().setAccessibleName("All");
		allButton.addActionListener(ae -> {
			setItemsEnabled(false);
			clearStatusText();
		});

		buttonGroup.add(allButton);
		toButton = new GRadioButton("To Address");
		toButton.setName("toButton");
		toButton.getAccessibleContext().setAccessibleName("To Address");
		toButton.addActionListener(ae -> {
			setStatusText("Enter an Address to go to");
			setAddressFieldEnabled(true);
			setLengthInputEnabled(false);
		});
		buttonGroup.add(toButton);
		gbc.gridx = 0;
		gbc.gridy = 0;
		main.add(allButton, gbc);
		gbc.gridy++;
		main.add(toButton, gbc);
		gbc.gridx++;
		gbc.gridy = 0;
		main.add(forwardButton, gbc);
		gbc.gridy++;
		main.add(backwardButton, gbc);
		setStatusText("Enter number of bytes to select");
		main.getAccessibleContext().setAccessibleName("Methods");
		return main;
	}

	@Override
	public void close() {
		super.close();
		navigatable = null;
	}

	void setNavigatable(Navigatable navigatable) {
		this.navigatable = navigatable;
		setOkEnabled(navigatable != null);
	}

	void show(ComponentProvider provider) {
		tool.showDialog(this, provider);
		repack();
	}

	void setLength(int length) {
		lengthField.setText(Integer.toString(length));
	}

	private void setItemsEnabled(boolean enabled) {
		setAddressFieldEnabled(enabled);
		setLengthInputEnabled(enabled);
	}

	private void setAddressFieldEnabled(boolean enabled) {
		toAddressField.setText("");
		toAddressField.setEditable(enabled);
		toAddressField.setEnabled(enabled);
	}

	private void setLengthInputEnabled(boolean enabled) {
		if (!enabled) {
			lengthField.setValue(null);
		}
		lengthField.setEnabled(enabled);

	}

	@Override
	protected void okCallback() {
		if (toButton.isSelected()) {
			selectToAddress();
		}
		else if (allButton.isSelected()) {
			selectAll();
		}
		else if (forwardButton.isSelected()) {
			createSelection(true);
		}
		else if (backwardButton.isSelected()) {
			createSelection(false);
		}
		else {
			setStatusText("You must choose the type of selection to make");
		}
	}

	private void selectAll() {
		AddressSetView addressSet = navigatable.getProgram().getMemory();
		ProgramSelection selection = new ProgramSelection(addressSet);
		NavigationUtils.setSelection(tool, navigatable, selection);
		clearStatusText();
	}

	private void selectToAddress() {

		String addressValue = toAddressField.getText();
		clearStatusText();

		// make sure the order of the addresses is correct
		Address currentAddress = navigatable.getLocation().getAddress();
		Address to = null;
		try {
			to = currentAddress.getAddress(addressValue);
		}
		catch (AddressFormatException e) {
			// use the fact that toAddress remains null
		}

		if (to == null) {
			setStatusText("Invalid address value, enter another address");
			return;
		}

		if (to.compareTo(currentAddress) < 0) {
			Address tmp = to;
			to = currentAddress;
			currentAddress = tmp;
		}
		AddressSet addressSet = new AddressSet(currentAddress, to);
		ProgramSelection selection = new ProgramSelection(addressSet);
		NavigationUtils.setSelection(tool, navigatable, selection);
	}

	private void createSelection(boolean forward) {
		BigInteger length = lengthField.getValue();
		if (length == null || length == BigInteger.ZERO) {
			setStatusText("length must be > 0");
			return;
		}

		clearStatusText();

		AddressSet startSet;
		ProgramSelection currentSelection = navigatable.getSelection();
		if (!currentSelection.isEmpty()) {
			startSet = new AddressSet(currentSelection);
		}
		else {
			Address currentAddress = navigatable.getLocation().getAddress();
			startSet = new AddressSet(currentAddress);
		}

		AddressRangeIterator it = startSet.getAddressRanges();
		AddressSet newSet = new AddressSet();
		while (it.hasNext()) {
			AddressRange range = it.next();

			if (forward) {
				Address from = range.getMinAddress();
				createForwardRange(newSet, from, length);
			}
			else {
				Address to = range.getMaxAddress();
				createBackwardRange(newSet, to, length);
			}
		}

		ProgramSelection newSelection = new ProgramSelection(newSet);
		NavigationUtils.setSelection(tool, navigatable, newSelection);
	}

	private void createForwardRange(AddressSet set, Address from, BigInteger length) {
		Address to = getToAddress(from, length);
		set.addRange(from, to);
	}

	private void createBackwardRange(AddressSet set, Address to, BigInteger length) {
		Address from = getFromAddress(to, length);
		set.addRange(from, to);
	}

	private Address getFromAddress(Address to, BigInteger length) {

		// subtract one to be inclusive; address ranges are inclusive
		BigInteger inclusiveLength = length.subtract(BigInteger.ONE);
		try {
			return to.subtractNoWrap(inclusiveLength);
		}
		catch (AddressOverflowException e) {
			showWarningDialog();
			AddressSpace space = to.getAddressSpace();
			return space.getMinAddress();
		}
	}

	private Address getToAddress(Address from, BigInteger length) {

		// subtract one to be inclusive; address ranges are inclusive
		BigInteger inclusiveLength = length.subtract(BigInteger.ONE);
		try {
			return from.addNoWrap(inclusiveLength);
		}
		catch (AddressOverflowException e) {
			showWarningDialog();
			AddressSpace space = from.getAddressSpace();
			return space.getMaxAddress();
		}
	}

	private void showWarningDialog() {
		Msg.showWarn(this, getComponent(), "Selection Overflow",
			"Selection is larger than available bytes. Using the boundary of the address space.");
	}

}
