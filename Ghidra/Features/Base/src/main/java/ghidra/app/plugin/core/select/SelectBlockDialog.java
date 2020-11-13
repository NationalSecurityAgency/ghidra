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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;

import javax.swing.*;

import docking.ComponentProvider;
import docking.DialogComponentProvider;
import docking.widgets.button.GRadioButton;
import docking.widgets.label.GLabel;
import docking.widgets.textfield.IntegerTextField;
import ghidra.app.nav.Navigatable;
import ghidra.app.nav.NavigationUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.layout.PairLayout;

/**
 * Class to set up dialog box that will enable the user
 * to set the available options for block selection
 */
class SelectBlockDialog extends DialogComponentProvider {
	private static final String OVERFLOW_SELECTION_WARNING =
		"Selection is larger than available " + "bytes, using the end of the address space";

	private JTextField toAddressField;
	private IntegerTextField numberInputField; // AddressInput allows decimal and hex input 
	private JRadioButton forwardButton;
	private JRadioButton backwardButton;
	private JRadioButton allButton;
	private JRadioButton toButton;
	private Navigatable navigatable;
	private PluginTool tool;

	SelectBlockDialog(PluginTool tool, Navigatable navigatable) {
		super("Select Bytes", false);
		this.tool = tool;
		this.navigatable = navigatable;
//		navigatable.addNavigatableListener(this);

		addWorkPanel(buildPanel());
		addOKButton();
		setOkButtonText("Select Bytes");
		addDismissButton();
		setHelpLocation(new HelpLocation("SelectBlockPlugin", "Select_Block_Help"));

		// make sure the state of the widgets is correct
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
		mainPanel.add(methodPanel(), gbc);
		gbc.gridx++;
		mainPanel.add(buildBlockPanel(), gbc);

		return mainPanel;
	}

	private JPanel buildBlockPanel() {
		JPanel main = new JPanel();
		main.setBorder(BorderFactory.createTitledBorder("Byte Selection"));
		
		main.setLayout(new PairLayout());

		main.add(new GLabel("Ending Address:"));
		toAddressField = new JTextField(10);
		main.add(toAddressField);

		main.add(new GLabel("Length: "));
		numberInputField = new IntegerTextField(10);
		numberInputField.setMaxValue(BigInteger.valueOf(Integer.MAX_VALUE));
		numberInputField.setAllowNegativeValues(false);
		main.add(numberInputField.getComponent());
		return main;
	}

	private JPanel methodPanel() {
		ButtonGroup buttonGroup = new ButtonGroup();
		JPanel main = new JPanel();
		main.setBorder(BorderFactory.createTitledBorder("By Method"));
		main.setLayout(new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.insets = new Insets(2, 2, 2, 2);
		gbc.anchor = GridBagConstraints.WEST;

		forwardButton = new GRadioButton("Select Forward", true);
		forwardButton.setName("forwardButton");
		forwardButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				setStatusText("Enter number of bytes to select");
				setAddressFieldEnabled(false);
				setLengthInputEnabled(true);
			}
		});
		buttonGroup.add(forwardButton);
		backwardButton = new GRadioButton("Select Backward");
		backwardButton.setName("backwardButton");
		backwardButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				setStatusText("Enter number of bytes to select");
				setAddressFieldEnabled(false);
				setLengthInputEnabled(true);
			}
		});
		buttonGroup.add(backwardButton);
		allButton = new GRadioButton("Select All");
		allButton.setName("allButton");
		allButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				setItemsEnabled(false);
				clearStatusText();
			}
		});

		buttonGroup.add(allButton);
		toButton = new GRadioButton("To Address");
		toButton.setName("toButton");
		toButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ae) {
				setStatusText("Enter an Address to go to");
				setAddressFieldEnabled(true);
				setLengthInputEnabled(false);
			}
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
		return main;
	}

	@Override
	public void close() {
		super.close();
		navigatable = null;
	}

	void show(ComponentProvider provider) {
		tool.showDialog(this, provider);
		repack();
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
			numberInputField.setValue(null);
		}
		numberInputField.setEnabled(enabled);

	}

	@Override
	protected void okCallback() {
		if (toButton.isSelected()) {
			handleToAddressSelection();
		}
		else if (allButton.isSelected()) {
			handleAllSelection();
		}
		else if (forwardButton.isSelected()) {
			handleForwardSelection();
		}
		else if (backwardButton.isSelected()) {
			handleBackwardSelection();
		}
		else {
			setStatusText("You must choose the type of selection to make");
		}
	}

	private void handleAllSelection() {
		AddressSetView addressSet = navigatable.getProgram().getMemory();
		ProgramSelection selection = new ProgramSelection(addressSet);
		NavigationUtils.setSelection(tool, navigatable, selection);
		clearStatusText();
	}

	private void handleToAddressSelection() {
		Address toAddress = null;
		String addressValue = toAddressField.getText();
		clearStatusText();

		// make sure the order of the addresses is correct
		Address currentAddress = navigatable.getLocation().getAddress();
		try {
			toAddress = currentAddress.getAddress(addressValue);
		}
		catch (AddressFormatException e) {
			// use the fact that toAddress remains null
		}
		if (toAddress == null) {
			setStatusText("Invalid address value, enter another address");
			return;
		}
		if (toAddress.compareTo(currentAddress) < 0) {
			Address tmp = toAddress;
			toAddress = currentAddress;
			currentAddress = tmp;
		}
		AddressSet addressSet = new AddressSet(currentAddress, toAddress);
		ProgramSelection selection = new ProgramSelection(addressSet);
		NavigationUtils.setSelection(tool, navigatable, selection);
	}

	private void handleForwardSelection() {
		// value is a length
		int length = numberInputField.getIntValue(); // throws NFE
		if (length == 0) {
			setStatusText("length must be > 0");
			return;
		}

		clearStatusText();

		// the number value is a byte size, which means we need to adjust that value by
		// the addressable unit size of the processor
		Address currentAddress = navigatable.getLocation().getAddress();

		AddressSet addressSet = new AddressSet(navigatable.getSelection());

		if (addressSet.isEmpty()) {
			addressSet.addRange(currentAddress, currentAddress);
		}
		length *= currentAddress.getAddressSpace().getAddressableUnitSize();

		AddressRangeIterator aiter = addressSet.getAddressRanges();
		AddressSet newSet = new AddressSet();
		while (aiter.hasNext()) {
			AddressRange range = aiter.next();
			Address toAddress = createForwardToAddress(range.getMinAddress(), length - 1);
			newSet.addRange(range.getMinAddress(), toAddress);
		}
		ProgramSelection selection = new ProgramSelection(newSet);
		NavigationUtils.setSelection(tool, navigatable, selection);
	}

	private void handleBackwardSelection() {
		// value is a length
		int length = numberInputField.getIntValue();
		if (length == 0) {
			setStatusText("length must be > 0");
			return;
		}
		clearStatusText();

		// the number value is a byte size, which means we need to adjust that value by
		// the addressable unit size of the processor
		Address currentAddress = navigatable.getLocation().getAddress();
		length *= currentAddress.getAddressSpace().getAddressableUnitSize();

		AddressFactory addressFactory = navigatable.getProgram().getAddressFactory();
		AddressSet addressSet = new AddressSet(navigatable.getSelection());
		if (addressSet.isEmpty()) {
			addressSet.addRange(currentAddress, currentAddress);
		}

		AddressRangeIterator aiter = addressSet.getAddressRanges();
		AddressSet newSet = new AddressSet();
		while (aiter.hasNext()) {
			AddressRange range = aiter.next();

			Address fromAddress = createBackwardToAddress(range.getMaxAddress(), length - 1);
			newSet.addRange(fromAddress, range.getMaxAddress());
		}
		ProgramSelection selection = new ProgramSelection(newSet);
		NavigationUtils.setSelection(tool, navigatable, selection);
	}

	private Address createBackwardToAddress(Address startAddress, long length) {
		AddressSpace addressSpace = startAddress.getAddressSpace();
		if (addressSpace.isOverlaySpace()) {
			OverlayAddressSpace oas = (OverlayAddressSpace) addressSpace;
			if (startAddress.getOffset() - length < oas.getMinOffset()) {
				showWarningDialog(OVERFLOW_SELECTION_WARNING);
				return addressSpace.getAddress(oas.getMinOffset());
			}
		}

		Address toAddress = null;
		try {
			toAddress = startAddress.subtract(length);
		}
		catch (AddressOutOfBoundsException aoobe) {
			showWarningDialog(OVERFLOW_SELECTION_WARNING);
			toAddress = addressSpace.getMinAddress();
		}

		return toAddress;
	}

	private Address createForwardToAddress(Address startAddress, long length) {
		AddressSpace addressSpace = startAddress.getAddressSpace();
		if (addressSpace.isOverlaySpace()) {
			OverlayAddressSpace oas = (OverlayAddressSpace) addressSpace;
			if (startAddress.getOffset() + length > oas.getMaxOffset()) {
				showWarningDialog(OVERFLOW_SELECTION_WARNING);
				return addressSpace.getAddress(oas.getMaxOffset());
			}
		}

		Address toAddress = null;
		try {
			toAddress = startAddress.add(length);
		}
		catch (AddressOutOfBoundsException aoobe) {
			showWarningDialog(OVERFLOW_SELECTION_WARNING);
			toAddress = addressSpace.getMaxAddress();
		}

		return toAddress;
	}

	private void showWarningDialog(final String text) {
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				JOptionPane.showMessageDialog(getComponent(), text);
			}
		});
	}

	public void setNavigatable(Navigatable navigatable) {
		this.navigatable = navigatable;
		setOkEnabled(navigatable != null);
	}
}
