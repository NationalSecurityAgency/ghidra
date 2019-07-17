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
package ghidra.app.plugin.core.register;

import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.math.BigInteger;
import java.util.Arrays;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.DialogComponentProvider;
import docking.widgets.combobox.GComboBox;
import docking.widgets.label.GLabel;
import ghidra.app.util.bean.FixedBitSizeValueField;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

public class SetRegisterValueDialog extends DialogComponentProvider {
	private JComboBox<RegisterWrapper> registerComboBox;
	private FixedBitSizeValueField registerValueField;
	private JList addressRangeList;
	private BigInteger registerValue;
	private Register selectedRegister;
	private boolean useValueField;
	private final AddressSetView addrSet;
	private final Program program;

	protected SetRegisterValueDialog(Program program, Register[] registers, Register register,
			AddressSetView addrSet, boolean useValueField) {
		super(useValueField ? "Set" : "Clear" + " Register Values", true, true, true, false);
		this.program = program;
		this.addrSet = addrSet;
		this.useValueField = useValueField;
		addWorkPanel(buildWorkPanel(registers));

		addOKButton();
		addCancelButton();
		if (useValueField) {
			setFocusComponent(registerValueField.getTextComponent());
		}
		setSelectedRegister(register);
		setAddressRanges(addrSet);
		registerChanged();
		updateOkEnablement();
		setDefaultButton(okButton);
		setHelpLocation(new HelpLocation("RegisterPlugin",
			useValueField ? "SetRegisterValues" : "ClearRegisterValues"));
		setRememberSize(false);
	}

	private void updateOkEnablement() {
		// if we are not using the value field, ok should always be enabled.
		// otherwise it should only be enabled when the registerValueField has a value.
		setOkEnabled(!useValueField || registerValueField.getValue() != null);
	}

	private JComponent buildWorkPanel(Register[] registers) {
		registerComboBox = new GComboBox<>(wrapRegisters(registers));
		Font f = registerComboBox.getFont().deriveFont(13f);
		registerComboBox.setFont(f);
		registerValueField = new FixedBitSizeValueField(32, true, false);
		registerValueField.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				updateOkEnablement();
			}
		});

		registerComboBox.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				registerChanged();
			}
		});
		f = new Font("monospaced", Font.PLAIN, 13);

		addressRangeList = new JList();
		addressRangeList.setEnabled(false);
		addressRangeList.setFont(f);
		JScrollPane scrollPane = new JScrollPane(addressRangeList);
		scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
		Dimension d = scrollPane.getPreferredSize();
		d.height = 120;
		d.width = 180;
		scrollPane.setPreferredSize(d);
		JPanel panel = new JPanel(new GridBagLayout());

		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.WEST;
		gbc.insets = new Insets(5, 5, 1, 5);
		gbc.gridx = 0;
		gbc.gridy = 0;
		panel.add(new GLabel("Register:"), gbc);
		gbc.gridy = 1;
		if (useValueField) {
			panel.add(new GLabel("Value:"), gbc);
		}
		gbc.gridy = 2;

		gbc.anchor = GridBagConstraints.NORTHWEST;
		gbc.insets = new Insets(10, 5, 1, 5);
		GLabel addressLabel = new GLabel("Address(es):");
		addressLabel.setVerticalAlignment(SwingConstants.TOP);
		panel.add(addressLabel, gbc);

		gbc.insets = new Insets(5, 5, 1, 5);
		gbc.weightx = 1.0;
		gbc.anchor = GridBagConstraints.WEST;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		gbc.gridx = 1;
		gbc.gridy = 0;
		panel.add(registerComboBox, gbc);
		gbc.gridy = 1;
		if (useValueField) {
			panel.add(registerValueField, gbc);
		}

		gbc.gridy = 2;
		gbc.weighty = 1.0;
		gbc.fill = GridBagConstraints.BOTH;
		panel.add(scrollPane, gbc);

		panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 0, 5));

		return panel;

	}

	private void registerChanged() {
		RegisterWrapper wrapper = (RegisterWrapper) registerComboBox.getSelectedItem();
		if (wrapper != null) {
			registerValueField.setBitSize(wrapper.register.getBitLength());
			updateOkEnablement();
		}
		updateValue();
	}

	void setSelectedRegister(Register register) {
		int n = registerComboBox.getItemCount();
		for (int i = 0; i < n; i++) {
			RegisterWrapper rw = registerComboBox.getItemAt(i);
			if (rw.register == register) {
				registerComboBox.setSelectedIndex(i);
				return;
			}
		}
		updateValue();
	}

	private void updateValue() {
		if (addrSet.getNumAddresses() == 1) {
			Address address = addrSet.getMinAddress();
			RegisterValue value =
				program.getProgramContext().getRegisterValue(doGetSelectedRegister(), address);
			if (value != null) {
				BigInteger unsignedValue = value.getUnsignedValue();
				if (unsignedValue != null) {
					registerValueField.setValue(unsignedValue);
					return;
				}
			}
		}
		registerValueField.setValue(null);

	}

	RegisterWrapper[] wrapRegisters(Register[] registers) {
		RegisterWrapper[] registerWrappers = new RegisterWrapper[registers.length];
		for (int i = 0; i < registers.length; i++) {
			registerWrappers[i] = new RegisterWrapper(registers[i]);
		}
		Arrays.sort(registerWrappers);
		return registerWrappers;
	}

	private void setAddressRanges(AddressSetView addrSet) {
		String[] rangeData = new String[addrSet.getNumAddressRanges()];
		int i = 0;
		for (AddressRange range : addrSet) {
			Address start = range.getMinAddress();
			Address end = range.getMaxAddress();
			if (start.equals(end)) {
				rangeData[i++] = start.toString();
			}
			else {
				rangeData[i++] = start.toString() + " - " + end.toString();
			}
		}
		addressRangeList.setListData(rangeData);
	}

	@Override
	protected void okCallback() {
		registerValue = registerValueField.getValue();
		selectedRegister = doGetSelectedRegister();
		close();
	}

	public BigInteger getRegisterValue() {
		return registerValue;
	}

	private Register doGetSelectedRegister() {
		RegisterWrapper wrapper = (RegisterWrapper) registerComboBox.getSelectedItem();
		if (wrapper != null) {
			return wrapper.register;
		}
		return null;
	}

	public Register getSelectRegister() {
		return selectedRegister;
	}

}

class RegisterWrapper implements Comparable<RegisterWrapper> {
	Register register;
	String displayName;

	RegisterWrapper(Register register) {
		this.register = register;
		displayName = register.getName() + " (" + register.getBitLength() + getAliases() + ")";
	}

	private String getAliases() {
		StringBuffer buf = new StringBuffer();
		for (String alias : register.getAliases()) {
			buf.append(buf.length() == 0 ? "; " : ", ");
			buf.append(alias);
		}
		return buf.toString();
	}

	@Override
	public String toString() {
		return displayName;
	}

	@Override
	public int compareTo(RegisterWrapper o) {
		return register.getName().compareToIgnoreCase(o.register.getName());
	}

}
