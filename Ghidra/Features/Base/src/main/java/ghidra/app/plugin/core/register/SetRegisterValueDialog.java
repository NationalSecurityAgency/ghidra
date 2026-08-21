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

import java.awt.Component;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Iterator;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.DialogComponentProvider;
import docking.widgets.combobox.GComboBox;
import docking.widgets.label.GLabel;
import docking.widgets.list.GListCellRenderer;
import docking.widgets.textfield.FixedSizeIntegerTextField;
import generic.theme.GThemeDefaults.Ids.Fonts;
import generic.theme.Gui;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.layout.VariableHeightPairLayout;

public class SetRegisterValueDialog extends DialogComponentProvider {
	private JComboBox<RegisterWrapper> registerComboBox;
	private FixedSizeIntegerTextField registerValueField;
	private JList<String> addressRangeList;
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
			setFocusComponent(registerValueField.getComponent());
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
		GLabel registerLabel = new GLabel("Register:");
		GLabel valueLabel = new GLabel("Value:");
		GLabel addressLabel = new GLabel("Address(es):");
		registerLabel.setHorizontalAlignment(SwingConstants.RIGHT);
		valueLabel.setHorizontalAlignment(SwingConstants.RIGHT);
		addressLabel.setHorizontalAlignment(SwingConstants.RIGHT);
		addressLabel.setVerticalAlignment(SwingConstants.TOP);

		JPanel panel = new JPanel(new VariableHeightPairLayout(10, 10));
		panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 0, 5));
		panel.add(registerLabel);
		panel.add(buildRegisterComboBox(registers));
		panel.add(valueLabel);
		panel.add(buildValueField(registers));
		panel.add(addressLabel);
		panel.add(buildAddressPanel());
		return panel;
	}

	private Component buildValueField(Register[] registers) {
		registerValueField = new FixedSizeIntegerTextField(16, 16);
		registerValueField.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				updateOkEnablement();
			}
		});
		return registerValueField.getComponent();
	}

	private Component buildRegisterComboBox(Register[] registers) {
		registerComboBox = new GComboBox<>(wrapRegisters(registers));
		registerComboBox.setRenderer(new RegisterComboRenderer());

		registerComboBox.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				registerChanged();
				updateComboToolTip();
			}
		});
		updateComboToolTip();
		return registerComboBox;
	}

	private void updateComboToolTip() {
		RegisterWrapper item = (RegisterWrapper) registerComboBox.getSelectedItem();
		String tooltip = item == null ? "" : item.getToolTip();
		registerComboBox.setToolTipText(tooltip);
	}

	private Component buildAddressPanel() {
		addressRangeList = new JList<String>();
		addressRangeList.setEnabled(false);
		Gui.registerFont(addressRangeList, Fonts.MONOSPACED);

		JScrollPane scrollPane = new JScrollPane(addressRangeList);
		scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
		return scrollPane;
	}

	private void registerChanged() {
		RegisterWrapper wrapper = (RegisterWrapper) registerComboBox.getSelectedItem();
		if (wrapper != null) {
			int bitLength = wrapper.register.getBitLength();
			registerValueField.setBitSize(bitLength);
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

	private static class RegisterComboRenderer extends GListCellRenderer<RegisterWrapper> {
		@Override
		public Component getListCellRendererComponent(JList<? extends RegisterWrapper> list,
				RegisterWrapper value, int index, boolean isSelected, boolean hasFocus) {
			super.getListCellRendererComponent(list, value, index, isSelected, hasFocus);
			String toolTip = value.getToolTip();
			setToolTipText(toolTip);
			return this;
		}

		@Override
		protected String getItemText(RegisterWrapper value) {
			return value == null ? "" : value.toString();
		}
	}
}

class RegisterWrapper implements Comparable<RegisterWrapper> {
	Register register;
	String displayName;

	RegisterWrapper(Register register) {
		this.register = register;
		displayName = register.getName() + " (" + register.getBitLength() + ")";
	}

	String getToolTip() {
		StringBuffer buf = new StringBuffer();
		buf.append(displayName);
		buf.append(" Aliases: ");
		Iterator<String> aliases = register.getAliases().iterator();
		if (!aliases.hasNext()) {
			buf.append("none");
		}
		else {
			buf.append(aliases.next());
			buf.append(", ");
		}
		while (aliases.hasNext()) {
			buf.append(", ");
			buf.append(aliases.next());
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
