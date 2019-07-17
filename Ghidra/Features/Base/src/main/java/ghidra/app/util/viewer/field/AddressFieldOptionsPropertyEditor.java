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
package ghidra.app.util.viewer.field;

import java.awt.Component;
import java.beans.PropertyEditorSupport;
import java.math.BigInteger;

import javax.swing.JPanel;
import javax.swing.SwingConstants;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GDLabel;
import docking.widgets.textfield.IntegerTextField;
import ghidra.framework.options.CustomOptionsEditor;
import ghidra.util.HTMLUtilities;
import ghidra.util.layout.PairLayout;

public class AddressFieldOptionsPropertyEditor extends PropertyEditorSupport
		implements CustomOptionsEditor {

	// names
	private static final String SHOW_BLOCK_NAME_LABEL = "Show Block Name";
	private static final String ADDRESS_DIGITS_LABEL = "Minimum Number of Address digits";
	private static final String PADDING_LABEL = "Fully Pad With Leading Zeros";
	private static final String JUSTIFICATION_LABEL = "Justification";

	private static final String[] NAMES =
		{ SHOW_BLOCK_NAME_LABEL, ADDRESS_DIGITS_LABEL, PADDING_LABEL, JUSTIFICATION_LABEL };

	// help tooltips
	private static final String ADDRESS_PADDING_TOOLTIP = HTMLUtilities.toWrappedHTML(
		"Pads Addresses with leading zeros to the full size of the largest possible address.", 75);
	private static final String MIN_HEX_DIGITS_TOOLTIP = HTMLUtilities.toWrappedHTML(
		"Specifies the minimum number of hex digits to display the address (The " +
			"minimum is actually the smaller of this number and the number of digits in " +
			"largest possible address in that address space.)",
		75);
	private static final String SHOW_BLOCKNAME_TOOLTIP = HTMLUtilities.toWrappedHTML(
		"Prepends the Memory Block name to address in the address field.", 75);
	private static final String RIGHT_JUSTIFY_TOOLTIP = HTMLUtilities.toWrappedHTML(
		"Specifies the justification for address text in the address field. The address " +
			"text will clip on the opposite side of the justification.",
		75);

	private static final String[] DESCRIPTIONS = { ADDRESS_PADDING_TOOLTIP, MIN_HEX_DIGITS_TOOLTIP,
		SHOW_BLOCKNAME_TOOLTIP, RIGHT_JUSTIFY_TOOLTIP };

	private AddressFieldOptionsWrappedOption addressFieldOptionsWrappedOption;

	private Component editorComponent;
	private GCheckBox padCheckBox;
	private IntegerTextField minDigitsField;
	private GCheckBox showBlocknameCheckbox;
	private GhidraComboBox<String> justificationCombobox;

	public AddressFieldOptionsPropertyEditor() {
		editorComponent = buildEditor();
	}

	private Component buildEditor() {
		// we want to have a panel with our options so that we may group them together
		JPanel panel = new JPanel(new PairLayout(6, 10));

		GDLabel label = new GDLabel(SHOW_BLOCK_NAME_LABEL, SwingConstants.RIGHT);
		label.setToolTipText(SHOW_BLOCKNAME_TOOLTIP);
		panel.add(label);
		showBlocknameCheckbox = new GCheckBox();
		showBlocknameCheckbox.setToolTipText(SHOW_BLOCKNAME_TOOLTIP);
		panel.add(showBlocknameCheckbox);

		// the namespace checkbox will disable the text field options when it is not used
		label = new GDLabel(PADDING_LABEL, SwingConstants.RIGHT);
		label.setToolTipText(ADDRESS_PADDING_TOOLTIP);
		panel.add(label);
		padCheckBox = new GCheckBox();
		panel.add(padCheckBox);
		padCheckBox.setSelected(false);
		padCheckBox.setToolTipText(ADDRESS_PADDING_TOOLTIP);
		label = new GDLabel(ADDRESS_DIGITS_LABEL, SwingConstants.RIGHT);
		label.setToolTipText(MIN_HEX_DIGITS_TOOLTIP);
		panel.add(label);

		minDigitsField = new IntegerTextField(2);
		minDigitsField.setAllowNegativeValues(false);
		minDigitsField.setDecimalMode();
		minDigitsField.setMaxValue(BigInteger.valueOf(32));
		minDigitsField.getComponent().setToolTipText(MIN_HEX_DIGITS_TOOLTIP);

		panel.add(minDigitsField.getComponent());

		label = new GDLabel(JUSTIFICATION_LABEL, SwingConstants.RIGHT);
		label.setToolTipText(RIGHT_JUSTIFY_TOOLTIP);
		panel.add(label);
		justificationCombobox = new GhidraComboBox<>(new String[] { "Left", "Right" });
		justificationCombobox.setToolTipText(RIGHT_JUSTIFY_TOOLTIP);
		panel.add(justificationCombobox);

		showBlocknameCheckbox.addItemListener(evt -> firePropertyChange());
		justificationCombobox.addItemListener(evt -> firePropertyChange());

		padCheckBox.addItemListener(evt -> {
			boolean enabled = !padCheckBox.isSelected();
			minDigitsField.setEnabled(enabled);
			firePropertyChange();
		});
		minDigitsField.addChangeListener(evt -> firePropertyChange());
		return panel;
	}

	@Override
	public void setValue(Object value) {
		if (!(value instanceof AddressFieldOptionsWrappedOption)) {
			return;
		}

		addressFieldOptionsWrappedOption = (AddressFieldOptionsWrappedOption) value;
		setLocalValues(addressFieldOptionsWrappedOption);
		firePropertyChange();
	}

	private int getMinNumberOfDigits() {
		return minDigitsField.getIntValue();
	}

	private void setLocalValues(AddressFieldOptionsWrappedOption addressPaddingOption) {
		if (addressPaddingOption.showBlockName() != showBlocknameCheckbox.isSelected()) {
			showBlocknameCheckbox.setSelected(addressPaddingOption.showBlockName());
		}
		boolean rightJust = justificationCombobox.getSelectedItem().equals("Right");
		if (addressPaddingOption.rightJustify() != rightJust) {
			justificationCombobox.setSelectedIndex(addressPaddingOption.rightJustify() ? 1 : 0);
		}
		if (addressPaddingOption.padWithZeros() != padCheckBox.isSelected()) {
			padCheckBox.setSelected(addressPaddingOption.padWithZeros());
		}
		if (!Integer.toString(addressPaddingOption.getMinimumHexDigits()).equals(
			minDigitsField.getText())) {
			minDigitsField.setValue(addressPaddingOption.getMinimumHexDigits());
		}
		boolean enabled = !padCheckBox.isSelected();
		minDigitsField.setEnabled(enabled);
	}

	private AddressFieldOptionsWrappedOption cloneAddressPadValues() {
		AddressFieldOptionsWrappedOption newOption = new AddressFieldOptionsWrappedOption();
		newOption.setPadWithZeros(padCheckBox.isSelected());
		newOption.setMinimumHexDigits(getMinNumberOfDigits());
		newOption.setShowBlockName(showBlocknameCheckbox.isSelected());
		newOption.setRightJustify(justificationCombobox.getSelectedItem().equals("Right"));
		return newOption;
	}

	@Override
	public String[] getOptionDescriptions() {
		return DESCRIPTIONS;
	}

	@Override
	public String[] getOptionNames() {
		return NAMES;
	}

	@Override
	public Object getValue() {
		return cloneAddressPadValues();
	}

	@Override
	public Component getCustomEditor() {
		return editorComponent;
	}

	@Override
	public boolean supportsCustomEditor() {
		return true;
	}
}
