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
package docking.widgets.values;

import javax.swing.JComponent;

import docking.widgets.textfield.IntegerTextField;

/**
 * Value class for {@link Integer} Value with an option for display the value as decimal or hex. The 
 * editor component uses an {@link IntegerTextField} for display and editing the value. This
 * value supports the concept of no value which is represented by the text field being empty. If
 * the text field is not empty, then the field only allows valid numeric values.
 * <P>
 * This class and other subclasses of {@link AbstractValue} are part of a subsystem for easily
 * defining a set of values that can be displayed in an input dialog ({@link ValuesMapDialog}).
 * Typically, these values are created indirectly using a {@link GValuesMap} which is then
 * given to the constructor of the dialog. However, an alternate approach is to create the
 * dialog without a ValuesMap and then use its {@link ValuesMapDialog#addValue(AbstractValue)} 
 * method directly.
 */
public class IntValue extends AbstractValue<Integer> {
	private boolean displayAsHex;
	private IntegerTextField field;

	/**
	 * Constructs an IntValue that displays it value in decimal
	 * @param name the name of the value
	 */
	public IntValue(String name) {
		this(name, null, false);
	}

	/**
	 * Constructs an IntValue with a default value that displays it value in decimal
	 * @param name the name of the value
	 * @param defaultValue the default value
	 */
	public IntValue(String name, int defaultValue) {
		this(name, defaultValue, false);
	}

	/**
	 * Constructs an IntValue with a default value.
	 * @param name the name of the value
	 * @param defaultValue the default value
	 * @param displayAsHex if true, the value will be displayed as hex, otherwise it will display
	 * as decimal.
	 */
	public IntValue(String name, Integer defaultValue, boolean displayAsHex) {
		super(name, defaultValue);
		this.displayAsHex = displayAsHex;
	}

	@Override
	public JComponent getComponent() {
		if (field == null) {
			field = new IntegerTextField(20);
			field.setAllowsHexPrefix(false);
			field.setShowNumberMode(false);
			if (displayAsHex) {
				field.setHexMode();
				field.setShowNumberMode(true);
			}
		}
		return field.getComponent();
	}

	@Override
	protected void updateValueFromComponent() {
		String text = field.getText();

		// special case where user didn't enter a value on a string field that was defined without
		// a value
		if (getValue() == null && text.equals("")) {
			return;
		}
		setValue(field.getIntValue());
	}

	@Override
	protected void updateComponentFromValue() {
		Integer value = getValue();
		if (value == null) {
			field.setText("");
			return;
		}
		field.setValue(value);
	}

	@Override
	public Integer fromString(String valueString) {
		return displayAsHex ? Integer.parseInt(valueString, 16) : Integer.parseInt(valueString, 10);
	}

	@Override
	public String toString(Integer v) {
		return displayAsHex ? Integer.toHexString(v) : v.toString();
	}

}
