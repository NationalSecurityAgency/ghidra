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

import docking.widgets.textfield.FloatingPointTextField;

/**
 * Value class for {@link Double} types. This value uses a {@link FloatingPointTextField} as it's
 * editor component. It supports the concept of no value, if the text field is empty.
 * <P>
 * This class and other subclasses of {@link AbstractValue} are part of a subsystem for easily
 * defining a set of values that can be displayed in an input dialog ({@link ValuesMapDialog}).
 * Typically, these values are created indirectly using a {@link GValuesMap} which is then
 * given to the constructor of the dialog. However, an alternate approach is to create the
 * dialog without a ValuesMap and then use its {@link ValuesMapDialog#addValue(AbstractValue)} 
 * method directly. 
 */
public class DoubleValue extends AbstractValue<Double> {
	private FloatingPointTextField field;

	public DoubleValue(String name) {
		this(name, null);
	}

	public DoubleValue(String name, Double defaultValue) {
		super(name, defaultValue);
	}

	@Override
	public JComponent getComponent() {
		if (field == null) {
			field = new FloatingPointTextField(20);
		}
		return field;
	}

	@Override
	protected void updateValueFromComponent() {
		String text = field.getText();

		// special case where user didn't enter a value on a string field that was defined without
		// a value
		if (getValue() == null && text.equals("")) {
			return;
		}
		setValue(field.getValue());
	}

	@Override
	protected void updateComponentFromValue() {
		Double value = getValue();
		if (value == null) {
			field.setText("");
			return;
		}
		field.setValue(value);
	}

	@Override
	public Double fromString(String valueString) {
		return Double.parseDouble(valueString);
	}

}
