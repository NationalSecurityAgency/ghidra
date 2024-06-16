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
import javax.swing.JTextField;

/**
 * Value class for {@link String} values. 
 * <P>
 * This class and other subclasses of {@link AbstractValue} are part of a subsystem for easily
 * defining a set of values that can be displayed in an input dialog ({@link ValuesMapDialog}).
 * Typically, these values are created indirectly using a {@link GValuesMap} which is then
 * given to the constructor of the dialog. However, an alternate approach is to create the
 * dialog without a ValuesMap and then use its {@link ValuesMapDialog#addValue(AbstractValue)} 
 * method directly.
 */
public class StringValue extends AbstractValue<String> {
	private JTextField textField;

	public StringValue(String name) {
		this(name, null);
	}

	public StringValue(String name, String defaultValue) {
		super(name, defaultValue);
	}

	@Override
	public JComponent getComponent() {
		if (textField == null) {
			textField = new JTextField(20);
		}
		return textField;
	}

	@Override
	protected void updateValueFromComponent() {
		String text = textField.getText();

		// special case where user didn't enter a value on a string field that was defined without
		// a value
		if (getValue() == null && text.equals("")) {
			return;
		}
		setValue(text);
	}

	@Override
	protected void updateComponentFromValue() {
		textField.setText(getValue());
	}

	@Override
	public String fromString(String valueString) {

		return valueString;
	}
}
