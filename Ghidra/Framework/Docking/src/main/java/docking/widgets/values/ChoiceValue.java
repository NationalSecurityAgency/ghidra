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

import docking.widgets.combobox.GComboBox;

/**
 * Value class for selecting from a restricted set of {@link String}s. ChoiceValues uses a 
 * {@link GComboBox} for the editor component.
 * <P>
 * This class and other subclasses of {@link AbstractValue} are part of a subsystem for easily
 * defining a set of values that can be displayed in an input dialog ({@link ValuesMapDialog}).
 * Typically, these values are created indirectly using a {@link GValuesMap} which is then
 * given to the constructor of the dialog. However, an alternate approach is to create the
 * dialog without a ValuesMap and then use its {@link ValuesMapDialog#addValue(AbstractValue)} 
 * method directly. */
public class ChoiceValue extends AbstractValue<String> {

	private String[] choices;
	private GComboBox<String> combo;

	ChoiceValue(String name, String defaultValue, String... choices) {
		super(name, defaultValue);
		this.choices = choices;
		if (defaultValue != null && !isValidChoice(defaultValue)) {
			throw new IllegalArgumentException("Default value is not one of the valid choices!");
		}
	}

	@Override
	public JComponent getComponent() {
		if (combo == null) {
			combo = new GComboBox<String>(choices);
		}
		return combo;
	}

	@Override
	protected void updateValueFromComponent() {
		setValue((String) combo.getSelectedItem());
	}

	@Override
	protected void updateComponentFromValue() {
		combo.setSelectedItem(getValue());
	}

	@Override
	protected String fromString(String valueString) {
		if (valueString == null) {
			return null;
		}
		if (isValidChoice(valueString)) {
			return valueString;
		}
		throw new IllegalArgumentException(valueString + " is not a valid choice!");
	}

	private boolean isValidChoice(String valueString) {
		for (String choice : choices) {
			if (choice.equals(valueString)) {
				return true;
			}
		}
		return false;
	}
}
