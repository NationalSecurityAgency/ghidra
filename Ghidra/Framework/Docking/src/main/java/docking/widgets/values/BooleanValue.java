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

import javax.swing.JCheckBox;
import javax.swing.JComponent;

/**
 * Value class for {@link Boolean} types. Boolean types use a {@link JCheckBox} for displaying and
 * modifying values. Because the checkBox is always either checked or unchecked, 
 * BooleanValues don't support the concept of having no value.
 * <P>
 * This class and other subclasses of {@link AbstractValue} are part of a subsystem for easily
 * defining a set of values that can be displayed in an input dialog ({@link ValuesMapDialog}).
 * Typically, these values are created indirectly using a {@link GValuesMap} which is then
 * given to the constructor of the dialog. However, an alternate approach is to create the
 * dialog without a ValuesMap and then use its {@link ValuesMapDialog#addValue(AbstractValue)} 
 * method directly. */
public class BooleanValue extends AbstractValue<Boolean> {

	private JCheckBox checkBox;

	BooleanValue(String name, boolean defaultValue) {
		super(name, defaultValue);
	}

	@Override
	public JComponent getComponent() {
		if (checkBox == null) {
			checkBox = new JCheckBox();
		}
		return checkBox;
	}

	@Override
	protected void updateValueFromComponent() {
		setValue(checkBox.isSelected());
	}

	@Override
	protected void updateComponentFromValue() {
		checkBox.setSelected(getValue());
	}

	@Override
	protected Boolean fromString(String valueString) {
		return Boolean.parseBoolean(valueString);
	}

}
