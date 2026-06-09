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
package ghidra.app.util.importer.options;

import java.awt.Component;

import docking.widgets.textfield.IntegerTextField;
import ghidra.app.util.*;
import ghidra.framework.options.SaveState;
import ghidra.program.model.address.AddressFactory;

/**
 * An {@link Option} used to specify an {@link Integer}
 */
public class IntegerOption extends AbstractOption<Integer> {

	/**
	 * Creates a new {@link IntegerOption}
	 * 
	* @param name the name of the option
	* @param value the value of the option
	* @param arg the option's command line argument
	* @param group the name for group of options
	* @param stateKey the state key name
	* @param hidden true if this option should be hidden from the user; otherwise, false
	* @param description a description of the option
	 */
	public IntegerOption(String name, int value, String arg, String group, String stateKey,
			boolean hidden, String description) {
		super(name, Integer.class, value, arg, group, stateKey, hidden, description);
	}

	@Override
	public boolean parseAndSetValueByType(String str, AddressFactory addressFactory) {
		try {
			setValue(Integer.decode(str));
			return true;
		}
		catch (NumberFormatException e) {
			return false;
		}
	}

	@Override
	public Component getCustomEditorComponent(AddressFactoryService addressFactoryService) {
		final SaveState state = getState();
		int defaultValue = getValue();
		int initialState = state != null ? state.getInt(getName(), defaultValue) : defaultValue;
		setValue(initialState);
		IntegerTextField field = new IntegerTextField();
		field.setValue(initialState);
		field.getComponent().setToolTipText(getDescription());
		field.addChangeListener(e -> {
			setValue(field.getIntValue());
			if (state != null) {
				state.putInt(getName(), field.getIntValue());
			}
		});
		return field.getComponent();
	}

	@Override
	public IntegerOption copy() {
		return new IntegerOption(getName(), getValue(), getArg(), getGroup(), getStateKey(),
			isHidden(), getDescription());
	}

	/**
	 * Builds a {@link IntegerOption}
	 */
	public static class Builder extends AbstractOptionBuilder<Integer, IntegerOption> {

		/**
		 * Creates a new {@link Builder}
		 * 
		 * @param name The name of the {@link IntegerOption} to be built
		 */
		public Builder(String name) {
			super(name);
		}

		@Override
		public IntegerOption build() {
			return new IntegerOption(name, value, commandLineArgument, group, stateKey, hidden,
				description);
		}
	}
}
