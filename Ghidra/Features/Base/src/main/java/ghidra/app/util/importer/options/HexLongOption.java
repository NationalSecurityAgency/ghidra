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
import ghidra.util.NumericUtilities;

/**
 * An {@link Option} used to specify a {@link HexLong}
 */
public class HexLongOption extends AbstractOption<HexLong> {

	/**
	 * Creates a new {@link HexLongOption}
	 * 
	* @param name the name of the option
	* @param value the value of the option
	* @param arg the option's command line argument
	* @param group the name for group of options
	* @param stateKey the state key name
	* @param hidden true if this option should be hidden from the user; otherwise, false
	* @param description a description of the option
	 */
	public HexLongOption(String name, HexLong value, String arg, String group, String stateKey,
			boolean hidden, String description) {
		super(name, HexLong.class, value, arg, group, stateKey, hidden, description);
	}

	@Override
	public boolean parseAndSetValueByType(String str, AddressFactory addressFactory) {
		try {
			setValue(new HexLong(NumericUtilities.parseHexLong(str)));
			return true;
		}
		catch (NumberFormatException e) {
			return false;
		}
	}

	@Override
	public Component getCustomEditorComponent(AddressFactoryService addressFactoryService) {
		final SaveState state = getState();
		HexLong defaultValue = getValue();
		long initialState = state != null ? state.getLong(getName(), defaultValue.longValue())
				: defaultValue.longValue();
		setValue(new HexLong(initialState));
		IntegerTextField field = new IntegerTextField();
		field.setValue(initialState);
		field.setHexMode();
		field.getComponent().setToolTipText(getDescription());
		field.addChangeListener(e -> {
			setValue(new HexLong(field.getLongValue()));
			if (state != null) {
				state.putLong(getName(), field.getLongValue());
			}
		});
		return field.getComponent();
	}

	@Override
	public HexLongOption copy() {
		return new HexLongOption(getName(), getValue(), getArg(), getGroup(), getStateKey(),
			isHidden(), getDescription());
	}

	/**
	* Builds a {@link HexLongOption}
	*/
	public static class Builder extends AbstractOptionBuilder<HexLong, HexLongOption> {

		/**
		 * Creates a new {@link Builder}
		 * 
		 * @param name The name of the {@link HexLongOption} to be built
		 */
		public Builder(String name) {
			super(name);
		}

		@Override
		public HexLongOption build() {
			return new HexLongOption(name, value, commandLineArgument, group, stateKey, hidden,
				description);
		}
	}
}
