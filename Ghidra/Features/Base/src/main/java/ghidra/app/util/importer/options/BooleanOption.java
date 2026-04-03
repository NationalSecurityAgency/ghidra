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

import org.apache.commons.lang3.BooleanUtils;

import docking.widgets.checkbox.GCheckBox;
import ghidra.app.util.*;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.options.SaveState;
import ghidra.program.model.address.AddressFactory;

/**
 * An {@link Option} used to specify a {@link Boolean}
 */
public class BooleanOption extends AbstractOption<Boolean> {

	/**
	 * Creates a new {@link BooleanOption}
	 * 
	* @param name the name of the option
	* @param value the value of the option
	* @param arg the option's command line argument
	* @param group the name for group of options
	* @param stateKey the state key name
	* @param hidden true if this option should be hidden from the user; otherwise, false
	* @param description a description of the option
	 */
	public BooleanOption(String name, boolean value, String arg, String group, String stateKey,
			boolean hidden, String description) {
		super(name, Boolean.class, value, arg, group, Loader.OPTIONS_PROJECT_SAVE_STATE_KEY,
			hidden, description);
	}

	@Override
	public boolean parseAndSetValueByType(String str, AddressFactory addressFactory) {
		try {
			setValue(BooleanUtils.toBoolean(str, "true", "false"));
			return true;
		}
		catch (IllegalArgumentException e) {
			return false;
		}
	}

	@Override
	public Component getCustomEditorComponent(AddressFactoryService addressFactoryService) {
		final SaveState state = getState();
		boolean defaultValue = getValue();
		boolean initialState =
			state != null ? state.getBoolean(getName(), defaultValue) : defaultValue;
		setValue(initialState);
		GCheckBox cb = new GCheckBox();
		cb.setName(getName());
		cb.setToolTipText(getDescription());
		cb.setSelected(initialState);
		cb.addItemListener(e -> {
			setValue(cb.isSelected());
			if (state != null) {
				state.putBoolean(getName(), cb.isSelected());
			}
		});
		return cb;
	}

	@Override
	public BooleanOption copy() {
		return new BooleanOption(getName(), getValue(), getArg(), getGroup(), getStateKey(),
			isHidden(), getDescription());
	}

	/**
	 * Builds a {@link BooleanOption}
	 */
	public static class Builder extends AbstractOptionBuilder<Boolean, BooleanOption> {

		/**
		 * Creates a new {@link Builder}
		 * 
		 * @param name The name of the {@link BooleanOption} to be built
		 */
		public Builder(String name) {
			super(name);
		}

		@Override
		public BooleanOption build() {
			return new BooleanOption(name, value, commandLineArgument, group, stateKey, hidden,
				description);
		}
	}
}
