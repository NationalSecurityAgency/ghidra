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

import javax.swing.JComboBox;

import docking.widgets.combobox.GComboBox;
import ghidra.app.util.*;
import ghidra.app.util.opinion.Loader;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;

/**
 * An {@link Option} used to specify an {@link AddressSpace}
 */
public class AddressSpaceOption extends AbstractOption<AddressSpace> {

	/**
	 * Creates a new {@link AddressSpaceOption}
	 * 
	* @param name the name of the option
	* @param value the value of the option
	* @param arg the option's command line argument
	* @param group the name for group of options
	* @param stateKey the state key name
	* @param hidden true if this option should be hidden from the user; otherwise, false
	* @param description a description of the option
	 */
	public AddressSpaceOption(String name, AddressSpace value, String arg, String group,
			String stateKey, boolean hidden, String description) {
		super(name, AddressSpace.class, value, arg, group,
			Loader.OPTIONS_PROJECT_SAVE_STATE_KEY, hidden, description);
	}

	@Override
	public boolean parseAndSetValueByType(String str, AddressFactory addressFactory) {
		// Implementation has not yet been needed
		return false;
	}

	@Override
	public Component getCustomEditorComponent(AddressFactoryService addressFactoryService) {
		if (addressFactoryService == null) {
			return null;
		}
		JComboBox<AddressSpace> combo = new GComboBox<>();
		AddressFactory addressFactory = addressFactoryService.getAddressFactory();
		AddressSpace[] spaces =
			addressFactory == null ? new AddressSpace[0] : addressFactory.getAddressSpaces();
		for (AddressSpace space : spaces) {
			combo.addItem(space);
		}
		AddressSpace space = getValue();
		if (space != null) {
			combo.setSelectedItem(space);
		}
		combo.addActionListener(e -> {
			// called whenever the combobox changes to push the value back to the Option that is
			// our 'model'
			setValue(combo.getSelectedItem());
		});
		combo.setToolTipText(getDescription());
		return combo;
	}

	@Override
	public AddressSpaceOption copy() {
		return new AddressSpaceOption(getName(), getValue(), getArg(), getGroup(),
			getStateKey(), isHidden(), getDescription());
	}

	/**
	 * Builds an {@link AddressSpaceOption}
	 */
	public static class Builder extends AbstractOptionBuilder<AddressSpace, AddressSpaceOption> {

		/**
		 * Creates a new {@link Builder}
		 * 
		 * @param name The name of the {@link AddressSpaceOption} to be built
		 */
		public Builder(String name) {
			super(name);
		}

		@Override
		public AddressSpaceOption build() {
			return new AddressSpaceOption(name, value, commandLineArgument, group, stateKey, hidden,
				description);
		}
	}
}
