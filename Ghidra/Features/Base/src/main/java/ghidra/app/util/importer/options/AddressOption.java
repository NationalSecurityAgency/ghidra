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

import ghidra.app.util.*;
import ghidra.app.util.opinion.Loader;
import ghidra.program.model.address.*;

/**
 * An {@link Option} used to specify an {@link Address}
 */
public class AddressOption extends AbstractOption<Address> {

	/**
	 * Creates a new {@link AddressOption}
	 * 
	* @param name the name of the option
	* @param value the value of the option
	* @param arg the option's command line argument
	* @param group the name for group of options
	* @param stateKey the state key name
	* @param hidden true if this option should be hidden from the user; otherwise, false
	* @param description a description of the option
	 */
	public AddressOption(String name, Address value, String arg, String group, String stateKey,
			boolean hidden, String description) {
		super(name, Address.class, value, arg, group, Loader.OPTIONS_PROJECT_SAVE_STATE_KEY,
			hidden, description);
	}

	@Override
	public boolean parseAndSetValueByType(String str, AddressFactory addressFactory) {
		try {
			Address origAddr = getValue();
			Address newAddr = null;
			if (origAddr != null) {
				newAddr = origAddr.getAddress(str);
			}
			else {
				if (addressFactory == null) {
					throw new RuntimeException("Attempted to use Address type option (" +
						getName() + ") without specifying Address Factory");
				}
				newAddr = addressFactory.getDefaultAddressSpace().getAddress(str);
			}
			if (newAddr == null) {
				return false;
			}
			setValue(newAddr);
		}
		catch (AddressFormatException e) {
			return false;
		}
		return true;
	}

	@Override
	public Component getCustomEditorComponent(AddressFactoryService addressFactoryService) {
		if (addressFactoryService == null) {
			return null;
		}
		AddressFactory addressFactory = addressFactoryService.getAddressFactory();
		AddressInput addressInput = new AddressInput(a -> setValue(a));
		addressInput.setName(getName());
		addressInput.setToolTipText(getDescription());
		Address addr = getValue();
		if (addr == null && addressFactory != null) {
			addr = addressFactory.getDefaultAddressSpace().getAddress(0);
			setValue(addr);
		}
		addressInput.setAddressFactory(addressFactory);
		addressInput.setAddress(addr);
		return addressInput;
	}

	@Override
	public AddressOption copy() {
		return new AddressOption(getName(), getValue(), getArg(), getGroup(), getStateKey(),
			isHidden(), getDescription());
	}

	/**
	 * Builds a {@link AddressOption}
	 */
	public static class Builder extends AbstractOptionBuilder<Address, AddressOption> {

		/**
		 * Creates a new {@link Builder}
		 * 
		 * @param name The name of the {@link AddressOption} to be built
		 */
		public Builder(String name) {
			super(name);
		}

		@Override
		public AddressOption build() {
			return new AddressOption(name, value, commandLineArgument, group, stateKey, hidden,
				description);
		}

	}
}
