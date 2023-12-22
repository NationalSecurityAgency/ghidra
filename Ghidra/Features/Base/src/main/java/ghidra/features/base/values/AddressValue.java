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
package ghidra.features.base.values;

import javax.swing.JComponent;

import docking.widgets.values.*;
import ghidra.app.util.AddressInput;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;

/**
 * Value class for {@link Address} types. In order to parse and create Address types, an 
 * {@link AddressFactory} is required when defining this type. As a convenience, it can
 * be constructed with a {@link Program}, in which case it will use the AddressFactory from 
 * that program.
 * <P>
 * This class and other subclasses of {@link AbstractValue} are part of a subsystem for easily
 * defining a set of values that can be displayed in an input dialog ({@link ValuesMapDialog}).
 * Typically, these values are created indirectly using a {@link GValuesMap} which is then
 * given to the constructor of the dialog. However, an alternate approach is to create the
 * dialog without a ValuesMap and then use its {@link ValuesMapDialog#addValue(AbstractValue)} 
 * method directly.
 */
public class AddressValue extends AbstractValue<Address> {

	private AddressInput field;
	private AddressFactory addressFactory;

	/**
	 * Creates an AddressValue with an optional default value and uses the {@link AddressFactory} 
	 * from the given program.
	 * @param name the name of this value
	 * @param defaultValue an optional default value
	 * @param program the program whose AddressFactory will be used to create Addresses.
	 */
	public AddressValue(String name, Address defaultValue, Program program) {
		this(name, defaultValue, program.getAddressFactory());
	}

	/**
	 * Creates an AddressValue with an optional default value.
	 * @param name the name of this value
	 * @param defaultValue an optional default value
	 * @param factory the AddressFactory that will be used to create Addresses.
	 */
	public AddressValue(String name, Address defaultValue, AddressFactory factory) {
		super(name, defaultValue);
		this.addressFactory = factory;
	}

	@Override
	public JComponent getComponent() {
		if (field == null) {
			field = new AddressInput();
			field.setAddressFactory(addressFactory);
		}
		return field;
	}

	@Override
	protected void updateValueFromComponent() throws ValuesMapParseException {
		Address address = field.getAddress();
		if (address == null && field.hasInput()) {
			throw new ValuesMapParseException(getName(), "Address",
				"Could not parse \"" + field.getText() + "\".");
		}
		setValue(address);
	}

	@Override
	protected void updateComponentFromValue() {
		Address v = getValue();
		if (v == null) {
			field.clear();
		}
		else {
			field.setAddress(v);
		}
	}

	@Override
	protected Address fromString(String valueString) {
		Address address = addressFactory.getAddress(valueString);
		if (address == null) {
			throw new IllegalArgumentException("Invalid address string: " + valueString);
		}
		return address;
	}
}
