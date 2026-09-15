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
package ghidra.app.plugin.core.debug.gui.emulation;

import javax.swing.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;

public abstract class AddressInputVerifier extends InputVerifier {
	private AddressFactory factory;

	public AddressInputVerifier(AddressFactory factory) {
		this.factory = factory;
	}

	@Override
	public boolean verify(JComponent input) {
		if (!(input instanceof JTextField text)) {
			throw new IllegalArgumentException(
				"Only JTextField is supported. Got %s".formatted(input.getClass()));
		}
		String str = text.getText();
		try {
			Address address = factory.getAddress(str);
			if (address == null) {
				reject("Invalid address: %s".formatted(str));
				return false;
			}
			if (!verifyAddress(address)) {
				reject("Invalid address: %s".formatted(str));
				return false;
			}
			return true;
		}
		catch (Exception e) {
			reject("%s while parsing '%s'".formatted(e.getMessage(), str));
			return false;
		}
	}

	protected abstract boolean verifyAddress(Address address);

	protected abstract void reject(String message);
}
