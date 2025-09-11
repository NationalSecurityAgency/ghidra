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
package ghidra.app.util.viewer.util;

import java.util.HashSet;
import java.util.Set;

import ghidra.program.model.address.Address;

/**
 * Class to maintain a simple open close/state for address locations. The default open/close
 * state can be set and then a set of address is kept for the locations that are the opposite
 * of the default.
 */
public class AddressBasedOpenCloseManager {
	private boolean openByDefault = true;
	private Set<Address> addresses = new HashSet<>();

	/**
	 * Checks if the state is "open" for the given address.
	 * @param address the address to test
	 * @return true if the state of the given address is "open"
	 */
	public boolean isOpen(Address address) {
		boolean contains = addresses.contains(address);
		return openByDefault ? !contains : contains;
	}

	/**
	 * Sets the state at the given address to be "open".
	 * @param address the address to set "open"
	 */
	public void open(Address address) {
		if (openByDefault) {
			addresses.remove(address);
		}
		else {
			addresses.add(address);
		}
	}

	/**
	 * Sets the state at the given address to be "closed".
	 * @param address the address to set "closed"
	 */
	public void close(Address address) {
		if (openByDefault) {
			addresses.add(address);
		}
		else {
			addresses.remove(address);
		}
	}

	/**
	 * Checks if the default state is "open".
	 * @return true if the default state for addresses is "open"
	 */
	public boolean isOpenByDefault() {
		return openByDefault;
	}

	/**
	 * Sets all address to "open" (Makes "open" the default state and clears all individual
	 * settings.
	 */
	public void openAll() {
		openByDefault = true;
		addresses.clear();
	}

	/**
	 * Sets all address to "closed" (Makes "closed" the default state and clears all individual
	 * settings.
	 */
	public void closeAll() {
		openByDefault = false;
		addresses.clear();
	}
}
