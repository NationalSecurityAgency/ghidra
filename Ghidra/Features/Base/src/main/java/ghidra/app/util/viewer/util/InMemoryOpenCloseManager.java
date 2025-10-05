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
public class InMemoryOpenCloseManager implements OpenCloseManager {
	private boolean openByDefault = true;
	private Set<Address> addresses = new HashSet<>();

	@Override
	public boolean isOpen(Address address) {
		boolean contains = addresses.contains(address);
		return openByDefault ? !contains : contains;
	}

	@Override
	public void open(Address address) {
		if (openByDefault) {
			addresses.remove(address);
		}
		else {
			addresses.add(address);
		}
	}

	@Override
	public void close(Address address) {
		if (openByDefault) {
			addresses.add(address);
		}
		else {
			addresses.remove(address);
		}
	}

	@Override
	public boolean isOpenByDefault() {
		return openByDefault;
	}

	@Override
	public void openAll() {
		openByDefault = true;
		addresses.clear();
	}

	@Override
	public void closeAll() {
		openByDefault = false;
		addresses.clear();
	}
}
