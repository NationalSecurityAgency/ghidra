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
package ghidra.program.database.data;

import java.util.LinkedHashMap;

import ghidra.program.model.address.Address;
import ghidra.util.datastruct.FixedSizeHashMap;

class SettingsCache {
	private static final int CACHE_SIZE = 200;

	class AddressNamePair {
		Address address;
		String name;

		AddressNamePair(Address address, String name) {
			this.address = address;
			this.name = name;
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof AddressNamePair)) {
				return false;
			}
			AddressNamePair other = (AddressNamePair) obj;
			return other.address.equals(address) && other.name.equals(name);
		}

		@Override
		public int hashCode() {
			return address.hashCode() + name.hashCode();
		}
	}

	private LinkedHashMap<AddressNamePair, InstanceSettingsDB> map;

	SettingsCache() {
		map = new FixedSizeHashMap<>(CACHE_SIZE, CACHE_SIZE);
	}

	public void remove(Address address, String name) {
		AddressNamePair key = new AddressNamePair(address, name);
		map.remove(key);
	}

	void clear() {
		map.clear();
	}

	InstanceSettingsDB getInstanceSettings(Address address, String name) {
		AddressNamePair key = new AddressNamePair(address, name);
		return map.get(key);
	}

	void put(Address address, String name, InstanceSettingsDB settings) {
		AddressNamePair key = new AddressNamePair(address, name);
		map.put(key, settings);
	}
}
