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
import java.util.Objects;

import ghidra.util.datastruct.FixedSizeHashMap;

class SettingsCache<K> {

	private static class IdNamePair {
		Object id; // object which corresponds to association ID (e.g., Address, DataType-ID) 
		String name;

		IdNamePair(Object id, String name) {
			this.id = id;
			this.name = name;
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof IdNamePair)) {
				return false;
			}
			IdNamePair other = (IdNamePair) obj;
			return other.id.equals(id) && other.name.equals(name);
		}

		@Override
		public int hashCode() {
			return Objects.hash(id, name);
		}
	}

	private LinkedHashMap<IdNamePair, SettingDB> map;

	/**
	 * Construct settings cache of a specified size
	 * @param size cache size (maximum number of entries held)
	 */
	SettingsCache(int size) {
		map = new FixedSizeHashMap<>(size, size);
	}

	/**
	 * Remove specific setting record from cache
	 * @param id association ID object (e.g., Address, DataType ID)
	 * @param name name of setting
	 */
	public void remove(K id, String name) {
		IdNamePair key = new IdNamePair(id, name);
		map.remove(key);
	}

	/**
	 * Clear all cached entries
	 */
	void clear() {
		map.clear();
	}

	/**
	 * Get a cached setting record
	 * @param id association ID object (e.g., Address, DataType ID)
	 * @param name name of setting
	 * @return cached setting or null if not found
	 */
	SettingDB get(K id, String name) {
		IdNamePair key = new IdNamePair(id, name);
		return map.get(key);
	}

	/**
	 * Add setting record to cache
	 * @param id association ID object (e.g., Address, DataType ID)
	 * @param name name of setting
	 * @param setting object
	 */
	void put(K id, String name, SettingDB setting) {
		IdNamePair key = new IdNamePair(id, name);
		map.put(key, setting);
	}
}
