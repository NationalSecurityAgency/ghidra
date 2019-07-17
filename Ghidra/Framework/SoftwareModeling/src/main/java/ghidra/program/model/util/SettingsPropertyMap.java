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
package ghidra.program.model.util;

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;

/**
 * Property map interface for storing Settings objects.
 */
public interface SettingsPropertyMap extends PropertyMap {
	/**
	 * Add an Settings object value at the specified address.
	 * @param addr address for the property
	 * @param value value of the property
	 */
	public void add(Address addr, Settings value);
		
	/**
	 * Get the Settings object value at the given address.
	 * @param addr the address from where to get the int value
	 * @return Settings object or null if property not found at addr.
	 */
	public Settings getSettings(Address addr);

}
