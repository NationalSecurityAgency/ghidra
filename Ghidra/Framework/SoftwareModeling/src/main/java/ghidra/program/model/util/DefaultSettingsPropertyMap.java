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
import ghidra.util.prop.ObjectPropertySet;

/**
 * Property manager that deals with properties that are of
 * Settings type. 
 */
public class DefaultSettingsPropertyMap extends DefaultPropertyMap implements SettingsPropertyMap {
	
    private ObjectPropertySet propSet;

	/**
	 * Construct a new DefaultSettingsPropertyMap
	 * @param name of property
	 */
	public DefaultSettingsPropertyMap(String name) {
		super(new ObjectPropertySet(name));
		propSet = (ObjectPropertySet)propertyMgr;
	}
	
	/**
	 * Add an object value at the specified address.
	 * @param addr address for the property
	 * @param value value of the property
	 * @exception TypeMismatchException thrown if the
	 *   property does not have Settings object values.
	 */
	public void add(Address addr, Settings value) {
		propSet.putObject(addrMap.getKey(addr), value);
	}
		
	/**
	 * Get the Settings object value at the given address.
	 * @param addr the address from where to get the int value
	 * @return Settings object or null if property not found at addr.
	 */
	public Settings getSettings(Address addr) {
		return (Settings)propSet.getObject(addrMap.getKey(addr));
	}
	
	/**
	 * @see ghidra.program.model.util.PropertyMap#getObject(ghidra.program.model.address.Address)
	 */
	public Object getObject(Address addr) {
		return getSettings(addr);
	}

}
