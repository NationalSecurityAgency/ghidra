/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.program.model.address.Address;
import ghidra.util.Saveable;
import ghidra.util.prop.SaveableObjectPropertySet;

/**
 * Property manager that deals with properties that are of
 * Object type. The Object type must implement the Saveable interface.
 */
public class DefaultObjectPropertyMap extends DefaultPropertyMap implements ObjectPropertyMap {
	
    private SaveableObjectPropertySet propSet;

	/**
	 * Construct a new ObjectPropertyMap
	 * @param name of property
	 * @param objectClass class of objects to be stored in this map
	 */
	public DefaultObjectPropertyMap(String name, Class<?> objectClass) {
		super(new SaveableObjectPropertySet(name, objectClass));
		propSet = (SaveableObjectPropertySet)propertyMgr;
	}
	
	/**
	 * Add an object value at the specified address.
	 * @param addr address for the property
	 * @param value value of the property
	 * @exception TypeMismatchException thrown if the
	 *   property does not have Saveable object values.
	 */
	public void add(Address addr, Saveable value) {
		propSet.putObject(addrMap.getKey(addr), value);
	}
		
	/**
	 * Get the object value at the given address.
	 * @param addr the address from where to get the int value
	 * @return Saveable object or null if property not found at addr.
	 */
	public Object getObject(Address addr) {
		return propSet.getObject(addrMap.getKey(addr));
	}

	/**
	 * @see ghidra.program.model.util.ObjectPropertyMap#getObjectClass()
	 */
	public Class<?> getObjectClass() {
		return propSet.getObjectClass();
	}

}
