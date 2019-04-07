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
import ghidra.util.exception.NoValueException;
import ghidra.util.prop.IntPropertySet;

/**
 * Property manager that deals with properties that are of
 * int type.
 */
public class DefaultIntPropertyMap extends DefaultPropertyMap implements IntPropertyMap {
	
    private final static long serialVersionUID = 1;
    private IntPropertySet ips;

 	/**
	 * Construct a new IntPropertyMap
	 * @param name name of property
	 */
	public DefaultIntPropertyMap(String name) {
		super(new IntPropertySet(name));
		ips = (IntPropertySet)propertyMgr;
	}
	
	/**
	 * Add an int value at the specified address.
	 * @param addr address for the property
	 * @param value value of the property
	 */
	public void add(Address addr, int value) {
		ips.putInt(addrMap.getKey(addr), value);
	}
		
	/**
	 * Get the integer value at the given address.
	 * @param addr the address from where to get the int value
	 * @throws NoValueException if there is no property value at addr.
	 */
	public int getInt(Address addr) throws NoValueException {
		return ips.getInt(addrMap.getKey(addr));
	}
	
	/**
	 * @see ghidra.program.model.util.PropertyMap#getObject(ghidra.program.model.address.Address)
	 */
	public Object getObject(Address addr) {
		try {
			return new Integer(getInt(addr));
		}
		catch (NoValueException e) {
			return null;
		}
	}

}
