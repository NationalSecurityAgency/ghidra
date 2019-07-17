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
import ghidra.util.prop.LongPropertySet;

/**
 * Property manager that deals with properties that are of
 *  long type.
 */ 
public class DefaultLongPropertyMap extends DefaultPropertyMap implements LongPropertyMap {
	
    private final static long serialVersionUID = 1;
    private LongPropertySet lps;


	/**
	 * Construct a new LongPropertyMap
	 * @param name name of property
	 */
	public DefaultLongPropertyMap(String name) {
		super(new LongPropertySet(name));
		lps = (LongPropertySet)propertyMgr;
	}
	
	/**
	 * Add a long value at the specified address.
	 * @param addr address for the property
	 * @param value value of the property
	 * @exception TypeMismatchException thrown if the
	 *   property does not have long values.
	 */
	public void add(Address addr, long value) {
		lps.putLong(addrMap.getKey(addr), value);
	}
		
	/**
	 * Get the long value at the given address.
	 * @param addr the address from where to get the long value
	 * @throws NoValueException if there is no property value at addr.
	 */
	public long getLong(Address addr) throws NoValueException {
		return lps.getLong(addrMap.getKey(addr));
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#getObject(ghidra.program.model.address.Address)
	 */
	public Object getObject(Address addr) {
		try {
			return new Long(getLong(addr));
		}
		catch (NoValueException e) {
			return null;
		}
	}
}
