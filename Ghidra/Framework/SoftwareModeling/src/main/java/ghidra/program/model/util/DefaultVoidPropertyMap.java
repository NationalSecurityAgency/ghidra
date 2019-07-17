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
import ghidra.util.prop.VoidPropertySet;

/**
 * Property manager that deals with properties that are of
 * "void" type, which is a marker for whether a property exists.
 */
public class DefaultVoidPropertyMap extends DefaultPropertyMap implements VoidPropertyMap {
	
	private VoidPropertySet propSet;
	
	/**
	 * Construct a new VoidPropertyMap
	 * @param name of property
	 */
	public DefaultVoidPropertyMap(String name) {
		super(new VoidPropertySet(name));
		propSet = (VoidPropertySet)propertyMgr;
	}
	
	/**
	 * Mark the specified address as having a property
	 * @param addr address for the property
	 */
	public void add(Address addr) {
		propSet.put(addrMap.getKey(addr));
	}
	
	/**
	 * @see ghidra.program.model.util.PropertyMap#getObject(ghidra.program.model.address.Address)
	 */
	public Object getObject(Address addr) {
		if (hasProperty(addr)) {
			return Boolean.TRUE;
		}
		return null;
	}
}
