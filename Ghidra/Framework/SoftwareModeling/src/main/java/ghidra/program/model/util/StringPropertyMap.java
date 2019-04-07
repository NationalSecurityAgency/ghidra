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

/**
 * Property manager that deals with properties that are of
 * String type.
 */
public interface StringPropertyMap extends PropertyMap {
	
	/**
	 * Add a String value at the specified address.
	 * @param addr address for the property
	 * @param value value of the property
	 * @exception TypeMismatchException thrown if the
	 *   property does not have String values.
	 */
	public void add(Address addr, String value);
		
	/**
	 * Get the String value at the given address.
	 * @param addr the address from where to get the String value
	 * @return String or null if property not found at addr.
	 */
	public String getString(Address addr);

}
