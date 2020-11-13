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

import ghidra.program.model.address.*;

/**
 * Defines methods to mark ranges in a property map. 
 *
 */
public interface AddressSetPropertyMap {

	/**
	 * Add the address range to the property map.
	 * @param start start of the range
	 * @param end end of the range
	 */
	void add(Address start, Address end);

	/**
	 * Add the address set to the property map.
	 * @param addressSet address set to add
	 */
	void add(AddressSetView addressSet);

	/**
	 * Clear the property map and set it with the given address set. 
	 * @param addressSet address set to use
	 */
	void set(AddressSetView addressSet);

	/**
	 * Remove the address range from the property map.
	 * @param start start of the range
	 * @param end end of the range
	 */
	void remove(Address start, Address end);

	/**
	 * Remove the address set from the property map.
	 * @param addressSet address set to remove
	 */
	void remove(AddressSetView addressSet);

	/**
	 * Return the address set for the property map.
	 */
	AddressSet getAddressSet();

	/**
	 * Return an address iterator over the property map. 
	 */
	AddressIterator getAddresses();

	/**
	 * Return an address range iterator over the property map.
	 */
	AddressRangeIterator getAddressRanges();

	/**
	 * Clear the property map.
	 *
	 */
	void clear();

	/**
	 * Return whether the property map contains the given address.
	 * @param addr address to check
	 */
	boolean contains(Address addr);

}
