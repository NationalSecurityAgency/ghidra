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
package ghidra.program.model.address;

/**
 *  This interface represents a collection of AddressSets (actually AddressSetViews). 
 *  It defines a set of methods that can efficiently be performed on a collection
 *  of one or more AddressSets.  
 */
public interface AddressSetCollection {

	/**
	 * Determine if any AddressSet in this collection intersects with the specified address set.
	 *
	 * @param addrSet address set to check intersection with.
	 */
	public boolean intersects(AddressSetView addrSet);

	/**
	 * Determine if range specified by start and end intersects with any of the AddressSets
	 * in this collection.
	 * @param start start of range
	 * @param end end of range
	 * @return true if the given range intersects this address set collection.
	 */
	public boolean intersects(Address start, Address end);

	/**
	 * Test if the address is contained within any of the addressSets in this collection.
	 * <P>
	 * @param address address to test.
	 * @return true if addr exists in the set, false otherwise.
	 */
	public boolean contains(Address address);

	/**
	 * Tests whether this collection of addressSets has approximately fewer ranges than
	 * the given threshold. This is probably estimated by adding up the number of ranges
	 * in each AddressSet in this collections. Returns true if the total is less than the 
	 * given threshold.
	 * @param rangeThreshold the number of ranges to test against.
	 * @return true if the max possible ranges is less than the given threshold.
	 */
	public boolean hasFewerRangesThan(int rangeThreshold);

	/**
	 * Returns a single AddressSet containing the union of all the addressSetViews in the collection.  
	 */
	public AddressSet getCombinedAddressSet();

	/**
	 * Finds the first address in this collection that is also in the given addressSet.
	 * @param set the addressSet to search for the first (lowest) common address.
	 * @return the first address that is contained in this set and the given set.
	 */
	public Address findFirstAddressInCommon(AddressSetView set);

	/**
	 * Returns true if all the AddressSets in this collection are empty.
	 * @return true if all the AddressSets in this collection are empty.
	 */
	public boolean isEmpty();

	/**
	 * Returns the smallest address in this collection or null if the collection is empty.
	 * @return  the smallest address in this collection or null if the collection is empty.
	 */
	public Address getMinAddress();

	/**
	 * Returns the largest address in this collection or null if the collection is empty.
	 * @return  the largest address in this collection or null if the collection is empty.
	 */
	public Address getMaxAddress();
}
