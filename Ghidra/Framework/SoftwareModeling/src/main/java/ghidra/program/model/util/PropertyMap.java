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
import ghidra.util.datastruct.NoSuchIndexException;
import ghidra.util.prop.PropertyVisitor;

/**
 * Interface to define a map containing properties over a set of addresses.
 */
public interface PropertyMap {
	/**
	 * Get the name for this property map.
	 */
	public String getName();
	/**
	 * Given two addresses, indicate whether there is an address in
	 * that range (inclusive) having the property.<p>
	 * @param start the start of the range.
	 * @param end the end of the range.
	 *
	 * @return boolean true if at least one address in the range
	 * has the property, false otherwise.
	 */
	public boolean intersects(Address start, Address end);
	
	/**
	 * Indicate whether there is an address within
	 * the set which exists within this map.<p>
	 * @param set set of addresses
	 *
	 * @return boolean true if at least one address in the set
	 * has the property, false otherwise.
	 */
	public boolean intersects(AddressSetView set);
	
	/**
	 * Removes all property values within a given range.
	 * @param start begin range
	 * @param end end range, inclusive
	 * @return true if any property value was removed; return
	 * 		false otherwise.
	 */
	public boolean removeRange(Address start, Address end);
	/**
	 * Remove the property value at the given address.
	 * @return true if the property value was removed, false
	 *   otherwise.
	 * @param addr the address where the property should be removed
	 */
	public boolean remove(Address addr);
	/**
	 * returns whether there is a property value at addr.
	 * @param addr the address in question
	 */
	public boolean hasProperty(Address addr);
	
	/**
	 * Returns the property value stored at the specified 
	 * address or null if no property found.
	 * @param addr property address
	 * @return property value
	 */
	public Object getObject(Address addr);
	
	/**
	 * Get the next address where the property value exists.
	 * @param addr the address from which to begin the search (exclusive).
	 */
	public Address getNextPropertyAddress(Address addr);
	/**
	 * Get the previous Address where a property value exists.
	 * @param addr the address from which
	 * 		to begin the search (exclusive).
	 */
	public Address getPreviousPropertyAddress(Address addr);
	/**
	 * Get the first Address where a property value exists.
	 */
	public Address getFirstPropertyAddress();
	/**
	 * Get the last Address where a property value exists.
	 */
	public Address getLastPropertyAddress();
	/**
	 * Get the number of properties in the map.
	 */
	public int getSize();
	/**
	 * Returns an iterator over the indices having a property
	 * value.
	 * @exception TypeMismatchException thrown if the property does not
	 * have values of type <CODE>Object</CODE>.
	 */
	public AddressIterator getPropertyIterator(
		Address start,
		Address end);
	/**
	 * Returns an iterator over addresses that have a property
	 * value.
	 * @param forward if true will iterate in increasing address order, otherwise it will start at
	 * the end and iterate in decreasing address order
	 * @exception TypeMismatchException thrown if the property does not
	 * have values of type <CODE>Object</CODE>.
	 */
	public AddressIterator getPropertyIterator(
		Address start,
		Address end,
		boolean forward);
	/**
	 * Returns an iterator over the addresses that a property
	 * value.
	 * @exception TypeMismatchException thrown if the property does not
	 * have values of type <CODE>Object</CODE>.
	 */
	public AddressIterator getPropertyIterator();

	/**
	 * Returns an iterator over the addresses that have a property value and
	 * are in the given address set.
	 * @param asv the set of addresses to iterate over.
	 */
	public AddressIterator getPropertyIterator(AddressSetView asv); 

	/**
	 * Returns an iterator over the addresses that have a property value and
	 * are in the given address set.
	 * @param forward if true will iterate in increasing address order, otherwise it will start at
	 * the end and iterate in decreasing address order
	 */
	public AddressIterator getPropertyIterator(AddressSetView asv, boolean forward);
	
	/**
	 * Returns an iterator over the address having a property
	 * value.
	 * @param start the starting address
	 * @param forward if true will iterate in increasing address order, otherwise it will start at
	 * the end and iterate in decreasing address order
	 * @exception TypeMismatchException thrown if the property does not
	 * have values of type <CODE>Object</CODE>.
	 */
	public AddressIterator getPropertyIterator(Address start, boolean forward);
	
	/**
	 * Applies a property value at the indicated address without knowing its 
	 * type (String, int, long, etc.) by using the property visitor.
	 * @param visitor the property visitor that lets you apply the property
	 * without knowing its specific type ahead of time.
	 * @param addr the address where the property is to be applied.
	 */
	public void applyValue(PropertyVisitor visitor, Address addr);
	
	/**
	 * Moves the properties defined in the range from the start address thru the 
	 * end address to now be located beginning at the newStart address. 
	 * The moved properties will be located at the same relative location to 
	 * the newStart address as they were previously to the start address.
	 * @param start the start of the range to move.
	 * @param end the end of the range to move.
	 * @param newStart the new start location of the range of properties 
	 * after the move.
	 */
	public void moveRange(Address start, Address end, Address newStart);

}
