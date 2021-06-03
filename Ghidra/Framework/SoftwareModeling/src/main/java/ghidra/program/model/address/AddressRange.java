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

import java.math.BigInteger;

/**
 * The AddressRange interface is used by any object
 * that represents a contiguous inclusive range of
 * addresses from a minimum address to a maximum
 * address.  The entire range must fall within a 
 * single address space.
 * <P>
 * @see AddressRangeImpl
 * @since 2000-02-16
 */

public interface AddressRange extends Comparable<AddressRange>, Iterable<Address> {

	/**
	 * Returns the number of addresses in the range.
	 */
	public long getLength();

	/**
	 * Returns the number of addresses as a BigInteger.
	 * @return the number of addresses as a BigInteger.
	 */
	public BigInteger getBigLength();

	/**
	 * Returns true if the given address is contained in the range.
	 */
	public boolean contains(Address addr);

	/**
	 * Computes the intersection of this range with another.
	 * @param range the range to intersect this range with
	 * @return AddressRange the intersection or null if the ranges
	 * do not intersect.
	 */
	public AddressRange intersect(AddressRange range);

	/**
	 * Computes the intersection of this range with another.
	 * @param start of range
	 * @param end end of range
	 * @return AddressRange the intersection or null if the ranges
	 * do not intersect.
	 */
	public AddressRange intersectRange(Address start, Address end);

	/**
	 * Returns true if the given range intersects this range.
	 * @param range the range to test for intersection with.
	 */
	public boolean intersects(AddressRange range);

	/**
	 * Returns true if the given range intersects this range.
	 * @param start the first address in the range to test for intersection.
	 * @param end the last address in the range to test for intersection.
	 */
	public boolean intersects(Address start, Address end);

	/**
	 * Compares the given address to this address range.
	 * 
	 * @param addr the address to compare.
	 * @return a negative integer if the address is greater than the maximum range address,
	 *         zero if the address is in the range, and
	 *         a positive integer if the address is less than minimum range address.
	 */
	public int compareTo(Address addr);

	/**
	 * @return the maximum address in the range.
	 */
	public Address getMaxAddress();

	/**
	 * @return the minimum address in the range.
	 */
	public Address getMinAddress();

	/**
	 * @return address space this range resides within
	 */
	public AddressSpace getAddressSpace();

}
