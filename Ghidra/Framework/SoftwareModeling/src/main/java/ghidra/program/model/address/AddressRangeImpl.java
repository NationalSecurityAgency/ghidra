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

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Iterator;

/**
 * Implementation of an AddressRange.  An AddressRange is a contiguous
 * inclusive set of addresses from some minimum to a maximum address.  Once created
 * it is immutable.
 *
 * @since 2000-2-16
 */

public class AddressRangeImpl implements AddressRange, Serializable {
	private static final long serialVersionUID = 1;

	private final Address minAddress; // minimum address in this range.
	private final Address maxAddress; // maximum address in this range.

	/**
	 * Construct a new AddressRangeImpl from the given range.
	 * @param range the address range to copy.
	 */
	public AddressRangeImpl(AddressRange range) {
		minAddress = range.getMinAddress();
		maxAddress = range.getMaxAddress();
	}

	/**
	 * Construct an AddressRange with the given start and end address.
	 * If the start address is before the end address,
	 *   they are swapped to be in order.
	 *
	 * @param start start address in the range
	 * @param end end address in the range
	 * @exception IllegalArgumentException thrown if the minimum and
	 * maximum addresses are not comparable.
	 */
	public AddressRangeImpl(Address start, Address end) {
		if (!start.getAddressSpace().equals(end.getAddressSpace())) {
			throw new IllegalArgumentException("Start and end addresses are not in the same space.");
		}

		if (start.compareTo(end) < 0) {
			minAddress = start;
			maxAddress = end;
		} else {
			// swap them if out of order
			minAddress = end;
			maxAddress = start;
		}
	}

	/**
	 * Construct an AddressRange with the given start address and length.
	 * @param start start address in the range
	 * @param length the length of the range.
	 * @exception AddressOverflowException if the length would wrap.
	 */
	public AddressRangeImpl(Address start, long length) throws AddressOverflowException {
		minAddress = start;
		maxAddress = start.addNoWrap(length - 1);
	}

	/**
	 * @see ghidra.program.model.address.AddressRange#contains(ghidra.program.model.address.Address)
	 */
	@Override
	public boolean contains(Address addr) {

		return minAddress.compareTo(addr) <= 0 && maxAddress.compareTo(addr) >= 0;
	}

	@Override
	public AddressSpace getAddressSpace() {
		return minAddress.getAddressSpace();
	}

	/**
	 * @see ghidra.program.model.address.AddressRange#getMinAddress()
	 */
	@Override
	public Address getMinAddress() {
		return minAddress;
	}

	/**
	 * 
	 * @see ghidra.program.model.address.AddressRange#getMaxAddress()
	 */
	@Override
	public Address getMaxAddress() {
		return maxAddress;
	}

	/**
	 * 
	 * @see ghidra.program.model.address.AddressRange#getLength()
	 */
	@Override
	public long getLength() {
		return maxAddress.subtract(minAddress) + 1;
	}

	@Override
	public BigInteger getBigLength() {
		return maxAddress.getOffsetAsBigInteger().subtract(minAddress.getOffsetAsBigInteger()).add(
			BigInteger.ONE);
	}

	/**
	 * 
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}

		if (this == obj) {
			return true;
		}

		if (getClass() != obj.getClass()) {
			return false;
		}

		AddressRange range = (AddressRange) obj;
		return minAddress.equals(range.getMinAddress()) && maxAddress.equals(range.getMaxAddress());
	}

	@Override
	public int hashCode() {
		return minAddress.hashCode();
	}

	/**
	 * 
	 * @see ghidra.program.model.address.AddressRange#compareTo(ghidra.program.model.address.Address)
	 */
	@Override
	public int compareTo(Address addr) {
		if (maxAddress.compareTo(addr) < 0) {
			return -1;
		}
		if (minAddress.compareTo(addr) > 0) {
			return 1;
		}
		return 0;
	}

	/**
	 * 
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "[" + minAddress + ", " + maxAddress + "]";
	}

	/**
	 * 
	 * @see ghidra.program.model.address.AddressRange#intersects(ghidra.program.model.address.AddressRange)
	 */
	@Override
	public boolean intersects(AddressRange range) {
		return intersects(range.getMinAddress(), range.getMaxAddress());
	}

	/**
	 * 
	 * @see ghidra.program.model.address.AddressRange#intersects(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	public boolean intersects(Address start, Address end) {

		return (end.compareTo(minAddress) >= 0) && (start.compareTo(maxAddress) <= 0);
	}

	/**
	 * 
	 * @see ghidra.program.model.address.AddressRange#intersect(ghidra.program.model.address.AddressRange)
	 */
	@Override
	public AddressRange intersect(AddressRange range) {
		return intersectRange(range.getMinAddress(), range.getMaxAddress());
	}

	/**
	 * @see ghidra.program.model.address.AddressRange#intersectRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	public AddressRange intersectRange(Address start, Address end) {
		if (start.compareTo(end) > 0) {
			Address tmp = start;
			start = end;
			end = tmp;
		}
		Address min = minAddress.compareTo(start) >= 0 ? minAddress : start;
		Address max = maxAddress.compareTo(end) <= 0 ? maxAddress : end;

		if (min.compareTo(max) <= 0) {
			return new AddressRangeImpl(min, max);
		}
		return null;
	}

	@Override
	public int compareTo(AddressRange o) {
		int result = minAddress.compareTo(o.getMinAddress());
		if (result == 0) {
			result = maxAddress.compareTo(o.getMaxAddress());
		}
		return result;
	}

	@Override
	public Iterator<Address> iterator() {
		return new MyAddressIterator();
	}

	private class MyAddressIterator implements Iterator<Address> {

		private Address curr;

		public MyAddressIterator() {
			this.curr = minAddress;
		}

		@Override
		public boolean hasNext() {
			return curr != null;
		}

		@Override
		public Address next() {
			Address next = curr;
			if (curr != null) {
				curr = curr.equals(maxAddress) ? null : curr.next();
			}
			return next;
		}

	}

}
