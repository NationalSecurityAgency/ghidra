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

import java.util.Iterator;

/**
 * This class wraps an address set and provides read-only access to that set.  This class
 * is used to ensure that users can not violate the read-only access by casting the object
 * to an address set.
 */
public class AddressSetViewAdapter implements AddressSetView {
	private AddressSetView set;

	/**
	 * Construct an AddressSetViewAdapter for an address set.
	 * @param set the address set to wrap as a read-only object.
	 */
	public AddressSetViewAdapter(AddressSetView set) {
		this.set = set;
	}

	@Override
	public boolean contains(Address addr) {
		return set.contains(addr);
	}

	@Override
	public boolean contains(Address start, Address end) {
		return set.contains(start, end);
	}

	@Override
	public boolean contains(AddressSetView rangeSet) {
		return set.contains(rangeSet);
	}

	@Override
	public boolean isEmpty() {
		return set.isEmpty();
	}

	@Override
	public Address getMinAddress() {
		return set.getMinAddress();
	}

	@Override
	public Address getMaxAddress() {
		return set.getMaxAddress();
	}

	@Override
	public int getNumAddressRanges() {
		return set.getNumAddressRanges();
	}

	@Override
	public AddressRangeIterator getAddressRanges() {
		return set.getAddressRanges();
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return getAddressRanges();
	}

	@Override
	public AddressRangeIterator getAddressRanges(boolean startAtFront) {
		return set.getAddressRanges(startAtFront);
	}

	@Override
	public long getNumAddresses() {
		return set.getNumAddresses();
	}

	@Override
	public AddressIterator getAddresses(boolean forward) {
		return set.getAddresses(forward);
	}

	@Override
	public AddressIterator getAddresses(Address start, boolean forward) {
		return set.getAddresses(start, forward);
	}

	@Override
	public boolean intersects(AddressSetView addrSet) {
		return set.intersects(addrSet);
	}

	@Override
	public boolean intersects(Address start, Address end) {
		return set.intersects(start, end);
	}

	@Override
	public AddressSet intersect(AddressSetView view) {
		return set.intersect(view);
	}

	@Override
	public AddressSet intersectRange(Address start, Address end) {
		return set.intersectRange(start, end);
	}

	@Override
	public AddressSet union(AddressSetView addrSet) {
		return set.union(addrSet);
	}

	@Override
	public AddressSet subtract(AddressSetView addrSet) {
		return set.subtract(addrSet);
	}

	@Override
	public AddressSet xor(AddressSetView addrSet) {
		return set.xor(addrSet);
	}

	@Override
	public boolean hasSameAddresses(AddressSetView view) {
		return set.hasSameAddresses(view);
	}

	@Override
	public AddressRangeIterator getAddressRanges(Address start, boolean forward) {
		return set.getAddressRanges(start, forward);
	}

	@Override
	public AddressRange getFirstRange() {
		return set.getFirstRange();
	}

	@Override
	public AddressRange getLastRange() {
		return set.getLastRange();
	}

	@Override
	public AddressRange getRangeContaining(Address address) {
		return set.getRangeContaining(address);
	}

	@Override
	public Iterator<AddressRange> iterator(boolean forward) {
		return set.iterator(forward);
	}

	@Override
	public Iterator<AddressRange> iterator(Address start, boolean forward) {
		return set.iterator(start, forward);
	}

	@Override
	public Address findFirstAddressInCommon(AddressSetView otherSet) {
		return set.findFirstAddressInCommon(otherSet);
	}

	@Override
	public String toString() {
		return set.toString();
	}
}
