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
package ghidra.program.database.mem;

import java.util.Iterator;

import ghidra.program.model.address.*;

/**
 * <code>SynchronizedAddressSet</code> provides a synchronized address set which
 * implements the {@link AddressSetView} interface.  Iterators returned by this
 * implementation will recover from concurrent modification of this address set.
 * See {@link RecoverableAddressRangeIterator} and {@link RecoverableAddressIterator}.
 */
class SynchronizedAddressSet implements AddressSetView {

	private AddressSet set;

	SynchronizedAddressSet() {
		set = new AddressSet();
	}

	/**
	 * Add all addresses of the given AddressSet to this set.
	 * @param addrSet set of addresses to add.
	 * @see AddressSet#add(AddressSetView)
	 */
	synchronized void add(AddressSet addrSet) {
		set.add(addrSet);
	}

	/**
	 * Adds the range to this set
	 * @param start the start address of the range to add
	 * @param end the end address of the range to add
	 * @see AddressSet#add(Address, Address)
	 */
	synchronized void add(Address start, Address end) {
		set.add(start, end);
	}

	/**
	 * Deletes a range of addresses from this set
	 * @param start the starting address of the range to be removed
	 * @param end the ending address of the range to be removed (inclusive)
	 * @see AddressSet#delete(Address, Address)
	 */
	synchronized void delete(Address start, Address end) {
		set.delete(start, end);
	}

	@Override
	public synchronized boolean contains(Address addr) {
		return set.contains(addr);
	}

	@Override
	public synchronized boolean contains(Address start, Address end) {
		return set.contains(start, end);
	}

	@Override
	public synchronized boolean contains(AddressSetView addrSet) {
		return set.contains(addrSet);
	}

	@Override
	public synchronized boolean isEmpty() {
		return set.isEmpty();
	}

	@Override
	public synchronized Address getMinAddress() {
		return set.getMinAddress();
	}

	@Override
	public synchronized Address getMaxAddress() {
		return set.getMaxAddress();
	}

	@Override
	public synchronized int getNumAddressRanges() {
		return set.getNumAddressRanges();
	}

	@Override
	public synchronized AddressRangeIterator getAddressRanges() {
		return set.getAddressRanges();
	}

	@Override
	public synchronized AddressRangeIterator getAddressRanges(boolean forward) {
		return set.getAddressRanges(forward);
	}

	@Override
	public synchronized AddressRangeIterator getAddressRanges(Address start, boolean forward) {
		return new RecoverableAddressRangeIterator(set, start, forward);
	}

	@Override
	public synchronized Iterator<AddressRange> iterator() {
		return set.getAddressRanges();
	}

	@Override
	public synchronized Iterator<AddressRange> iterator(boolean forward) {
		return set.getAddressRanges(forward);
	}

	@Override
	public synchronized Iterator<AddressRange> iterator(Address start, boolean forward) {
		return set.getAddressRanges(start, forward);
	}

	@Override
	public synchronized long getNumAddresses() {
		return set.getNumAddresses();
	}

	@Override
	public synchronized AddressIterator getAddresses(boolean forward) {
		return new RecoverableAddressIterator(set, null, forward);
	}

	@Override
	public synchronized AddressIterator getAddresses(Address start, boolean forward) {
		return new RecoverableAddressIterator(set, start, forward);
	}

	@Override
	public synchronized boolean intersects(AddressSetView addrSet) {
		return set.intersects(addrSet);
	}

	@Override
	public synchronized boolean intersects(Address start, Address end) {
		return set.intersects(start, end);
	}

	@Override
	public synchronized AddressSet intersect(AddressSetView addrSet) {
		return set.intersect(addrSet);
	}

	@Override
	public synchronized AddressSet intersectRange(Address start, Address end) {
		return set.intersectRange(start, end);
	}

	@Override
	public synchronized AddressSet union(AddressSetView addrSet) {
		return set.union(addrSet);
	}

	@Override
	public synchronized AddressSet subtract(AddressSetView addrSet) {
		return set.subtract(addrSet);
	}

	@Override
	public synchronized AddressSet xor(AddressSetView addrSet) {
		return set.xor(addrSet);
	}

	@Override
	public synchronized boolean hasSameAddresses(AddressSetView addrSet) {
		return set.hasSameAddresses(addrSet);
	}

	@Override
	public synchronized AddressRange getFirstRange() {
		return set.getFirstRange();
	}

	@Override
	public synchronized AddressRange getLastRange() {
		return set.getLastRange();
	}

	@Override
	public synchronized AddressRange getRangeContaining(Address address) {
		return set.getRangeContaining(address);
	}

	@Override
	public synchronized Address findFirstAddressInCommon(AddressSetView addrSet) {
		return set.findFirstAddressInCommon(addrSet);
	}

	@Override
	public synchronized int hashCode() {
		return set.hashCode();
	}

	@Override
	public synchronized boolean equals(Object obj) {
		return set.equals(obj);
	}

	@Override
	public synchronized String toString() {
		return set.toString();
	}

}
