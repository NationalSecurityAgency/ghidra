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
	private int modificationID = 1; // updated if set above ever replaced

	SynchronizedAddressSet() {
		set = new AddressSet();
	}
	
	/**
	 * get the modification number of the internal address set
	 * If the underlying set if ever replaced, modification id is changed
	 * @return current modification id
	 */
	int getModificationID() {
		return modificationID;
	}

	/**
	 * Add all addresses of the given AddressSet to this set.
	 * @param addrSet set of addresses to add.
	 * @see AddressSet#add(AddressSetView)
	 */
	synchronized void add(AddressSet addrSet) {
		AddressSet newSet = new AddressSet(set);
		newSet.add(addrSet);
		set = newSet;
		modificationID++;
	}

	/**
	 * Adds the range to this set
	 * @param start the start address of the range to add
	 * @param end the end address of the range to add
	 * @see AddressSet#add(Address, Address)
	 */
	synchronized void add(Address start, Address end) {
		AddressSet newSet = new AddressSet(set);
		newSet.add(start, end);
		set = newSet;
		modificationID++;
	}

	/**
	 * Deletes a range of addresses from this set
	 * @param start the starting address of the range to be removed
	 * @param end the ending address of the range to be removed (inclusive)
	 * @see AddressSet#delete(Address, Address)
	 */
	synchronized void delete(Address start, Address end) {
		AddressSet newSet = new AddressSet(set);
		newSet.delete(start, end);
		set = newSet;
		modificationID++;
	}
	
	synchronized AddressSet getInternalSet() {
		return set;
	}
	
	/**
	 * Check if the internal set has been modified
	 * If the mod id is different, then the set has changed.
	 * 
	 * @param modID modification id to check
	 * @return true if internal mod id is different
	 */
	public boolean hasChanged(int modID) {
		return modID != modificationID;
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
	public boolean contains(AddressSetView addrSet) {
		return set.contains(addrSet);
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
	public AddressRangeIterator getAddressRanges(boolean forward) {
		return set.getAddressRanges(forward);
	}

	@Override
	public synchronized AddressRangeIterator getAddressRanges(Address start, boolean forward) {
		return new RecoverableAddressRangeIterator(this, start, forward);
	}

	@Override
	public synchronized Iterator<AddressRange> iterator() {
		return set.getAddressRanges();
	}

	@Override
	public Iterator<AddressRange> iterator(boolean forward) {
		return set.getAddressRanges(forward);
	}

	@Override
	public Iterator<AddressRange> iterator(Address start, boolean forward) {
		return set.getAddressRanges(start, forward);
	}

	@Override
	public long getNumAddresses() {
		return set.getNumAddresses();
	}

	@Override
	public synchronized AddressIterator getAddresses(boolean forward) {
		return new RecoverableAddressIterator(this, null, forward);
	}

	@Override
	public synchronized AddressIterator getAddresses(Address start, boolean forward) {
		return new RecoverableAddressIterator(this, start, forward);
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
	public AddressSet intersect(AddressSetView addrSet) {
		return set.intersect(addrSet);
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
	public boolean hasSameAddresses(AddressSetView addrSet) {
		return set.hasSameAddresses(addrSet);
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
	public Address findFirstAddressInCommon(AddressSetView addrSet) {
		return set.findFirstAddressInCommon(addrSet);
	}

	@Override
	public int hashCode() {
		return set.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		return set.equals(obj);
	}

	@Override
	public String toString() {
		return set.toString();
	}
}
