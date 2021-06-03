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

import static ghidra.util.ComparatorMath.cmax;
import static ghidra.util.ComparatorMath.cmin;

import java.util.Iterator;

import ghidra.util.AbstractPeekableIterator;
import ghidra.util.AddressIteratorAdapter;

/**
 * For cases where an address set cannot be accessed expediently, this class may wrap it to provide
 * cached read-only access.
 */
public class CachedAddressSetView implements AddressSetView {
	//protected static long hits;
	//protected static long misses;

	protected class CachedRangeIterator extends AbstractPeekableIterator<AddressRange>
			implements AddressRangeIterator {
		protected final Address start;
		protected final boolean forward;

		protected Address cur;

		public CachedRangeIterator(Address start, boolean forward) {
			this.start = start;
			this.forward = forward;

			cur = start;
		}

		@Override
		public Iterator<AddressRange> iterator() {
			return this;
		}

		@Override
		protected AddressRange seekNext() {
			if (cur == null) {
				return null;
			}
			ensureKnown(cur, cur);
			AddressRangeIterator it = cache.getAddressRanges(cur, forward);
			if (!it.hasNext()) {
				return null;
			}
			AddressRange result = it.next();
			cur = forward ? result.getMaxAddress().next() : result.getMinAddress().previous();
			return result;
		}
	}

	protected final AddressSetView delegate;

	protected final AddressSet cache = new AddressSet();
	protected final AddressSet known = new AddressSet();

	protected Address minAddress;
	protected Address maxAddress;
	protected Integer numRanges = null;
	protected Long numAddresses = null;

	public CachedAddressSetView(AddressSetView delegate) {
		this.delegate = delegate;
		init();
	}

	protected void init() {
		minAddress = delegate.getMinAddress();
		maxAddress = delegate.getMaxAddress();
	}

	protected void ensureKnown(Address min, Address max) {
		if (minAddress == null) {
			return;
		}
		min = cmax(min, minAddress);
		max = cmin(max, maxAddress);
		if (known.contains(min, max)) {
			//hits++;
			return;
		}
		//misses++;
		AddressRangeIterator rangesBackward = delegate.getAddressRanges(min, false);
		if (rangesBackward.hasNext()) {
			AddressRange prev = rangesBackward.next();
			cache.add(prev);
			known.add(prev.getMinAddress(), min);
		}
		else {
			known.add(minAddress, min);
		}
		AddressRangeIterator rangesForward = delegate.getAddressRanges(min, true);
		while (true) {
			if (!rangesForward.hasNext()) {
				known.add(min, maxAddress);
				break;
			}
			AddressRange next = rangesForward.next();
			cache.add(next);
			if (next.getMaxAddress().compareTo(max) >= 0) {
				known.add(min, next.getMaxAddress());
				break;
			}
		}
	}

	@Override
	public boolean contains(Address addr) {
		ensureKnown(addr, addr);
		return cache.contains(addr);
	}

	@Override
	public boolean contains(Address start, Address end) {
		ensureKnown(start, end);
		return cache.contains(start, end);
	}

	@Override
	public boolean contains(AddressSetView rangeSet) {
		// TODO: Consider the same linear/binary switch as in AddressSet.
		// Currently, this only does binary.
		for (AddressRange rng : rangeSet) {
			if (!contains(rng.getMinAddress(), rng.getMaxAddress())) {
				return false;
			}
		}
		return true;
	}

	@Override
	public boolean isEmpty() {
		return minAddress == null;
	}

	@Override
	public Address getMinAddress() {
		return minAddress;
	}

	@Override
	public Address getMaxAddress() {
		return maxAddress;
	}

	@Override
	public int getNumAddressRanges() {
		if (numRanges == null) {
			numRanges = delegate.getNumAddressRanges();
		}
		return numRanges;
	}

	@Override
	public AddressRangeIterator getAddressRanges() {
		return getAddressRanges(true);
	}

	@Override
	public AddressRangeIterator getAddressRanges(boolean forward) {
		return getAddressRanges(forward ? minAddress : maxAddress, forward);
	}

	@Override
	public AddressRangeIterator getAddressRanges(Address start, boolean forward) {
		return new CachedRangeIterator(start, forward);
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return getAddressRanges();
	}

	@Override
	public Iterator<AddressRange> iterator(boolean forward) {
		return getAddressRanges(true);
	}

	@Override
	public Iterator<AddressRange> iterator(Address start, boolean forward) {
		return getAddressRanges(start, forward);
	}

	@Override
	public long getNumAddresses() {
		if (numAddresses == null) {
			numAddresses = delegate.getNumAddresses();
		}
		return numAddresses;
	}

	@Override
	public AddressIterator getAddresses(boolean forward) {
		return new AddressIteratorAdapter(getAddressRanges(forward), forward);
	}

	@Override
	public AddressIterator getAddresses(Address start, boolean forward) {
		return new AddressIteratorAdapter(getAddressRanges(start, forward), start, forward);
	}

	@Override
	public boolean intersects(AddressSetView addrSet) {
		for (AddressRange rng : addrSet) {
			if (intersects(rng.getMinAddress(), rng.getMaxAddress())) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean intersects(Address start, Address end) {
		ensureKnown(start, end);
		return cache.intersects(start, end);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Only use this for small sets, otherwise, this cache may become overloaded. This method is
	 * also generally not efficient for sets comprised of many ranges.
	 */
	@Override
	public AddressSet intersect(AddressSetView view) {
		AddressSet result = new AddressSet();
		for (AddressRange rng : view) {
			result.add(intersectRange(rng.getMinAddress(), rng.getMaxAddress()));
		}
		return result;
	}

	@Override
	public AddressSet intersectRange(Address start, Address end) {
		ensureKnown(start, end);
		return cache.intersectRange(start, end);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * After this method is executed, the entire delegate will be loaded in the cache.
	 */
	@Override
	public AddressSet union(AddressSetView addrSet) {
		ensureKnown(minAddress, maxAddress); // Whoa
		return cache.union(addrSet);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * After this method is executed, the entire delegate is loaded into the cache.
	 */
	@Override
	public AddressSet subtract(AddressSetView addrSet) {
		ensureKnown(minAddress, maxAddress); // Whoa
		return cache.subtract(addrSet);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * After this method is executed, the entire delegate is loaded into the cache.
	 */
	@Override
	public AddressSet xor(AddressSetView addrSet) {
		ensureKnown(minAddress, maxAddress); // Whoa
		return cache.xor(addrSet);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * If this method returns true, then the entire delegate has been loaded into the cache.
	 */
	@Override
	public boolean hasSameAddresses(AddressSetView view) {
		for (AddressRange rng : view) {
			Address min = rng.getMinAddress();
			ensureKnown(min, rng.getMaxAddress());
			if (!cache.getRangeContaining(min).equals(rng)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public AddressRange getFirstRange() {
		ensureKnown(minAddress, minAddress);
		return cache.getFirstRange();
	}

	@Override
	public AddressRange getLastRange() {
		ensureKnown(maxAddress, maxAddress);
		return cache.getLastRange();
	}

	@Override
	public AddressRange getRangeContaining(Address address) {
		ensureKnown(address, address);
		return cache.getRangeContaining(address);
	}

	@Override
	public Address findFirstAddressInCommon(AddressSetView set) {
		for (AddressRange rng : set) {
			ensureKnown(rng.getMinAddress(), rng.getMaxAddress());
			AddressSet ir = cache.intersectRange(rng.getMinAddress(), rng.getMaxAddress());
			if (ir != null) {
				return ir.getMinAddress();
			}
		}
		return null;
	}

	public void invalidate() {
		cache.clear();
		known.clear();
		numRanges = null;
		numAddresses = null;
		init();
	}
}
