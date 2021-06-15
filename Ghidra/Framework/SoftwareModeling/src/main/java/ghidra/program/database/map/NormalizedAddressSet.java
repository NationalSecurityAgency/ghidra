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
package ghidra.program.database.map;

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.util.datastruct.Range;
import ghidra.util.datastruct.SortedRangeList;

/**
 * AddressSetView implementation that handles image base changes. NOTE: THIS IMPLEMENTATION
 * ASSUMES THAT ONLY ADDRESS RANGES THAT ARE PART OF THE MEMORY MAP WILL BE ADDED TO THIS
 * ADDRESS SET. IT IS INTENDED FOR USE BY THE CHANGE SET.
 */

public class NormalizedAddressSet implements AddressSetView {

// TODO: Needs a rewrite - use a new implementation of AddressRangeMapDB which is stored in memory not in a table.
// Since it will not be able to leverage the DB undo/redo mechanism, the user of this table must handle such things!

	private AddressMap addrMap;

	private Map<Long, SortedRangeList> baseLists = new HashMap<>();
	private ArrayList<Long> bases = new ArrayList<Long>();

	private Comparator<Long> baseComparator = new Comparator<Long>() {

		@Override
		public int compare(Long base1, Long base2) {
			Address a1 = addrMap.decodeAddress(base1);
			Address a2 = addrMap.decodeAddress(base2);
			return a1.compareTo(a2);
		}
	};

	/**
	 *  Constructs a NormalizedAddressSet
	 * @param addrMap the address map
	 */
	public NormalizedAddressSet(AddressMap addrMap) {
		this.addrMap = addrMap;
	}

	/**
	 * Adds the address to the set.
	 * @param addr the address to add
	 */
	public void add(Address addr) {
		addRange(addr, addr);
	}

	/**
	 * Adds the addressSet to this set.
	 * @param set the set of addresses to add/
	 */
	public void add(AddressSetView set) {
		AddressRangeIterator it = set.getAddressRanges();
		while (it.hasNext()) {
			add(it.next());
		}
	}

	/**
	 * Adds the address range to this set.
	 * @param range the range to add.
	 */
	public void add(AddressRange range) {
		addRange(range.getMinAddress(), range.getMaxAddress());
	}

	/**
	 * Adds the address range to this set.
	 * @param startAddr the first address in the range to add.
	 * @param endAddr the last address in the range to add.
	 */
	public void addRange(Address startAddr, Address endAddr) {

		long start = addrMap.getKey(startAddr, true);
		long end = addrMap.getKey(endAddr, true);
		if ((start & AddressMapDB.BASE_MASK) == (end & AddressMapDB.BASE_MASK) && start <= end) {
			addRange(start, end);
			return;
		}

		List<KeyRange> ranges = addrMap.getKeyRanges(startAddr, endAddr, true);
		Iterator<KeyRange> it = ranges.iterator();
		while (it.hasNext()) {
			KeyRange kr = it.next();
			addRange(kr.minKey, kr.maxKey);
		}
	}

	/**
	 * Removes all addresses from this set.
	 */
	public void clear() {
		baseLists = new HashMap<>();
		bases = new ArrayList<Long>();
	}

	private void addRange(long minKey, long maxKey) {
		long baseKey = minKey & AddressMapDB.BASE_MASK;
		SortedRangeList set = baseLists.get(baseKey);
		if (set == null) {
			set = new SortedRangeList();
			baseLists.put(baseKey, set);
			bases.add(new Long(baseKey));
			Collections.sort(bases, baseComparator);
		}
		set.addRange((int) minKey + Integer.MIN_VALUE, (int) maxKey + Integer.MIN_VALUE);
	}

	private SortedRangeList getRangeList(long key) {
		return baseLists.get(key & AddressMapDB.BASE_MASK);
	}

	/**
	 * REmoves all the addresses in the given address set from this set.
	 * @param view the set of addresses to remove.
	 */
	public void delete(AddressSetView view) {
		List<KeyRange> list = addrMap.getKeyRanges(view, false, false);
		Iterator<KeyRange> it = list.iterator();
		while (it.hasNext()) {
			KeyRange kr = it.next();
			deleteRange(kr.minKey, kr.maxKey);
		}
	}

	private void deleteRange(long minKey, long maxKey) {
		long baseKey = minKey & AddressMapDB.BASE_MASK;
		SortedRangeList set = baseLists.get(baseKey);
		if (set == null) {
			return;
		}
		set.removeRange((int) minKey + Integer.MIN_VALUE, (int) maxKey + Integer.MIN_VALUE);
		if (set.isEmpty()) {
			baseLists.remove(baseKey);
			bases.remove(new Long(baseKey));
		}
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#contains(ghidra.program.model.address.Address)
	 */
	@Override
	public boolean contains(Address addr) {
		long key = addrMap.getKey(addr, false);
		SortedRangeList list = getRangeList(key);
		if (list != null) {
			return list.contains((int) key + Integer.MIN_VALUE);
		}
		return false;
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#contains(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	public boolean contains(Address startAddr, Address endAddr) {
		if (!startAddr.hasSameAddressSpace(endAddr)) {
			return contains(addrMap.getAddressFactory().getAddressSet(startAddr, endAddr));
		}
		List<KeyRange> ranges = addrMap.getKeyRanges(startAddr, endAddr, false);
		if (ranges.isEmpty() || !addrMap.decodeAddress(ranges.get(0).minKey).equals(startAddr) ||
			!addrMap.decodeAddress(ranges.get(ranges.size() - 1).maxKey).equals(endAddr)) {
			return false;
		}
		Iterator<KeyRange> it = ranges.iterator();
		while (it.hasNext()) {
			KeyRange kr = it.next();
			SortedRangeList list = getRangeList(kr.minKey);
			if (!list.contains((int) kr.minKey + Integer.MIN_VALUE,
				(int) kr.maxKey + Integer.MIN_VALUE)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#contains(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public boolean contains(AddressSetView rangeSet) {
		AddressRangeIterator it = rangeSet.getAddressRanges();
		while (it.hasNext()) {
			AddressRange range = it.next();
			if (!contains(range.getMinAddress(), range.getMaxAddress())) {
				return false;
			}
		}
		return true;
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#isEmpty()
	 */
	@Override
	public boolean isEmpty() {
		return baseLists.size() == 0;
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#getMinAddress()
	 */
	@Override
	public Address getMinAddress() {
		if (bases.size() == 0) {
			return null;
		}

		long minBase = (bases.get(0)).longValue();
		SortedRangeList list = baseLists.get(minBase);
		long min = minBase + ((list.getMin() - Integer.MIN_VALUE) & 0xffffffffl);
		return addrMap.decodeAddress(min);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#getMaxAddress()
	 */
	@Override
	public Address getMaxAddress() {
		if (bases.size() == 0) {
			return null;
		}

		long maxBase = (bases.get(bases.size() - 1)).longValue();
		SortedRangeList list = baseLists.get(maxBase);
		long max = maxBase + ((list.getMax() - Integer.MIN_VALUE) & 0xffffffffl);
		return addrMap.decodeAddress(max);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#getNumAddressRanges()
	 */
	@Override
	public int getNumAddressRanges() {
		int n = 0;

		for (long key : baseLists.keySet()) {
			SortedRangeList list = baseLists.get(key);
			n += list.getNumRanges();
		}
		return n;
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#getAddressRanges()
	 */
	@Override
	public AddressRangeIterator getAddressRanges() {
		return getAddressRanges(true);
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return getAddressRanges();
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#getAddressRanges(boolean)
	 */
	@Override
	public AddressRangeIterator getAddressRanges(boolean forward) {
		return new MyAddressRangeIterator(forward);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#getNumAddresses()
	 */
	@Override
	public long getNumAddresses() {
		long n = 0;
		for (long key : baseLists.keySet()) {
			SortedRangeList list = baseLists.get(key);
			n += list.getNumValues();
		}
		return n;

	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#getAddresses(boolean)
	 */
	@Override
	public AddressIterator getAddresses(boolean forward) {
		return new MyAddressIterator(forward, null);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#getAddresses(ghidra.program.model.address.Address, boolean)
	 */
	@Override
	public AddressIterator getAddresses(Address start, boolean forward) {
		return new MyAddressIterator(forward, start);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#intersects(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public boolean intersects(AddressSetView addrSet) {
		List<KeyRange> keyList = addrMap.getKeyRanges(addrSet, false, false);
		Iterator<KeyRange> it = keyList.iterator();
		while (it.hasNext()) {
			KeyRange kr = it.next();
			if (intersects(kr.minKey, kr.maxKey)) {
				return true;
			}
		}
		return false;
	}

	private boolean intersects(long min, long max) {
		SortedRangeList srl = getRangeList(min);
		if (srl == null) {
			return false;
		}
		return srl.intersects((int) min + Integer.MIN_VALUE, (int) max + Integer.MIN_VALUE);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#intersects(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	public boolean intersects(Address start, Address end) {
		List<KeyRange> keyList = addrMap.getKeyRanges(start, end, false);
		Iterator<KeyRange> it = keyList.iterator();
		while (it.hasNext()) {
			KeyRange kr = it.next();
			if (intersects(kr.minKey, kr.maxKey)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#intersect(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public AddressSet intersect(AddressSetView view) {
		return new AddressSet(this).intersect(view);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#intersectRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	public AddressSet intersectRange(Address start, Address end) {
		return new AddressSet(this).intersectRange(start, end);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#union(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public AddressSet union(AddressSetView addrSet) {
		return new AddressSet(this).union(addrSet);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#subtract(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public AddressSet subtract(AddressSetView addrSet) {
		return new AddressSet(this).subtract(addrSet);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#xor(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public AddressSet xor(AddressSetView addrSet) {
		return new AddressSet(this).xor(addrSet);
	}

	/**
	 * @see ghidra.program.model.address.AddressSetView#hasSameAddresses(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public boolean hasSameAddresses(AddressSetView view) {

		AddressRangeIterator it1 = getAddressRanges();
		AddressRangeIterator it2 = view.getAddressRanges();

		while (it1.hasNext() && it2.hasNext()) {
			AddressRange myRange = it1.next();
			AddressRange yourRange = it2.next();
			if (!myRange.equals(yourRange)) {
				return false;
			}
		}
		return !it1.hasNext() && !it2.hasNext();
	}

	class MyAddressIterator implements AddressIterator {
		AddressRangeIterator it;
		Address nextAddr;
		Address endAddr;
		boolean forward;

		MyAddressIterator(boolean forward, Address start) {
			it = getAddressRanges(forward);
			this.forward = forward;
			if (start != null) {
				init(start);
			}
		}

		void init(Address start) {
			while (it.hasNext()) {
				AddressRange range = it.next();
				int comp = range.compareTo(start);
				if (comp == 0) {
					nextAddr = start;
					endAddr = forward ? range.getMaxAddress() : range.getMinAddress();
				}
				else if ((forward & (comp > 0)) || (!forward & (comp < 0))) {
					return;
				}
			}
		}

		/**
		 * @see java.util.Iterator#remove()
		 */
		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		/**
		 * @see ghidra.program.model.address.AddressIterator#next()
		 */
		@Override
		public Address next() {
			if (hasNext()) {
				Address retAddr = nextAddr;
				if (forward) {
					nextAddr = (nextAddr.compareTo(endAddr) < 0) ? nextAddr.next() : null;
				}
				else {
					nextAddr = (nextAddr.compareTo(endAddr) > 0) ? nextAddr.previous() : null;
				}
				return retAddr;
			}
			return null;
		}

		/**
		 * @see ghidra.program.model.address.AddressIterator#hasNext()
		 */
		@Override
		public boolean hasNext() {
			if (nextAddr != null) {
				return true;
			}
			if (it.hasNext()) {
				AddressRange range = it.next();
				if (forward) {
					nextAddr = range.getMinAddress();
					endAddr = range.getMaxAddress();
				}
				else {
					nextAddr = range.getMaxAddress();
					endAddr = range.getMinAddress();
				}
				return true;
			}
			return false;
		}

		@Override
		public Iterator<Address> iterator() {
			return this;
		}
	}

	class MyAddressRangeIterator implements AddressRangeIterator {
		private boolean forward;
		private Iterator<Long> baseIterator;
		private Iterator<Range> currIt;
		private long base;

		MyAddressRangeIterator(boolean forward) {
			this.forward = forward;
			ArrayList<Long> myBases = new ArrayList<Long>(bases);
			if (!forward) {
				Collections.reverse(myBases);
			}
			baseIterator = myBases.iterator();
			if (baseIterator.hasNext()) {
				base = baseIterator.next().longValue();
				SortedRangeList srl = getRangeList(base);
				currIt = srl.getRanges(forward);
			}
		}

		@Override
		public Iterator<AddressRange> iterator() {
			return this;
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		/**
		 * @see ghidra.program.model.address.AddressRangeIterator#next()
		 */
		@Override
		public AddressRange next() {
			if (hasNext()) {
				Range range = currIt.next();
				Address a1 =
					addrMap.decodeAddress(base + ((range.min - Integer.MIN_VALUE) & 0xffffffffl));
				Address a2 =
					addrMap.decodeAddress(base + ((range.max - Integer.MIN_VALUE) & 0xffffffffl));
				return new AddressRangeImpl(a1, a2);
			}
			return null;
		}

		/**
		 * @see ghidra.program.model.address.AddressRangeIterator#hasNext()
		 */
		@Override
		public boolean hasNext() {
			if (currIt == null) {
				return false;
			}
			if (currIt.hasNext()) {
				return true;
			}
			currIt = null;
			while (baseIterator.hasNext()) {
				base = baseIterator.next().longValue();
				SortedRangeList srl = getRangeList(base);
				currIt = srl.getRanges(forward);
				if (currIt.hasNext()) {
					return true;
				}
			}
			return false;
		}
	}

	/**
	 *
	 * @see java.lang.Object#toString()
	 */
	@Override
	public final String toString() {
		int size = getNumAddressRanges();

		if (size == 0) {
			return ("[empty]\n");
		}

		StringBuffer str = new StringBuffer();
		for (AddressRange range : this) {
			str.append(range);
			str.append(" ");
		}
		return (str.toString());
	}

	@Override
	public AddressRangeIterator getAddressRanges(Address start, boolean forward) {
		return new AddressSet(this).getAddressRanges(start, forward);
	}

	@Override
	public AddressRange getFirstRange() {
		return new AddressSet(this).getFirstRange();
	}

	@Override
	public AddressRange getLastRange() {
		return new AddressSet(this).getLastRange();
	}

	@Override
	public AddressRange getRangeContaining(Address address) {
		return new AddressSet(this).getRangeContaining(address);
	}

	@Override
	public Iterator<AddressRange> iterator(Address start, boolean forward) {
		return new AddressSet(this).iterator(start, forward);
	}

	@Override
	public Iterator<AddressRange> iterator(boolean forward) {
		return new AddressSet(this).iterator(forward);
	}

	@Override
	public Address findFirstAddressInCommon(AddressSetView set) {
		return new AddressSet(this).findFirstAddressInCommon(set);
	}
}
