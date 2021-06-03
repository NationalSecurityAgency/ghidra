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

import java.util.*;

import ghidra.util.UniversalIdGenerator;

/**
 * <code>AddressMapImpl</code> provides a stand-alone AddressMap.
 * An AddressMapImpl instance should only be used to decode keys which it has generated.
 * If this map is used for a specific program instance, the map should be discard if any changes 
 * are made to that programs address map (e.g., removing or renaming overlay spaces).
 */
public class AddressMapImpl {

	private final static int ADDR_OFFSET_SIZE = 32;
	private final static int MAP_ID_SIZE = 8;
	private final static long MAX_OFFSET = (1L << ADDR_OFFSET_SIZE) - 1;
	private final static long ADDR_OFFSET_MASK = MAX_OFFSET;
	private final static long MAP_ID_MASK = (long) -1 << (64 - MAP_ID_SIZE);

	private final static long BASE_MASK = ~ADDR_OFFSET_MASK;
	private final static int BASE_ID_SIZE = 64 - MAP_ID_SIZE - ADDR_OFFSET_SIZE;
	private final static int BASE_ID_MASK = (1 << BASE_ID_SIZE) - 1;

	private final static int STACK_SPACE_ID = -1 >>> MAP_ID_SIZE;

	private HashMap<String, AddressSpace> spaceMap = new HashMap<String, AddressSpace>();
	private AddressSpace stackSpace; // special case - this is the only signed space map supports

	private final AddressFactory addrFactory;
	private Address[] baseAddrs; // order must not change since it relates to generated keys
	private Address[] sortedBaseStartAddrs;
	private Address[] sortedBaseEndAddrs;
	private HashMap<Address, Integer> addrToIndexMap = new HashMap<Address, Integer>();
	private int lastBaseIndex;
	private long mapIdBits;

	/**
	 * Creates a new AddressMapImpl with a mapID of 0.
	 */
	public AddressMapImpl() {
		this((byte) 0, null);
	}

	/**
	 * Creates a new AddressMapImpl with the specified mapID
	 * @param mapID the 8-bit value is placed in the upper 8 bits of every address encoding.
	 */
	public AddressMapImpl(byte mapID, AddressFactory addrFactory) {
		this.addrFactory = addrFactory;
		this.mapIdBits = (long) mapID << (64 - MAP_ID_SIZE);
		baseAddrs = new Address[0];
		init();
	}

	private void init() {
		lastBaseIndex = baseAddrs.length - 1;
		sortedBaseEndAddrs = new Address[baseAddrs.length];
		sortedBaseStartAddrs = new Address[baseAddrs.length];
		System.arraycopy(baseAddrs, 0, sortedBaseStartAddrs, 0, baseAddrs.length);
		Arrays.sort(sortedBaseStartAddrs);
		for (int i = 0; i < sortedBaseStartAddrs.length; i++) {
			long max = sortedBaseStartAddrs[i].getAddressSpace().getMaxAddress().getOffset();
			max = max < 0 ? MAX_OFFSET : Math.min(max, MAX_OFFSET);
			// Avoid use of add which fails for overlay addresses which have restricted min/max offsets
			long off = sortedBaseStartAddrs[i].getOffset() | max;
			sortedBaseEndAddrs[i] =
				sortedBaseStartAddrs[i].getAddressSpace().getAddressInThisSpaceOnly(off);
		}
		addrToIndexMap.clear();
		for (int i = 0; i < baseAddrs.length; i++) {
			if (!addrToIndexMap.containsKey(baseAddrs[i])) {
				addrToIndexMap.put(baseAddrs[i], new Integer(i));
			}
		}
	}

	/**
	 * Comparator used to identify if an addr occurs before or after the 
	 * start of a key range.
	 */
	private Comparator<Object> addressInsertionKeyRangeComparator = new Comparator<Object>() {
		@Override
		public int compare(Object keyRangeObj, Object addrObj) {
			KeyRange range = (KeyRange) keyRangeObj;
			Address addr = (Address) addrObj;

			Address min = decodeAddress(range.minKey);
			if (min.compareTo(addr) > 0) {
				return 1;
			}

			Address max = decodeAddress(range.maxKey);
			if (max.compareTo(addr) < 0) {
				return -1;
			}
			return 0;
		}
	};

	private int getBaseAddressIndex(Address addr) {

		AddressSpace space = addr.getAddressSpace();
		if (space.isStackSpace()) {
			if (stackSpace != null && !stackSpace.equals(space)) {
				throw new IllegalArgumentException("Only one stack space allowed");
			}
			stackSpace = space;
			return STACK_SPACE_ID;
		}

		long baseOffset = addr.getOffset() & BASE_MASK;

		if (lastBaseIndex >= 0) {
			Address base = baseAddrs[lastBaseIndex];
			if (base.hasSameAddressSpace(addr) && baseOffset == base.getOffset()) {
				return lastBaseIndex;
			}
		}

		int search = Arrays.binarySearch(sortedBaseStartAddrs, addr);
		if (search < 0) {
			search = -search - 2;
		}
		if (search >= 0) {
			Address base = sortedBaseStartAddrs[search];
			if (base.hasSameAddressSpace(addr) && baseOffset == base.getOffset()) {
				int index = addrToIndexMap.get(base);
				lastBaseIndex = index;
				return index;
			}
		}
		checkAddressSpace(addr.getAddressSpace());
		int index = baseAddrs.length;

		// Create new base without modifying database
		Address[] newBaseAddrs = new Address[baseAddrs.length + 1];
		System.arraycopy(baseAddrs, 0, newBaseAddrs, 0, baseAddrs.length);
		newBaseAddrs[index] = addr.getAddressSpace().getAddressInThisSpaceOnly(baseOffset);
		baseAddrs = newBaseAddrs;

		init(); // re-sorts baseAddrs
		lastBaseIndex = index;
		return lastBaseIndex;
	}

	void checkAddressSpace(AddressSpace addrSpace) {
		String name = addrSpace.getName();
		AddressSpace existingSpace = spaceMap.get(name);
		if (existingSpace == null) {
			spaceMap.put(name, addrSpace);
		}
		else if (!addrSpace.equals(existingSpace)) {
			throw new IllegalArgumentException("Address space conflicts with another space in map");
		}
	}

	/**
	 * @see ghidra.program.database.map.AddressMap#decodeAddress(long)
	 */
	public synchronized Address decodeAddress(long value) {
		if ((value & MAP_ID_MASK) != mapIdBits) {
			return Address.NO_ADDRESS;
		}

		int baseIndex = (int) (value >> ADDR_OFFSET_SIZE) & BASE_ID_MASK;
		long offset = value & ADDR_OFFSET_MASK;
		if (baseIndex == STACK_SPACE_ID && stackSpace != null) {
			return stackSpace.getAddress((int) offset);
		}
		if (baseIndex >= baseAddrs.length) {
			return Address.NO_ADDRESS;
		}
		return baseAddrs[baseIndex].addWrapSpace(offset);
	}

	/**
	 * Generate a unique key for the specified addr.  Only addresses from a single address space or 
	 * single program should be passed to this method. Only limited checking is not performed in order to 
	 * improve performance.
	 * @param addr address
	 * @see ghidra.program.database.map.AddressMap#getKey(Address, boolean)
	 */
	public synchronized long getKey(Address addr) {
		return mapIdBits | ((long) getBaseAddressIndex(addr) << ADDR_OFFSET_SIZE) |
			(addr.getOffset() & ADDR_OFFSET_MASK);
	}

	/**
	 * @see ghidra.program.database.map.AddressMap#findKeyRange(List, Address)
	 */
	public int findKeyRange(List<KeyRange> keyRangeList, Address addr) {
		if (addr == null) {
			return -1;
		}
		return Collections.binarySearch(keyRangeList, addr, addressInsertionKeyRangeComparator);
	}

	/**
	 * @see ghidra.program.database.map.AddressMap#getKeyRanges(Address, Address, boolean)
	 */
	public List<KeyRange> getKeyRanges(Address start, Address end) {
		if (start.getAddressSpace() != end.getAddressSpace() ||
			start.getOffset() > end.getOffset()) {
			throw new IllegalArgumentException();
		}
		ArrayList<KeyRange> keyRangeList = new ArrayList<KeyRange>();
		addKeyRanges(keyRangeList, start, end);
		return keyRangeList;
	}

	/**
	 * @see ghidra.program.database.map.AddressMap#getKeyRanges(AddressSetView, boolean)
	 */
	public synchronized List<KeyRange> getKeyRanges(AddressSetView set) {

		ArrayList<KeyRange> keyRangeList = new ArrayList<KeyRange>();
		if (set == null) {
			for (int i = 0; i < sortedBaseStartAddrs.length; i++) {
				keyRangeList.add(
					new KeyRange(getKey(sortedBaseStartAddrs[i]), getKey(sortedBaseEndAddrs[i])));
			}
		}
		else {
			AddressRangeIterator it = set.getAddressRanges();
			while (it.hasNext()) {
				AddressRange range = it.next();
				addKeyRanges(keyRangeList, range.getMinAddress(), range.getMaxAddress());
			}
		}
		return keyRangeList;
	}

	private void addKeyRanges(List<KeyRange> keyRangeList, Address start, Address end) {
		int index = Arrays.binarySearch(sortedBaseStartAddrs, start);
		if (index < 0) {
			index = -index - 2;
		}
		if (index < 0) {
			index++;
		}
		while (index < sortedBaseStartAddrs.length &&
			end.compareTo(sortedBaseStartAddrs[index]) >= 0) {
			Address addr1 = max(start, sortedBaseStartAddrs[index]);
			Address addr2 = min(end, sortedBaseEndAddrs[index]);
			if (addr1.compareTo(addr2) <= 0) {
				keyRangeList.add(new KeyRange(getKey(addr1), getKey(addr2)));
			}
			index++;
		}
	}

	private Address min(Address a1, Address a2) {
		return a1.compareTo(a2) < 0 ? a1 : a2;
	}

	private Address max(Address a1, Address a2) {
		return a1.compareTo(a2) < 0 ? a2 : a1;
	}

	/**
	 * Reconcile address space changes using associated address factory.
	 * This method should be invoked following an undo/redo (if the
	 * associated address factory may have changed) or removal of an
	 * overlay memory block.
	 */
	public void reconcile() {
		if (addrFactory == null) {
			return;
		}

		HashMap<String, OverlayAddressSpace> remapSpaces =
			new HashMap<String, OverlayAddressSpace>();

		Iterator<String> iter = spaceMap.keySet().iterator();
		while (iter.hasNext()) {
			String key = iter.next();
			AddressSpace space = spaceMap.get(key);
			if (space instanceof ObsoleteOverlaySpace) {
				// check for restored space
				OverlayAddressSpace oldOverlaySpace =
					((ObsoleteOverlaySpace) space).getOriginalSpace();
				AddressSpace curSpace = addrFactory.getAddressSpace(oldOverlaySpace.getName());
				if (curSpace != null && curSpace.equals(oldOverlaySpace)) {
					remapSpaces.put(space.getName(), (OverlayAddressSpace) curSpace);
					iter.remove();
				}
			}
			else if (space instanceof OverlayAddressSpace) {
				// check for removed space
				AddressSpace curSpace = addrFactory.getAddressSpace(space.getName());
				if (curSpace == null || !curSpace.equals(space)) {
					ObsoleteOverlaySpace obsoleteSpace =
						new ObsoleteOverlaySpace((OverlayAddressSpace) space);
					remapSpaces.put(space.getName(), obsoleteSpace);
					iter.remove();
				}
			}
		}

		for (AddressSpace space : remapSpaces.values()) {
			spaceMap.put(space.getName(), space);
		}

		for (int i = 0; i < baseAddrs.length; i++) {
			Address addr = baseAddrs[i];
			AddressSpace space = addr.getAddressSpace();
			OverlayAddressSpace curSpace = remapSpaces.get(space.getName());
			if (curSpace != null) {
				baseAddrs[i] = curSpace.getAddressInThisSpaceOnly(addr.getOffset());
			}
		}

		init();
	}

	private static class ObsoleteOverlaySpace extends OverlayAddressSpace {

		private final OverlayAddressSpace originalSpace;

		ObsoleteOverlaySpace(OverlayAddressSpace ovSpace) {
			super(makeName(), ovSpace.getOverlayedSpace(), ovSpace.getUnique(),
				ovSpace.getMinOffset(), ovSpace.getMaxOffset());
			this.originalSpace = ovSpace;
		}

		private static String makeName() {
			return "DELETED_" + Long.toHexString(UniversalIdGenerator.nextID().getValue());
		}

		OverlayAddressSpace getOriginalSpace() {
			return originalSpace;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == this) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (!(obj instanceof ObsoleteOverlaySpace)) {
				return false;
			}
			ObsoleteOverlaySpace s = (ObsoleteOverlaySpace) obj;

			return originalSpace.equals(s.originalSpace) && name.equals(s.name) &&
				getMinOffset() == s.getMinOffset() && getMaxOffset() == s.getMaxOffset();
		}
	}
}
