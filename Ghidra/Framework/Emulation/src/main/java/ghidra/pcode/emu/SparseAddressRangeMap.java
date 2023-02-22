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
package ghidra.pcode.emu;

import java.util.*;
import java.util.Map.Entry;
import java.util.function.Predicate;

import ghidra.program.model.address.*;

public class SparseAddressRangeMap<V> {
	public static final long PAGE_BITS = 12;
	public static final long PAGE_MASK = -1L << PAGE_BITS;
	public static final long OFF_MASK = ~PAGE_MASK;

	private static class Space<V> {
		private final Map<Long, Page<V>> pages = new HashMap<>();

		private static long getPageIndex(Address addr) {
			return addr.getOffset() >> PAGE_BITS;
		}

		Entry<AddressRange, V> put(Entry<AddressRange, V> entry) {
			AddressRange range = entry.getKey();
			long indexMin = getPageIndex(range.getMinAddress());
			Page<V> pageMin = pages.computeIfAbsent(indexMin, o -> new Page<>());
			pageMin.put(entry);
			long indexMax = getPageIndex(range.getMaxAddress());
			if (indexMax == indexMin) {
				return entry;
			}
			Page<V> pageMax = pages.computeIfAbsent(indexMax, o -> new Page<>());
			return pageMax.put(entry);
		}

		boolean hasEntry(Address address, Predicate<V> predicate) {
			Page<V> page = pages.get(getPageIndex(address));
			if (page == null) {
				return false;
			}
			return page.hasEntry(address, predicate);
		}
	}

	private static class Page<V> {
		static final Comparator<Entry<AddressRange, ?>> ENTRY_COMPARATOR = Page::compareEntries;
		private final List<Entry<AddressRange, V>> entries = new ArrayList<>();

		private static int compareEntries(Entry<AddressRange, ?> e1, Entry<AddressRange, ?> e2) {
			return e1.getKey().getMinAddress().compareTo(e2.getKey().getMinAddress());
		}

		Entry<AddressRange, V> put(Entry<AddressRange, V> entry) {
			int index = Collections.binarySearch(entries, entry, ENTRY_COMPARATOR);
			if (index < 0) {
				index = -index - 1;
			}
			entries.add(index, entry);
			return entry;
		}

		boolean hasEntry(Address address, Predicate<V> predicate) {
			for (Entry<AddressRange, V> ent : entries) {
				AddressRange range = ent.getKey();
				if (range.contains(address)) {
					if (predicate.test(ent.getValue())) {
						return true;
					}
					continue;
				}
				if (address.compareTo(range.getMinAddress()) < 0) {
					return false;
				}
			}
			return false;
		}
	}

	private final Map<AddressSpace, Space<V>> spaces = new HashMap<>();
	private boolean isEmpty = true;

	public Entry<AddressRange, V> put(AddressRange range, V value) {
		Space<V> space = spaces.computeIfAbsent(range.getAddressSpace(), s -> new Space<>());
		Entry<AddressRange, V> entry = space.put(Map.entry(range, value));
		isEmpty = false;
		return entry;
	}

	public boolean hasEntry(Address address, Predicate<V> predicate) {
		Space<V> space = spaces.get(address.getAddressSpace());
		if (space == null) {
			return false;
		}
		return space.hasEntry(address, predicate);
	}

	public void clear() {
		spaces.clear();
		isEmpty = true;
	}

	public boolean isEmpty() {
		return isEmpty;
	}
}
