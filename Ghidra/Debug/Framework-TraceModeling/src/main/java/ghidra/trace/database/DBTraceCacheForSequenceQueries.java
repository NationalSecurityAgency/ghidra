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
package ghidra.trace.database;

import java.util.*;
import java.util.Map.Entry;

import com.google.common.collect.Range;

import ghidra.program.model.address.*;
import ghidra.trace.model.ImmutableTraceAddressSnapRange;
import ghidra.trace.model.TraceAddressSnapRange;

public abstract class DBTraceCacheForSequenceQueries<T> {
	//protected static long hits = 0;
	//protected static long misses = 0;
	//protected static long totalCheck = 0;
	//protected static long totalLoad = 0;
	//protected static long totalQuery = 0;

	protected class CachedRegion {
		public long snap;
		private final NavigableMap<Address, T> nav = new TreeMap<>();

		public Address min;
		public Address max;

		public CachedRegion(long snap, AddressRange range) {
			this.snap = snap;
			this.min = range.getMinAddress();
			this.max = range.getMaxAddress();
		}

		public T getFloor(Address address) {
			Entry<Address, T> floor = nav.floorEntry(address);
			if (floor != null) {
				return floor.getValue();
			}
			if (min == min.getAddressSpace().getMinAddress()) {
				return null;
			}
			Entry<TraceAddressSnapRange, T> ent = doFloorEntry(snap, address);
			if (ent == null) {
				min = min.getAddressSpace().getMinAddress();
				return null;
			}
			Address x1 = ent.getKey().getX1();
			nav.put(x1, ent.getValue());
			min = x1;
			return ent.getValue();
		}

		public T getCeiling(Address address) {
			Entry<Address, T> ceiling = nav.ceilingEntry(address);
			if (ceiling != null) {
				return ceiling.getValue();
			}
			if (max == max.getAddressSpace().getMaxAddress()) {
				return null;
			}
			Entry<TraceAddressSnapRange, T> ent = doCeilingEntry(snap, address);
			if (ent == null) {
				max = max.getAddressSpace().getMaxAddress();
				return null;
			}
			Address x1 = ent.getKey().getX1();
			nav.put(x1, ent.getValue());
			max = x1;
			return ent.getValue();
		}

		public void load(
				ArrayList<? extends Entry<? extends TraceAddressSnapRange, ? extends T>> entries) {
			for (Entry<? extends TraceAddressSnapRange, ? extends T> ent : entries) {
				nav.put(ent.getKey().getX1(), ent.getValue());
			}
		}

		protected boolean contains(Address address) {
			return min.hasSameAddressSpace(address) && min.compareTo(address) <= 0 &&
				max.compareTo(address) >= 0;
		}

		protected void reInit(@SuppressWarnings("hiding") long snap, AddressRange range) {
			this.snap = snap;
			this.min = range.getMinAddress();
			this.max = range.getMaxAddress();
		}
	}

	protected final int maxRegions;
	protected final int addressBreadth;
	// TODO: Depending on the number of regions, LinkedList may perform better
	protected final List<CachedRegion> cache = new ArrayList<>();

	public DBTraceCacheForSequenceQueries(int maxRegions, int addressBreadth) {
		this.maxRegions = maxRegions;
		this.addressBreadth = addressBreadth;
	}

	protected abstract void loadCachedRegion(CachedRegion region);

	protected abstract Entry<TraceAddressSnapRange, T> doFloorEntry(long snap, Address address);

	protected abstract Entry<TraceAddressSnapRange, T> doCeilingEntry(long snap, Address address);

	protected CachedRegion ensureInCache(long snap, Address address) {
		//System.err.println("Seq cache perf:" +
		//	" hits=" + hits +
		//	",misses=" + misses +
		//	",ratio=" + (1.0 * hits / misses) +
		//	",size=" + cache.size() +
		//	",avgCheck=" + (1.0 * totalCheck) / (hits + misses) +
		//	",avgLoad=" + (1.0 * totalLoad) / (misses) +
		//	",avgQuery=" + (1.0 * totalQuery) / (hits + misses));
		//long start = System.currentTimeMillis();
		for (int i = 0; i < cache.size(); i++) {
			CachedRegion region = cache.get(i);
			if (region.snap == snap && region.contains(address)) {
				cache.remove(i);
				cache.add(0, region);
				//hits++;
				//totalCheck += System.currentTimeMillis() - start;
				return region;
			}
		}
		//totalCheck += System.currentTimeMillis() - start;
		CachedRegion region;
		if (cache.size() >= maxRegions) {
			region = cache.remove(0);
			region.reInit(snap, computeNewCachedRange(address));
		}
		else {
			region = new CachedRegion(snap, computeNewCachedRange(address));
		}
		//start = System.currentTimeMillis();
		loadCachedRegion(region);
		//totalLoad += System.currentTimeMillis() - start;
		cache.add(region);
		//misses++;
		return region;
	}

	protected AddressRange computeNewCachedRange(Address address) {
		return ImmutableTraceAddressSnapRange.rangeCentered(address, addressBreadth);
	}

	public T getFloor(long snap, Address address) {
		//long start = System.currentTimeMillis();
		T result = ensureInCache(snap, address).getFloor(address);
		//totalQuery += System.currentTimeMillis() - start;
		return result;
	}

	public T getCeiling(long snap, Address address) {
		//long start = System.currentTimeMillis();
		T result = ensureInCache(snap, address).getCeiling(address);
		//totalQuery += System.currentTimeMillis() - start;
		return result;
	}

	public void notifyNewEntry(Range<Long> lifespan, AddressRangeImpl range, T item) {
		// TODO: Can this be smarter?
		invalidate();
	}

	public void notifyEntryRemoved(Range<Long> lifespan, AddressRange range, T item) {
		// TODO: Can this be smarter?
		invalidate();
	}

	public void notifyEntryShapeChanged(Range<Long> lifespan, AddressRange range, T item) {
		// TODO: Can this be smarter?
		invalidate();
	}

	public void invalidate() {
		cache.clear();
	}
}
