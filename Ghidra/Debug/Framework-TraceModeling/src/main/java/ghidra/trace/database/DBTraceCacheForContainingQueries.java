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

import org.apache.commons.lang3.tuple.ImmutablePair;

import ghidra.program.model.address.*;
import ghidra.trace.database.DBTraceCacheForContainingQueries.GetKey;
import ghidra.trace.model.*;
import ghidra.util.datastruct.FixedSizeHashMap;

public abstract class DBTraceCacheForContainingQueries<K extends GetKey, V, T> {
	public static class GetKey {
		public final long snap;
		public final Address addr;

		public GetKey(long snap, Address addr) {
			this.snap = snap;
			this.addr = addr;
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof GetKey)) {
				return false;
			}
			GetKey that = (GetKey) obj;
			if (this.snap != that.snap) {
				return false;
			}
			if (!this.addr.equals(that.addr)) {
				return false;
			}
			return true;
		}

		@Override
		public int hashCode() {
			int result = 0;
			result += snap;
			result *= 31;
			result += addr.hashCode();
			return result;
		}
	}

	// TODO: Experiment with multiple range caches
	protected final int snapBreadth;
	protected final int addressBreadth;
	protected final List<Entry<TraceAddressSnapRange, T>> rangeCache = new ArrayList<>();
	protected TraceAddressSnapRange rangeCacheRange;

	protected final Map<K, V> pointCache;

	public DBTraceCacheForContainingQueries(int snapBreadth, int addressBreadth, int maxPoints) {
		this.snapBreadth = snapBreadth;
		this.addressBreadth = addressBreadth;
		this.pointCache = new FixedSizeHashMap<>(maxPoints);
	}

	protected abstract void loadRangeCache(TraceAddressSnapRange range);

	protected abstract V doGetContaining(K key);

	protected List<? extends T> getAllInRangeCacheContaining(K key) {
		List<T> result = new ArrayList<>();
		for (Entry<TraceAddressSnapRange, T> ent : rangeCache) {
			TraceAddressSnapRange range = ent.getKey();
			if (!range.getLifespan().contains(key.snap)) {
				continue;
			}
			if (!range.getRange().contains(key.addr)) {
				continue;
			}
			result.add(ent.getValue());
		}
		return result;
	}

	protected T getFirstInRangeCacheContaining(K key) {
		for (Entry<TraceAddressSnapRange, T> ent : rangeCache) {
			TraceAddressSnapRange range = ent.getKey();
			if (!range.getLifespan().contains(key.snap)) {
				continue;
			}
			if (!range.getRange().contains(key.addr)) {
				continue;
			}
			return ent.getValue();
		}
		return null;
	}

	protected boolean isInCachedRange(long snap, Address address) {
		return rangeCacheRange != null && rangeCacheRange.getLifespan().contains(snap) &&
			rangeCacheRange.getRange().contains(address);
	}

	protected void ensureInCachedRange(long snap, Address address) {
		if (isInCachedRange(snap, address)) {
			return;
		}
		rangeCache.clear();
		loadRangeCache(rangeCacheRange = computeNewCachedRange(snap, address));
	}

	protected TraceAddressSnapRange computeNewCachedRange(long snap, Address address) {
		return ImmutableTraceAddressSnapRange.centered(address, snap, addressBreadth, snapBreadth);
	}

	public V getContaining(K key) {
		return pointCache.computeIfAbsent(key, this::doGetContaining);
	}

	public void notifyNewEntry(Lifespan lifespan, Address address, T item) {
		// TODO: Can this be smarter?
		pointCache.clear();
		if (rangeCacheRange != null &&
			!rangeCacheRange.getLifespan().intersect(lifespan).isEmpty() &&
			rangeCacheRange.getRange().contains(address)) {
			rangeCache.add(new ImmutablePair<>(
				new ImmutableTraceAddressSnapRange(address, lifespan), item));
		}
	}

	public void notifyNewEntry(Lifespan lifespan, AddressRange range, T item) {
		// TODO: Can this be smarter?
		pointCache.clear();
		if (rangeCacheRange != null &&
			!rangeCacheRange.getLifespan().intersect(lifespan).isEmpty() &&
			rangeCacheRange.getRange().intersects(range)) {
			rangeCache.add(new ImmutablePair<>(
				new ImmutableTraceAddressSnapRange(range, lifespan), item));
		}
	}

	public void notifyNewEntries(Lifespan lifespan, AddressSetView addresses, T item) {
		// TODO: Can this be smarter?
		pointCache.clear();
		if (rangeCacheRange != null &&
			!rangeCacheRange.getLifespan().intersect(lifespan).isEmpty()) {
			for (AddressRange range : addresses) {
				if (rangeCacheRange.getRange().intersects(range)) {
					rangeCache.add(new ImmutablePair<>(
						new ImmutableTraceAddressSnapRange(range, lifespan), item));
				}
			}
		}
	}

	public void notifyEntryRemoved(Lifespan lifespan, AddressRange range, T item) {
		// TODO: Can this be smarter?
		invalidate();
	}

	public void notifyEntryShapeChanged(Lifespan lifespan, AddressRange range, T item) {
		// TODO: Can this be smarter?
		invalidate();
	}

	public void invalidate() {
		pointCache.clear();
		rangeCache.clear();
		rangeCacheRange = null;
	}
}
