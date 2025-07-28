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
package ghidra.trace.database.symbol;

import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.lang3.tuple.ImmutablePair;

import ghidra.program.model.address.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.trace.database.DBTraceCacheForContainingQueries;
import ghidra.trace.database.DBTraceCacheForContainingQueries.GetKey;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapSpace;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.symbol.DBTraceSymbolManager.DBTraceSymbolIDEntry;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.symbol.TraceNamespaceSymbol;
import ghidra.trace.model.symbol.TraceSymbolManager;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.LazyCollection;
import ghidra.util.LockHold;
import ghidra.util.database.DBCachedObjectStore;
import ghidra.util.database.spatial.rect.Rectangle2DDirection;

public abstract class AbstractDBTraceSymbolSingleTypeWithLocationView<T extends AbstractDBTraceSymbol>
		extends AbstractDBTraceSymbolSingleTypeView<T> {

	protected final static int CACHE_SNAP_BREADTH = 2;
	protected final static int CACHE_ADDRESS_BREADTH = 30;
	protected final static int CACHE_MAX_POINTS = 1000;

	protected static class GetSymbolsKey extends GetKey {
		public final TraceThread thread;
		protected final boolean includeDynamic;

		public GetSymbolsKey(TraceThread thread, long snap, Address addr,
				boolean includeDynamic) {
			super(snap, addr);
			this.thread = thread;
			this.includeDynamic = includeDynamic;
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof GetSymbolsKey)) {
				return false;
			}
			GetSymbolsKey that = (GetSymbolsKey) obj;
			if (this.includeDynamic != that.includeDynamic) {
				return false;
			}
			if (this.thread != that.thread) {
				return false;
			}
			return super.equals(obj);
		}

		@Override
		public int hashCode() {
			int result = super.hashCode();
			result *= 31;
			result += System.identityHashCode(thread);
			result *= 31;
			result += Boolean.hashCode(includeDynamic);
			return result;
		}
	}

	protected class CacheForGetSymbolsAtQueries
			extends DBTraceCacheForContainingQueries<GetSymbolsKey, Collection<? extends T>, T> {

		public CacheForGetSymbolsAtQueries() {
			super(CACHE_SNAP_BREADTH, CACHE_ADDRESS_BREADTH, CACHE_MAX_POINTS);
		}

		@Override
		protected void loadRangeCache(TraceAddressSnapRange range) {
			rangeCache.clear();
			DBTraceAddressSnapRangePropertyMapSpace<Long, DBTraceSymbolIDEntry> idSpace =
				manager.idMap.getForSpace(range.getRange().getAddressSpace(), false);
			if (idSpace == null) {
				return;
			}
			Object[] entries =
				idSpace.reduce(TraceAddressSnapRangeQuery.intersecting(range))
						.entries()
						.toArray();
			for (Object obj : entries) {
				@SuppressWarnings("unchecked")
				Entry<TraceAddressSnapRange, Long> ent =
					(Entry<TraceAddressSnapRange, Long>) obj;
				long id = ent.getValue();
				if (DBTraceSymbolManager.unpackTypeID(id) != typeID) {
					continue;
				}
				rangeCache.add(new ImmutablePair<>(ent.getKey(),
					store.getObjectAt(DBTraceSymbolManager.unpackKey(id))));
			}
			rangeCache.sort(
				Comparator.comparing(Entry::getValue, TraceSymbolManager.PRIMALITY_COMPARATOR));
		}

		@Override
		protected Collection<? extends T> doGetContaining(GetSymbolsKey key) {
			if (key.thread != null) {
				List<T> result =
					new ArrayList<>(getIntersecting(Lifespan.at(key.snap),
						new AddressRangeImpl(key.addr, key.addr), key.includeDynamic, true));
				result.sort(TraceSymbolManager.PRIMALITY_COMPARATOR);
				return result;
			}
			ensureInCachedRange(key.snap, key.addr);
			// NOTE: loadRangeCache pre-sorts
			return getAllInRangeCacheContaining(key);
		}
	}

	protected final CacheForGetSymbolsAtQueries cacheForAt = new CacheForGetSymbolsAtQueries();

	public AbstractDBTraceSymbolSingleTypeWithLocationView(DBTraceSymbolManager manager,
			byte typeID, DBCachedObjectStore<T> store) {
		super(manager, typeID, store);
	}

	public T getChildWithNameAt(String name, long snap, Address address,
			TraceNamespaceSymbol parent) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			DBTraceNamespaceSymbol dbnsParent = manager.assertIsMine((Namespace) parent);
			// TODO: Does this include dynamic symbols?
			for (T symbol : getIntersecting(Lifespan.at(snap),
				new AddressRangeImpl(address, address), false, true)) {
				if (symbol.parentID != dbnsParent.getID()) {
					continue;
				}
				if (!name.equals(symbol.name)) {
					continue;
				}
				return symbol;
			}
			return null;
		}
	}

	/**
	 * Get the symbols at the given snap and address, starting with the primary
	 * 
	 * @param snap the snapshot key
	 * @param address the address
	 * @param includeDynamicSymbols true to include dynamic symbols
	 * @return the collection
	 */
	public Collection<? extends T> getAt(long snap, Address address,
			boolean includeDynamicSymbols) {
		try (LockHold hold = getManager().getTrace().lockRead()) {
			// TODO: Does "at" here work like "containing"? I suspect not....
			return cacheForAt
					.getContaining(new GetSymbolsKey(null, snap, address, includeDynamicSymbols));
		}
	}

	/**
	 * Get intersecting things in no particular order
	 * 
	 * @param span the span of snapshots
	 * @param range the range of addresses
	 * @param includeDynamicSymbols true to include dynamic symbols
	 * @return the collection
	 */
	public Collection<? extends T> getIntersecting(Lifespan span, AddressRange range,
			boolean includeDynamicSymbols) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			DBTraceAddressSnapRangePropertyMapSpace<Long, DBTraceSymbolIDEntry> space =
				manager.idMap.get(range.getAddressSpace(), false);
			if (space == null) {
				return Collections.emptyList();
			}
			return new LazyCollection<>(() -> {
				return space.reduce(TraceAddressSnapRangeQuery.intersecting(range, span))
						.values()
						.stream()
						.filter(s -> DBTraceSymbolManager.unpackTypeID(s) == this.typeID)
						.map(s -> store.getObjectAt(DBTraceSymbolManager.unpackKey(s)));
			});
		}
	}

	public Collection<? extends T> getIntersecting(Lifespan span, AddressRange range,
			boolean includeDynamicSymbols, boolean forward) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			DBTraceAddressSnapRangePropertyMapSpace<Long, DBTraceSymbolIDEntry> space =
				manager.idMap.get(range.getAddressSpace(), false);
			if (space == null) {
				return Collections.emptyList();
			}
			return new LazyCollection<T>(() -> {
				return space.reduce(TraceAddressSnapRangeQuery.intersecting(range, span)
						.starting(forward
								? Rectangle2DDirection.LEFTMOST
								: Rectangle2DDirection.RIGHTMOST))
						.orderedValues()
						.stream()
						.filter(s -> DBTraceSymbolManager.unpackTypeID(s) == this.typeID)
						.map(s -> store.getObjectAt(DBTraceSymbolManager.unpackKey(s)));
			});
		}
	}

	@Override
	public void invalidateCache() {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			super.invalidateCache();
			cacheForAt.invalidate();
		}
	}
}
