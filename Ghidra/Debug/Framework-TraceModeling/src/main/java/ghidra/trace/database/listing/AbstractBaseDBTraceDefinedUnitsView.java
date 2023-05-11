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
package ghidra.trace.database.listing;

import java.util.*;
import java.util.Map.Entry;

import ghidra.program.model.address.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.trace.database.DBTraceCacheForContainingQueries;
import ghidra.trace.database.DBTraceCacheForContainingQueries.GetKey;
import ghidra.trace.database.DBTraceCacheForSequenceQueries;
import ghidra.trace.database.context.DBTraceRegisterContextSpace;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapAddressSetView;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapSpace;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.model.*;
import ghidra.trace.model.Trace.TraceCodeChangeType;
import ghidra.trace.model.listing.TraceBaseDefinedUnitsView;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.database.spatial.rect.Rectangle2DDirection;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * An abstract implementation of a single-type view for a defined unit type
 *
 * <p>
 * This is <em>note</em> a base class of {@link DBTraceDefinedUnitsView}. This class supports the
 * implementation of one or the other: Instruction or Defined data. {@link DBTraceDefinedUnitsView}
 * is the implementation of the composition of both.
 * 
 * @param <T>
 */
public abstract class AbstractBaseDBTraceDefinedUnitsView<T extends AbstractDBTraceCodeUnit<T>>
		extends AbstractSingleDBTraceCodeUnitsView<T> {

	protected final static int CACHE_MAX_REGIONS = 1000;
	protected final static int CACHE_ADDRESS_BREADTH = 10000;
	protected final static int CACHE_MAX_POINTS = 10000;

	/**
	 * Cache for optimizing {@link AbstractBaseDBTraceDefinedUnitsView#getAt(long, Address)}
	 */
	protected class CacheForGetUnitContainingQueries
			extends DBTraceCacheForContainingQueries<GetKey, T, T> {

		public CacheForGetUnitContainingQueries() {
			super(CACHE_MAX_REGIONS, CACHE_ADDRESS_BREADTH, CACHE_MAX_POINTS);
		}

		@Override
		protected void loadRangeCache(TraceAddressSnapRange range) {
			rangeCache.addAll(
				mapSpace.reduce(TraceAddressSnapRangeQuery.intersecting(range)).entries());
		}

		@Override
		protected T doGetContaining(GetKey key) {
			ensureInCachedRange(key.snap, key.addr);
			return getFirstInRangeCacheContaining(key);
		}
	};

	/**
	 * Cache for optimizing {@link AbstractBaseDBTraceDefinedUnitsView#getFloor(long, Address)} and
	 * similar.
	 */
	protected class CacheForGetUnitSequenceQueries extends DBTraceCacheForSequenceQueries<T> {
		public CacheForGetUnitSequenceQueries() {
			super(CACHE_MAX_REGIONS, CACHE_ADDRESS_BREADTH);
		}

		@Override
		protected void loadCachedRegion(CachedRegion region) {
			region.load(new ArrayList<>(
				mapSpace.reduce(TraceAddressSnapRangeQuery.intersecting(region.min, region.max,
					region.snap, region.snap)).entries()));
		}

		@Override
		protected Entry<TraceAddressSnapRange, T> doFloorEntry(long snap, Address max) {
			Address spaceMin = space.space.getMinAddress();
			return mapSpace
					.reduce(TraceAddressSnapRangeQuery.intersecting(spaceMin, max, snap, snap)
							.starting(Rectangle2DDirection.RIGHTMOST))
					.firstEntry();
		}

		@Override
		protected Entry<TraceAddressSnapRange, T> doCeilingEntry(long snap, Address min) {
			Address spaceMax = space.space.getMaxAddress();
			return mapSpace
					.reduce(TraceAddressSnapRangeQuery.intersecting(min, spaceMax, snap, snap))
					.reduce(TraceAddressSnapRangeQuery.enclosed(min, spaceMax, Long.MIN_VALUE,
						Long.MAX_VALUE)
							.starting(Rectangle2DDirection.LEFTMOST))
					.firstEntry();
		}
	}

	protected final DBTraceAddressSnapRangePropertyMapSpace<T, T> mapSpace;

	protected final CacheForGetUnitContainingQueries cacheForContaining =
		new CacheForGetUnitContainingQueries();
	protected final CacheForGetUnitSequenceQueries cacheForSequence =
		new CacheForGetUnitSequenceQueries();

	/**
	 * Construct the view
	 * 
	 * @param space the space, bound to an address space
	 * @param mapSpace the map storing the actual code unit entries
	 */
	public AbstractBaseDBTraceDefinedUnitsView(DBTraceCodeSpace space,
			DBTraceAddressSnapRangePropertyMapSpace<T, T> mapSpace) {
		super(space);
		this.mapSpace = mapSpace;
	}

	@Override
	public int size() {
		return mapSpace.size();
	}

	@Override
	public boolean containsAddress(long snap, Address address) {
		// TODO: Put this through cache?
		return !mapSpace.reduce(TraceAddressSnapRangeQuery.at(address, snap)).isEmpty();
	}

	/**
	 * Subtract from cur, the boxes covered by the entries intersecting the given query box
	 * 
	 * <p>
	 * Compute C = A - B, where A B and C are sets of (possibly overlapping) boxes. A is given by
	 * {@code} cur, and B is the set of bounding boxes for entries intersecting the query box. Two
	 * temporary sets must be provided, and {@code cur} must be identical to one of them. This
	 * routine will mutate them. The returned result will be identical to one of them.
	 * 
	 * <p>
	 * If repeated subtraction is needed, the temporary sets need only be constructed once. For each
	 * subsequent round of subtraction, {@code cur} should be the returned result of the previous
	 * round. The final result is the return value of the final round.
	 * 
	 * <p>
	 * This is used in the implementation of {@link #coversRange(TraceAddressSnapRange)}.
	 * 
	 * @param span the lifespan of the query box
	 * @param range the address range of the query box
	 * @param cur the set of boxes, identical to one of the temporary working sets.
	 * @param set1 a temporary set for working
	 * @param set2 a temporary set for working
	 * @return the result of subtraction, identical to one of the temporary working sets
	 */
	protected Set<TraceAddressSnapRange> subtractFrom(Lifespan span, AddressRange range,
			Set<TraceAddressSnapRange> cur, Set<TraceAddressSnapRange> set1,
			Set<TraceAddressSnapRange> set2) {
		Set<TraceAddressSnapRange> prevLeftOver = cur;
		Set<TraceAddressSnapRange> nextLeftOver = cur == set1 ? set2 : set1;
		for (TraceAddressSnapRange tasr : mapSpace.reduce(
			TraceAddressSnapRangeQuery.intersecting(range, span)).keys()) {
			for (TraceAddressSnapRange lo : prevLeftOver) {
				if (tasr.encloses(lo)) {
					continue;
				}
				if (!lo.intersects(tasr)) {
					nextLeftOver.add(lo);
					continue;
				}
				TraceAddressSnapRange intersection = lo.intersection(tasr);
				// TODO: See how this performs in practice.
				// This could cause an explosion before a reduction....
				if (lo.getX1().compareTo(intersection.getX1()) < 0) {
					nextLeftOver.add(new ImmutableTraceAddressSnapRange(lo.getX1(),
						intersection.getX1().previous(), lo.getLifespan()));
				}
				if (lo.getX2().compareTo(intersection.getX2()) > 0) {
					nextLeftOver.add(new ImmutableTraceAddressSnapRange(intersection.getX2().next(),
						lo.getX2(), lo.getLifespan()));
				}
				if (lo.getY1().compareTo(intersection.getY1()) < 0) {
					nextLeftOver.add(new ImmutableTraceAddressSnapRange(intersection.getRange(),
						Lifespan.span(lo.getY1(), intersection.getY1() - 1)));
				}
				if (lo.getY2().compareTo(intersection.getY2()) > 0) {
					nextLeftOver.add(new ImmutableTraceAddressSnapRange(intersection.getRange(),
						Lifespan.span(intersection.getY2() + 1, lo.getY2())));
				}
			}
			if (nextLeftOver.isEmpty()) {
				return nextLeftOver;
			}

			Set<TraceAddressSnapRange> clear = prevLeftOver;
			clear.clear();
			prevLeftOver = nextLeftOver;
			nextLeftOver = clear;
		}
		return prevLeftOver;
	}

	@Override
	public boolean coversRange(Lifespan span, AddressRange range) {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			Set<TraceAddressSnapRange> set1 = new HashSet<>();
			Set<TraceAddressSnapRange> set2 = new HashSet<>();
			set1.add(new ImmutableTraceAddressSnapRange(range, span));
			Set<TraceAddressSnapRange> cur = subtractFrom(span, range, set1, set1, set2);
			return cur.isEmpty();
		}
	}

	@Override
	public boolean intersectsRange(Lifespan lifespan, AddressRange range) {
		return !mapSpace.reduce(TraceAddressSnapRangeQuery.intersecting(range, lifespan)).isEmpty();
	}

	@Override
	public T getFloor(long snap, Address max) {
		return cacheForSequence.getFloor(snap, max);
	}

	@Override
	public T getContaining(long snap, Address address) {
		return cacheForContaining.getContaining(new GetKey(snap, address));
	}

	@Override
	public T getAt(long snap, Address address) {
		T unit = getContaining(snap, address);
		if (unit == null) {
			return null;
		}
		if (!unit.getAddress().equals(address)) {
			return null;
		}
		return unit;
	}

	@Override
	public T getCeiling(long snap, Address min) {
		return cacheForSequence.getCeiling(snap, min);
	}

	@Override
	public Iterable<? extends T> get(long snap, Address min, Address max, boolean forward) {
		Address spaceMax = space.space.getMaxAddress();
		Rectangle2DDirection direction =
			forward ? Rectangle2DDirection.LEFTMOST : Rectangle2DDirection.RIGHTMOST;
		return () -> mapSpace //
				.reduce(TraceAddressSnapRangeQuery.intersecting(min, max, snap, snap)) //
				.reduce(TraceAddressSnapRangeQuery.enclosed(min, spaceMax, Long.MIN_VALUE,
					Long.MAX_VALUE).starting(direction))
				.orderedValues()
				.iterator();
	}

	@Override
	public Iterable<? extends T> getIntersecting(TraceAddressSnapRange tasr) {
		return Collections.unmodifiableCollection(
			mapSpace.reduce(TraceAddressSnapRangeQuery.intersecting(tasr)).values());
	}

	@Override
	public AddressSetView getAddressSetView(long snap, AddressRange within) {
		return new DBTraceAddressSnapRangePropertyMapAddressSetView<T>(within.getAddressSpace(),
			space.lock,
			mapSpace.reduce(TraceAddressSnapRangeQuery.intersecting(within.getMinAddress(),
				within.getMaxAddress(), snap, snap)),
			t -> true);
	}

	/**
	 * Clear the register context in the given box
	 * 
	 * @param span the lifespan of the box
	 * @param range the address range of the box
	 */
	protected void clearContext(Lifespan span, AddressRange range) {
		DBTraceRegisterContextSpace ctxSpace =
			space.trace.getRegisterContextManager().get(space, false);
		if (ctxSpace == null) {
			return;
		}
		ctxSpace.clear(span, range);
	}

	/**
	 * @see TraceBaseDefinedUnitsView#clear(Lifespan, AddressRange, boolean, TaskMonitor)
	 */
	public void clear(Lifespan span, AddressRange range, boolean clearContext,
			TaskMonitor monitor) throws CancelledException {
		long startSnap = span.lmin();
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			cacheForContaining.invalidate();
			cacheForSequence.invalidate();
			for (T unit : mapSpace.reduce(
				TraceAddressSnapRangeQuery.intersecting(range, span)).values()) {
				monitor.checkCancelled();
				if (unit.getStartSnap() < startSnap) {
					Lifespan oldSpan = unit.getLifespan();
					if (clearContext) {
						clearContext(Lifespan.span(span.lmin(), oldSpan.lmax()), unit.getRange());
					}
					unit.setEndSnap(startSnap - 1);
				}
				else {
					if (clearContext) {
						clearContext(unit.getLifespan(), unit.getRange());
					}
					unit.delete();
				}
			}
		}
	}

	/**
	 * Notify domain object listeners that a unit was removed
	 * 
	 * @param unit the removed unit
	 */
	protected void unitRemoved(T unit) {
		cacheForContaining.notifyEntryRemoved(unit.getLifespan(), unit.getRange(), unit);
		cacheForSequence.notifyEntryRemoved(unit.getLifespan(), unit.getRange(), unit);
		space.undefinedData.invalidateCache();
		space.trace.setChanged(new TraceChangeRecord<>(TraceCodeChangeType.REMOVED,
			space, unit.getBounds(), unit, null));
	}

	/**
	 * Notify domain object listeners taht a unit's lifespan changed
	 * 
	 * @param oldSpan the old snap
	 * @param unit the unit (having the new span)
	 */
	protected void unitSpanChanged(Lifespan oldSpan, T unit) {
		cacheForContaining.notifyEntryShapeChanged(unit.getLifespan(), unit.getRange(), unit);
		cacheForSequence.notifyEntryShapeChanged(unit.getLifespan(), unit.getRange(), unit);
		space.undefinedData.invalidateCache();
		space.trace.setChanged(new TraceChangeRecord<>(TraceCodeChangeType.LIFESPAN_CHANGED,
			space, unit, oldSpan, unit.getLifespan()));
	}

	/**
	 * Select a sub-lifespan from that given so that the box does not overlap an existing unit
	 * 
	 * <p>
	 * The selected lifespan will have the same start snap as that given. The box is the bounding
	 * box of a unit the client is trying to create.
	 * 
	 * @param span the lifespan of the box
	 * @param extending if applicable, the unit whose lifespan is being extended
	 * @param range the address range of the box
	 * @return the selected sub-lifespan
	 * @throws CodeUnitInsertionException if the start snap is contained in an existing unit
	 */
	protected Lifespan truncateSoonestDefined(Lifespan span, AbstractDBTraceCodeUnit<?> extending,
			AddressRange range) throws CodeUnitInsertionException {
		final Lifespan toScan;
		if (extending == null) {
			toScan = span;
		}
		else if (span.lmax() <= extending.getEndSnap()) {
			// we're shrinking or staying the same, so not possible to collide with others
			return span;
		}
		else {
			toScan = span.withMin(extending.getEndSnap() + 1);
		}
		T truncateBy =
			mapSpace.reduce(TraceAddressSnapRangeQuery.intersecting(range, toScan)
					.starting(Rectangle2DDirection.BOTTOMMOST))
					.firstValue();
		if (truncateBy == null) {
			return span;
		}
		if (truncateBy.getStartSnap() <= span.lmin()) {
			throw new CodeUnitInsertionException("Code units cannot overlap");
		}
		return span.withMax(truncateBy.getStartSnap() - 1);
	}

	protected long computeTruncatedMax(Lifespan lifespan, T extending, AddressRange range)
			throws CodeUnitInsertionException {
		// First, truncate lifespan to the next code unit when upper bound is max
		if (!lifespan.maxIsFinite()) {
			lifespan = space.instructions.truncateSoonestDefined(lifespan, extending, range);
			lifespan = space.definedData.truncateSoonestDefined(lifespan, extending, range);
		}
		// Second, truncate lifespan to the next change of bytes in the range
		DBTraceMemorySpace memSpace =
			space.trace.getMemoryManager().getMemorySpace(space.space, true);
		Lifespan fullSpan = extending == null ? lifespan : lifespan.bound(extending.getLifespan());
		long endSnap = memSpace.getFirstChange(fullSpan, range);
		if (endSnap == Long.MIN_VALUE) {
			return lifespan.lmax();
		}
		return endSnap - 1;
	}

	/**
	 * Invalidate the query-optimizing caches for this view
	 */
	public void invalidateCache() {
		cacheForContaining.invalidate();
		cacheForSequence.invalidate();
	}
}
