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
package ghidra.trace.database.map;

import java.util.Iterator;
import java.util.Map.Entry;
import java.util.NoSuchElementException;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.function.Predicate;

import com.google.common.collect.Iterators;
import com.google.common.collect.Range;

import ghidra.program.model.address.*;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.util.*;
import ghidra.util.database.spatial.SpatialMap;
import ghidra.util.database.spatial.rect.Rectangle2DDirection;

public class DBTraceAddressSnapRangePropertyMapAddressSetView<T> extends AbstractAddressSetView {

	private final AddressRangeImpl fullSpace;
	private final ReadWriteLock lock;
	private final SpatialMap<TraceAddressSnapRange, T, TraceAddressSnapRangeQuery> map;
	private final Predicate<? super T> predicate;

	/**
	 * TODO Document me
	 * 
	 * The caller must reduce the map if only a certain range is desired.
	 * 
	 * @param lock
	 * @param map
	 * @param predicate
	 */
	public DBTraceAddressSnapRangePropertyMapAddressSetView(AddressSpace space, ReadWriteLock lock,
			SpatialMap<TraceAddressSnapRange, T, TraceAddressSnapRangeQuery> map,
			Predicate<? super T> predicate) {
		this.fullSpace = new AddressRangeImpl(space.getMinAddress(), space.getMaxAddress());
		this.lock = lock;
		this.map = map;
		this.predicate = predicate;
	}

	@Override
	public boolean contains(Address addr) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			for (T t : map
					.reduce(TraceAddressSnapRangeQuery.intersecting(addr, addr, Long.MIN_VALUE,
						Long.MAX_VALUE))
					.values()) {
				if (predicate.test(t)) {
					return true;
				}
			}
			return false;
		}
		catch (NoSuchElementException e) {
			return false;
		}
	}

	@Override
	public boolean contains(Address start, Address end) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return super.contains(start, end);
		}
	}

	@Override
	public boolean contains(AddressSetView rangeSet) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return super.contains(rangeSet);
		}
	}

	@Override
	public boolean isEmpty() {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			for (T t : map.values()) {
				if (predicate.test(t)) {
					return false;
				}
			}
			return true;
		}
	}

	@Override
	public Address getMinAddress() {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			for (Entry<TraceAddressSnapRange, T> entry : map
					.reduce(TraceAddressSnapRangeQuery.intersecting(fullSpace, Range.all())
							.starting(Rectangle2DDirection.LEFTMOST))
					.orderedEntries()) {
				if (predicate.test(entry.getValue())) {
					return entry.getKey().getX1();
				}
			}
		}
		return null;
	}

	@Override
	public Address getMaxAddress() {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			for (Entry<TraceAddressSnapRange, T> entry : map
					.reduce(TraceAddressSnapRangeQuery.intersecting(fullSpace, Range.all())
							.starting(Rectangle2DDirection.RIGHTMOST))
					.orderedEntries()) {
				if (predicate.test(entry.getValue())) {
					return entry.getKey().getX2();
				}
			}
		}
		return null;
	}

	@Override
	public int getNumAddressRanges() {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return super.getNumAddressRanges();
		}
	}

	@Override
	public AddressRangeIterator getAddressRanges() {
		return getAddressRanges(fullSpace.getMinAddress(), true);
	}

	@Override
	public AddressRangeIterator getAddressRanges(boolean forward) {
		return getAddressRanges(forward ? fullSpace.getMinAddress() : fullSpace.getMaxAddress(),
			forward);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Note the first range may be incomplete up when composed of connected entries, but it will at
	 * least include all the ranges ahead of the given start -- or behind the given start if forward
	 * is false. TODO: Fix that, just like {@link UnionAddressSetView}?
	 */
	@Override
	public AddressRangeIterator getAddressRanges(Address start, boolean forward) {
		if (!start.getAddressSpace().equals(fullSpace.getMinAddress().getAddressSpace())) {
			return new EmptyAddressRangeIterator();
		}
		AddressRange within = forward ? new AddressRangeImpl(start, fullSpace.getMaxAddress())
				: new AddressRangeImpl(fullSpace.getMinAddress(), start);
		Iterator<Entry<TraceAddressSnapRange, T>> mapIt = map
				.reduce(TraceAddressSnapRangeQuery.intersecting(within, Range.all())
						.starting(forward
								? Rectangle2DDirection.LEFTMOST
								: Rectangle2DDirection.RIGHTMOST))
				.orderedEntries()
				.iterator();
		Iterator<Entry<TraceAddressSnapRange, T>> fltIt =
			Iterators.filter(mapIt, e -> predicate.test(e.getValue()));
		Iterator<AddressRange> rawIt = Iterators.transform(fltIt, e -> e.getKey().getRange());
		return new UnionAddressRangeIterator(rawIt, forward);
	}

	@Override
	public long getNumAddresses() {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return super.getNumAddresses();
		}
	}

	@Override
	public boolean intersects(AddressSetView addrSet) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return super.intersects(addrSet);
		}
	}

	@Override
	public boolean intersects(Address start, Address end) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return super.intersects(start, end);
		}
	}

	@Override
	public AddressSet intersect(AddressSetView view) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return super.intersect(view);
		}
	}

	@Override
	public AddressSet intersectRange(Address start, Address end) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return super.intersectRange(start, end);
		}
	}

	@Override
	public AddressSet union(AddressSetView addrSet) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return super.union(addrSet);
		}
	}

	@Override
	public AddressSet subtract(AddressSetView addrSet) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return super.subtract(addrSet);
		}
	}

	@Override
	public AddressSet xor(AddressSetView addrSet) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return super.xor(addrSet);
		}
	}

	@Override
	public boolean hasSameAddresses(AddressSetView view) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return super.hasSameAddresses(view);
		}
	}

	@Override
	public AddressRange getFirstRange() {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return super.getFirstRange();
		}
	}

	@Override
	public AddressRange getLastRange() {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return super.getLastRange();
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Note that adjacent or overlapping ranges may be omitted if they don't also contain the
	 * address.
	 */
	@Override
	public AddressRange getRangeContaining(Address address) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return super.getRangeContaining(address);
		}
	}

	@Override
	public Address findFirstAddressInCommon(AddressSetView set) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return super.findFirstAddressInCommon(set);
		}
	}
}
