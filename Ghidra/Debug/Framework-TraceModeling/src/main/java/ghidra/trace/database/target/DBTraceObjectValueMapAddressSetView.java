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
package ghidra.trace.database.target;

import java.util.Iterator;
import java.util.Map.Entry;
import java.util.NoSuchElementException;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.function.Predicate;

import org.apache.commons.collections4.IteratorUtils;

import ghidra.program.model.address.*;
import ghidra.trace.database.target.ValueSpace.AddressDimension;
import ghidra.trace.database.target.ValueSpace.EntryKeyDimension;
import ghidra.trace.model.Lifespan;
import ghidra.util.*;
import ghidra.util.database.DBCachedObjectStoreFactory.RecAddress;
import ghidra.util.database.spatial.SpatialMap;

public class DBTraceObjectValueMapAddressSetView extends AbstractAddressSetView {

	private final AddressFactory factory;
	private final ReadWriteLock lock;
	private final SpatialMap<ValueShape, InternalTraceObjectValue, TraceObjectValueQuery> map;
	private final Predicate<? super InternalTraceObjectValue> predicate;

	/**
	 * An address set view that unions all addresses where an entry satisfying the given predicate
	 * exists.
	 * 
	 * <p>
	 * The caller may reduce the map given to this view. Reduction is preferable to using a
	 * predicate, where possible, because reduction benefits from the index.
	 * 
	 * @param factory the trace's address factory
	 * @param lock the lock on the database
	 * @param map the map
	 * @param predicate a predicate to further filter entries
	 */
	public DBTraceObjectValueMapAddressSetView(AddressFactory factory, ReadWriteLock lock,
			SpatialMap<ValueShape, InternalTraceObjectValue, TraceObjectValueQuery> map,
			Predicate<? super InternalTraceObjectValue> predicate) {
		this.factory = factory;
		this.lock = lock;
		this.map = map;
		this.predicate = predicate;
	}

	@Override
	public boolean contains(Address addr) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			for (InternalTraceObjectValue value : map
					.reduce(TraceObjectValueQuery.intersecting(Lifespan.ALL,
						new AddressRangeImpl(addr, addr)))
					.values()) {
				if (predicate.test(value)) {
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
			for (InternalTraceObjectValue value : map.values()) {
				if (predicate.test(value)) {
					return false;
				}
			}
			return true;
		}
	}

	@Override
	public Address getMinAddress() {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			for (Entry<ValueShape, InternalTraceObjectValue> entry : map
					.reduce(TraceObjectValueQuery.all().starting(AddressDimension.FORWARD))
					.orderedEntries()) {
				if (predicate.test(entry.getValue())) {
					return entry.getKey().getMinAddress(factory);
				}
			}
		}
		return null;
	}

	@Override
	public Address getMaxAddress() {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			for (Entry<ValueShape, InternalTraceObjectValue> entry : map
					.reduce(TraceObjectValueQuery.all().starting(AddressDimension.BACKWARD))
					.orderedEntries()) {
				if (predicate.test(entry.getValue())) {
					return entry.getKey().getMaxAddress(factory);
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
		return doGetAddressRanges(AddressDimension.INSTANCE.absoluteMin(),
			AddressDimension.INSTANCE.absoluteMax(), true);
	}

	@Override
	public AddressRangeIterator getAddressRanges(boolean forward) {
		return doGetAddressRanges(AddressDimension.INSTANCE.absoluteMin(),
			AddressDimension.INSTANCE.absoluteMax(), forward);
	}

	protected AddressRangeIterator doGetAddressRanges(RecAddress start, RecAddress end,
			boolean forward) {
		Iterator<Entry<ValueShape, InternalTraceObjectValue>> mapIt = map
				.reduce(TraceObjectValueQuery
						.intersecting(EntryKeyDimension.INSTANCE.absoluteMin(),
							EntryKeyDimension.INSTANCE.absoluteMax(), Lifespan.ALL, start, end)
						.starting(forward ? AddressDimension.FORWARD : AddressDimension.BACKWARD))
				.orderedEntries()
				.iterator();
		Iterator<Entry<ValueShape, InternalTraceObjectValue>> fltIt =
			IteratorUtils.filteredIterator(mapIt, e -> predicate.test(e.getValue()));
		Iterator<AddressRange> rawIt =
			IteratorUtils.transformedIterator(fltIt, e -> e.getKey().getRange(factory));
		return new UnionAddressRangeIterator(rawIt, forward);
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
		RecAddress min = forward
				? RecAddress.fromAddress(start)
				: AddressDimension.INSTANCE.absoluteMin();
		RecAddress max = forward
				? AddressDimension.INSTANCE.absoluteMax()
				: RecAddress.fromAddress(start);
		return doGetAddressRanges(min, max, forward);
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
	 * <p>
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
