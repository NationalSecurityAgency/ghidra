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

import java.util.Collections;
import java.util.concurrent.locks.Lock;

import generic.NestedIterator;
import ghidra.program.model.address.*;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.space.DBTraceDelegatingManager;
import ghidra.trace.model.*;
import ghidra.trace.model.listing.TraceBaseCodeUnitsView;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.LockHold;

/**
 * An abstract implementation of {@link TraceBaseCodeUnitsView} for composing views of many address
 * spaces
 *
 * @param <T> the implementation type of the units contained in the view
 * @param <M> the implementation type of the views being composed
 */
public abstract class AbstractBaseDBTraceCodeUnitsMemoryView<T extends DBTraceCodeUnitAdapter, M extends AbstractBaseDBTraceCodeUnitsView<T>>
		implements DBTraceDelegatingManager<M> {
	protected final DBTraceCodeManager manager;

	/**
	 * Construct a composite view
	 * 
	 * @param manager the code manager, from which individual views are retrieved
	 */
	public AbstractBaseDBTraceCodeUnitsMemoryView(DBTraceCodeManager manager) {
		this.manager = manager;
	}

	public AddressSpace getSpace() {
		return null;
	}

	/**
	 * @see TraceBaseCodeUnitsView#getTrace()
	 */
	public Trace getTrace() {
		return manager.getTrace();
	}

	/**
	 * @see TraceBaseCodeUnitsView#getThread()
	 */
	public TraceThread getThread() {
		return null;
	}

	/**
	 * @see TraceBaseCodeUnitsView#getFrameLevel()
	 */
	public int getFrameLevel() {
		return 0;
	}

	/**
	 * Get the individual view from the given space
	 * 
	 * @param space the space, bound to a specific address space
	 * @return the view
	 */
	protected abstract M getView(DBTraceCodeSpace space);

	/**
	 * Create the appropriate unit (possibly caching) when there is no view or space for the given
	 * address's space
	 * 
	 * <p>
	 * Views composing undefined units should generate (possibly delegating to a view) an undefined
	 * unit. Others should leave this null.
	 * 
	 * @param snap the snap the client requested
	 * @param address the address the client requested
	 * @return the unit or null
	 */
	protected T nullOrUndefined(long snap, Address address) {
		return null;
	}

	/**
	 * The address set when there is no view or space for the given range's space
	 * 
	 * <p>
	 * Views composing undefined units should return the whole range. Others should leave this
	 * empty.
	 * 
	 * @param within the range the client requested
	 * @return the full range or empty
	 */
	protected AddressSetView emptyOrFullAddressSetUndefined(AddressRange within) {
		return new AddressSet();
	}

	/**
	 * The result of contains, covers, or intersects when there is no view or space for an address
	 * space
	 * 
	 * <p>
	 * Views composing undefined units should return true, since the address is known to be in an
	 * unpopulated space. Others should leave this false.
	 * 
	 * @return true if an undefined unit implicitly contains the address, false otherwise.
	 */
	protected boolean falseOrTrueUndefined() {
		return false;
	}

	/**
	 * The result of iteration when there is no view or space for the given range's space
	 * 
	 * <p>
	 * Views composing undefiend units should return an iterable that generates (possibly caching)
	 * undefined units. Others should leave this empty.
	 * 
	 * @param snap the snap the client requested
	 * @param range the range of iteration
	 * @param forward true to iterate forward (min to max), false for backward (max to min)
	 * @return the iterator
	 */
	public Iterable<? extends T> emptyOrFullIterableUndefined(long snap, AddressRange range,
			boolean forward) {
		return Collections.emptyList();
	}

	/**
	 * @see #emptyOrFullIterableUndefined(long, AddressRange, boolean)
	 */
	public Iterable<? extends T> emptyOrFullIterableUndefined(TraceAddressSnapRange tasr) {
		return Collections.emptyList();
	}

	@Override
	public Lock readLock() {
		return manager.readLock();
	}

	@Override
	public Lock writeLock() {
		return manager.writeLock();
	}

	@Override
	public M getForSpace(AddressSpace space, boolean createIfAbsent) {
		DBTraceCodeSpace codeSpace = manager.getForSpace(space, createIfAbsent);
		return codeSpace == null ? null : getView(codeSpace);
	}

	/**
	 * Compute the address preceding the given
	 * 
	 * <p>
	 * If this address is the minimum in its space, then this will choose the maximum address of the
	 * previous space, if it exists.
	 * 
	 * @param address the address
	 * @return the previous address or null
	 */
	protected Address prevAddress(Address address) {
		Address prev = address.previous();
		if (prev != null) {
			return prev;
		}
		AddressRangeIterator ranges =
			manager.getBaseLanguage()
					.getAddressFactory()
					.getAddressSet()
					.getAddressRanges(address,
						false);
		if (!ranges.hasNext()) {
			return null;
		}
		AddressRange prevRange = ranges.next();
		if (prevRange.contains(address)) {
			if (!ranges.hasNext()) {
				return null;
			}
			prevRange = ranges.next();
		}
		return prevRange.getMaxAddress();
	}

	/**
	 * Compute the address following the given
	 * 
	 * <p>
	 * If the address is the maximum in its space, then this will choose the minimum address of the
	 * next space, if it exists.
	 * 
	 * @return the next address or null
	 */
	protected Address nextAddress(Address address) {
		Address next = address.next();
		if (next != null) {
			return next;
		}
		AddressRangeIterator ranges =
			manager.getBaseLanguage()
					.getAddressFactory()
					.getAddressSet()
					.getAddressRanges(address,
						true);
		if (!ranges.hasNext()) {
			return null;
		}
		AddressRange nextRange = ranges.next();
		if (nextRange.contains(address)) {
			if (!ranges.hasNext()) {
				return null;
			}
			nextRange = ranges.next();
		}
		return nextRange.getMinAddress();
	}

	/**
	 * @see TraceBaseCodeUnitsView#size()
	 */
	public int size() {
		int sum = 0;
		for (DBTraceCodeSpace space : manager.getActiveMemorySpaces()) {
			sum += getView(space).size();
		}
		return sum;
	}

	/**
	 * @see TraceBaseCodeUnitsView#getBefore(long, Address)
	 */
	public T getBefore(long snap, Address address) {
		Address prev = prevAddress(address);
		if (prev == null) {
			return null;
		}
		return getFloor(snap, prev);
	}

	/**
	 * @see TraceBaseCodeUnitsView#getFloor(long, Address)
	 */
	public T getFloor(long snap, Address address) {
		try (LockHold hold = LockHold.lock(readLock())) {
			for (AddressRange range : DBTraceUtils.getAddressSet(
				manager.getBaseLanguage().getAddressFactory(), address, false)) {
				M m = getForSpace(range.getAddressSpace(), false);
				T candidate = m == null ? nullOrUndefined(snap, range.getMaxAddress())
						: m.getFloor(snap, range.getMaxAddress());
				if (candidate != null) {
					return candidate;
				}
			}
			return null;
		}
	}

	/**
	 * @see TraceBaseCodeUnitsView#getContaining(long, Address)
	 */
	public T getContaining(long snap, Address address) {
		try (LockHold hold = LockHold.lock(readLock())) {
			M m = getForSpace(address.getAddressSpace(), false);
			if (m == null) {
				return nullOrUndefined(snap, address);
			}
			return m.getContaining(snap, address);
		}
	}

	/**
	 * @see TraceBaseCodeUnitsView#getAt(long, Address)
	 */
	public T getAt(long snap, Address address) {
		try (LockHold hold = LockHold.lock(readLock())) {
			M m = getForSpace(address.getAddressSpace(), false);
			if (m == null) {
				return nullOrUndefined(snap, address);
			}
			return m.getAt(snap, address);
		}
	}

	/**
	 * @see TraceBaseCodeUnitsView#getCeiling(long, Address)
	 */
	public T getCeiling(long snap, Address address) {
		try (LockHold hold = LockHold.lock(readLock())) {
			for (AddressRange range : DBTraceUtils.getAddressSet(
				manager.getBaseLanguage().getAddressFactory(), address, true)) {
				M m = getForSpace(range.getAddressSpace(), false);
				T candidate = m == null ? nullOrUndefined(snap, range.getMinAddress())
						: m.getCeiling(snap, range.getMinAddress());
				if (candidate != null) {
					return candidate;
				}
			}
			return null;
		}
	}

	/**
	 * @see TraceBaseCodeUnitsView#getAfter(long, Address)
	 */
	public T getAfter(long snap, Address address) {
		Address next = nextAddress(address);
		if (next == null) {
			return null;
		}
		return getCeiling(snap, next);
	}

	/**
	 * @see TraceBaseCodeUnitsView#get(long, Address, Address, boolean)
	 */
	public Iterable<? extends T> get(long snap, Address min, Address max, boolean forward) {
		if (min.hasSameAddressSpace(max)) {
			return get(snap, new AddressRangeImpl(min, max), forward);
		}
		return get(snap, manager.getBaseLanguage().getAddressFactory().getAddressSet(min, max),
			forward);
	}

	/**
	 * @see TraceBaseCodeUnitsView#get(long, AddressSetView, boolean)
	 */
	public Iterable<? extends T> get(long snap, AddressSetView set, boolean forward) {
		return () -> NestedIterator.start(set.iterator(forward),
			r -> get(snap, r, forward).iterator());
	}

	/**
	 * @see TraceBaseCodeUnitsView#get(long, AddressRange, boolean)
	 */
	public Iterable<? extends T> get(long snap, AddressRange range, boolean forward) {
		M m = getForSpace(range.getAddressSpace(), false);
		if (m == null) {
			return emptyOrFullIterableUndefined(snap, range, forward);
		}
		return m.get(snap, range, forward);
	}

	/**
	 * @see TraceBaseCodeUnitsView#get(long, Address, boolean)
	 */
	public Iterable<? extends T> get(long snap, Address start, boolean forward) {
		AddressFactory factory = manager.getBaseLanguage().getAddressFactory();
		return get(snap, DBTraceUtils.getAddressSet(factory, start, forward), forward);
	}

	/**
	 * @see TraceBaseCodeUnitsView#get(long, boolean)
	 */
	public Iterable<? extends T> get(long snap, boolean forward) {
		return get(snap, manager.getBaseLanguage().getAddressFactory().getAddressSet(), forward);
	}

	/**
	 * @see TraceBaseCodeUnitsView#getIntersecting(TraceAddressSnapRange)
	 */
	public Iterable<? extends T> getIntersecting(TraceAddressSnapRange tasr) {
		M m = getForSpace(tasr.getX1().getAddressSpace(), false);
		if (m == null) {
			return emptyOrFullIterableUndefined(tasr);
		}
		return m.getIntersecting(tasr);
	}

	/**
	 * @see TraceBaseCodeUnitsView#getAddressSetView(long, AddressRange)
	 */
	public AddressSetView getAddressSetView(long snap, AddressRange within) {
		M m = getForSpace(within.getAddressSpace(), false);
		if (m == null) {
			return emptyOrFullAddressSetUndefined(within);
		}
		return m.getAddressSetView(snap, within);
	}

	/**
	 * @see TraceBaseCodeUnitsView#getAddressSetView(long)
	 */
	public AddressSetView getAddressSetView(long snap) {
		AddressSet result = new AddressSet();
		for (AddressRange range : manager.getBaseLanguage().getAddressFactory().getAddressSet()) {
			M m = getForSpace(range.getAddressSpace(), false);
			if (m == null) {
				result.add(emptyOrFullAddressSetUndefined(range));
			}
			else {
				result.add(m.getAddressSetView(snap));
			}
		}
		return result;
	}

	/**
	 * @see TraceBaseCodeUnitsView#containsAddress(long, Address)
	 */
	public boolean containsAddress(long snap, Address address) {
		return delegateRead(address.getAddressSpace(), m -> m.containsAddress(snap, address),
			falseOrTrueUndefined());
	}

	/**
	 * @see TraceBaseCodeUnitsView#coversRange(Lifespan, AddressRange)
	 */
	public boolean coversRange(Lifespan span, AddressRange range) {
		return delegateRead(range.getAddressSpace(), m -> m.coversRange(span, range),
			falseOrTrueUndefined());
	}

	/**
	 * @see TraceBaseCodeUnitsView#coversRange(TraceAddressSnapRange)
	 */
	public boolean coversRange(TraceAddressSnapRange range) {
		return delegateRead(range.getRange().getAddressSpace(), m -> m.coversRange(range),
			falseOrTrueUndefined());
	}

	/**
	 * @see TraceBaseCodeUnitsView#intersectsRange(Lifespan, AddressRange)
	 */
	public boolean intersectsRange(Lifespan span, AddressRange range) {
		return delegateRead(range.getAddressSpace(), m -> m.intersectsRange(span, range),
			falseOrTrueUndefined());
	}

	/**
	 * @see TraceBaseCodeUnitsView#intersectsRange(TraceAddressSnapRange)
	 */
	public boolean intersectsRange(TraceAddressSnapRange range) {
		return delegateRead(range.getRange().getAddressSpace(), m -> m.intersectsRange(range),
			falseOrTrueUndefined());
	}
}
