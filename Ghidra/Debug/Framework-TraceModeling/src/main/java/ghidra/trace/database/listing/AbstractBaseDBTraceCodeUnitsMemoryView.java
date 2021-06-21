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

import java.util.Collection;
import java.util.Collections;
import java.util.concurrent.locks.Lock;

import com.google.common.collect.Collections2;
import com.google.common.collect.Range;

import generic.NestedIterator;
import ghidra.program.model.address.*;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.space.DBTraceDelegatingManager;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.util.LockHold;

public abstract class AbstractBaseDBTraceCodeUnitsMemoryView<T extends DBTraceCodeUnitAdapter, M extends AbstractBaseDBTraceCodeUnitsView<T>>
		implements DBTraceDelegatingManager<M> {
	protected final DBTraceCodeManager manager;
	protected final Collection<M> activeSpacesView;

	public AbstractBaseDBTraceCodeUnitsMemoryView(DBTraceCodeManager manager) {
		this.manager = manager;
		this.activeSpacesView =
			Collections2.transform(manager.getActiveMemorySpaces(), this::getView);
	}

	protected abstract M getView(DBTraceCodeSpace space);

	protected T nullOrUndefined(long snap, Address address) {
		return null;
	}

	protected AddressSetView emptyOrFullAddressSetUndefined(AddressRange within) {
		return new AddressSet();
	}

	protected boolean falseOrTrueUndefined() {
		return false;
	}

	public Iterable<? extends T> emptyOrFullIterableUndefined(long snap, AddressRange range,
			boolean forward) {
		return Collections.emptyList();
	}

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

	public int size() {
		int sum = 0;
		for (M m : activeSpacesView) {
			sum += m.size();
		}
		return sum;
	}

	public T getBefore(long snap, Address address) {
		Address prev = prevAddress(address);
		if (prev == null) {
			return null;
		}
		return getFloor(snap, prev);
	}

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

	public T getContaining(long snap, Address address) {
		try (LockHold hold = LockHold.lock(readLock())) {
			M m = getForSpace(address.getAddressSpace(), false);
			if (m == null) {
				return nullOrUndefined(snap, address);
			}
			return m.getContaining(snap, address);
		}
	}

	public T getAt(long snap, Address address) {
		try (LockHold hold = LockHold.lock(readLock())) {
			M m = getForSpace(address.getAddressSpace(), false);
			if (m == null) {
				return nullOrUndefined(snap, address);
			}
			return m.getAt(snap, address);
		}
	}

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

	public T getAfter(long snap, Address address) {
		Address next = nextAddress(address);
		if (next == null) {
			return null;
		}
		return getCeiling(snap, next);
	}

	public Iterable<? extends T> get(long snap, Address min, Address max, boolean forward) {
		if (min.hasSameAddressSpace(max)) {
			return get(snap, new AddressRangeImpl(min, max), forward);
		}
		return get(snap, manager.getBaseLanguage().getAddressFactory().getAddressSet(min, max),
			forward);
	}

	public Iterable<? extends T> get(long snap, AddressSetView set, boolean forward) {
		return () -> NestedIterator.start(set.iterator(forward),
			r -> get(snap, r, forward).iterator());
	}

	public Iterable<? extends T> get(long snap, AddressRange range, boolean forward) {
		M m = getForSpace(range.getAddressSpace(), false);
		if (m == null) {
			return emptyOrFullIterableUndefined(snap, range, forward);
		}
		return m.get(snap, range, forward);
	}

	public Iterable<? extends T> get(long snap, Address start, boolean forward) {
		AddressFactory factory = manager.getBaseLanguage().getAddressFactory();
		return get(snap, DBTraceUtils.getAddressSet(factory, start, forward), forward);
	}

	public Iterable<? extends T> get(long snap, boolean forward) {
		return get(snap, manager.getBaseLanguage().getAddressFactory().getAddressSet(), forward);
	}

	public Iterable<? extends T> getIntersecting(TraceAddressSnapRange tasr) {
		M m = getForSpace(tasr.getX1().getAddressSpace(), false);
		if (m == null) {
			return emptyOrFullIterableUndefined(tasr);
		}
		return m.getIntersecting(tasr);
	}

	public AddressSetView getAddressSetView(long snap, AddressRange within) {
		M m = getForSpace(within.getAddressSpace(), false);
		if (m == null) {
			return emptyOrFullAddressSetUndefined(within);
		}
		return m.getAddressSetView(snap, within);
	}

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

	public boolean containsAddress(long snap, Address address) {
		return delegateRead(address.getAddressSpace(), m -> m.containsAddress(snap, address),
			falseOrTrueUndefined());
	}

	public boolean coversRange(Range<Long> span, AddressRange range) {
		return delegateRead(range.getAddressSpace(), m -> m.coversRange(span, range),
			falseOrTrueUndefined());
	}

	public boolean coversRange(TraceAddressSnapRange range) {
		return delegateRead(range.getRange().getAddressSpace(), m -> m.coversRange(range),
			falseOrTrueUndefined());
	}

	public boolean intersectsRange(Range<Long> span, AddressRange range) {
		return delegateRead(range.getAddressSpace(), m -> m.intersectsRange(span, range),
			falseOrTrueUndefined());
	}

	public boolean intersectsRange(TraceAddressSnapRange range) {
		return delegateRead(range.getRange().getAddressSpace(), m -> m.intersectsRange(range),
			falseOrTrueUndefined());
	}
}
