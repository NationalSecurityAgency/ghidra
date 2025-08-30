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
import java.util.Iterator;
import java.util.stream.StreamSupport;

import generic.util.MergeSortingIterator;
import ghidra.program.model.address.*;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.listing.TraceCodeUnit;
import ghidra.util.*;

/**
 * An abstract implementation of a multi-type view, by composing other single-type views
 *
 * @param <T> the implementation type of units contained in the view
 * @param <P> the implementation type of views composed by this view
 */
public abstract class AbstractComposedDBTraceCodeUnitsView<T extends DBTraceCodeUnitAdapter, //
		P extends AbstractSingleDBTraceCodeUnitsView<? extends T>>
		extends AbstractBaseDBTraceCodeUnitsView<T> {

	/**
	 * Compare two code units for forward iteration
	 * 
	 * @param a a code unit
	 * @param b a code unit
	 * @return as in {@link Comparable#compareTo(Object)}
	 */
	protected static int compareForward(TraceCodeUnit a, TraceCodeUnit b) {
		return a.getMinAddress().compareTo(b.getMinAddress());
	}

	/**
	 * Compare two code units for backward iteration
	 * 
	 * @param a a code unit
	 * @param b a code unit
	 * @return as in {@link Comparable#compareTo(Object)}
	 */
	protected static int compareBackward(TraceCodeUnit a, TraceCodeUnit b) {
		return b.getMaxAddress().compareTo(a.getMaxAddress());
	}

	protected final Collection<P> parts;

	/**
	 * Construct a view
	 * 
	 * @param space the space, bound to an address space
	 * @param parts the single-type views composed
	 */
	public AbstractComposedDBTraceCodeUnitsView(DBTraceCodeSpace space, Collection<P> parts) {
		super(space);
		this.parts = parts;
	}

	@Override
	public int size() {
		int sum = 0;
		for (P p : parts) {
			sum += p.size();
		}
		return sum;
	}

	@Override
	public Iterable<? extends T> get(long snap, Address min, Address max, boolean forward) {
		Collection<? extends Iterator<? extends T>> itCol =
			parts.stream().map(p -> p.get(snap, min, max, forward).iterator()).toList();
		return () -> new MergeSortingIterator<T>(itCol,
			forward ? DBTraceDefinedUnitsView::compareForward
					: DBTraceDefinedUnitsView::compareBackward);
	}

	@Override
	public Iterable<? extends T> getIntersecting(TraceAddressSnapRange tasr) {
		return () -> parts.stream()
				.flatMap(p -> StreamSupport.stream(p.getIntersecting(tasr).spliterator(), false)
						.map(t -> (T) t))
				.iterator();
	}

	@Override
	public T getFloor(long snap, Address address) {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			T best = null;
			for (P p : parts) {
				T candidate = p.getFloor(snap, address);
				if (candidate == null) {
					continue;
				}
				if (candidate.getMaxAddress().compareTo(address) >= 0) {
					return candidate;
				}
				if (best == null || candidate.getMaxAddress().compareTo(best.getMaxAddress()) > 0) {
					best = candidate;
				}
			}
			return best;
		}
	}

	@Override
	public T getContaining(long snap, Address address) {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			for (P p : parts) {
				T candidate = p.getContaining(snap, address);
				if (candidate != null) {
					return candidate;
				}
			}
			return null;
		}
	}

	@Override
	public T getAt(long snap, Address address) {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			for (P p : parts) {
				T candidate = p.getAt(snap, address);
				if (candidate != null) {
					return candidate;
				}
			}
			return null;
		}
	}

	@Override
	public T getCeiling(long snap, Address address) {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			T best = null;
			for (P p : parts) {
				T candidate = p.getCeiling(snap, address);
				if (candidate == null) {
					continue;
				}
				if (candidate.getAddress().equals(address)) {
					return candidate;
				}
				if (best == null || candidate.getMinAddress().compareTo(best.getMinAddress()) < 0) {
					best = candidate;
				}
			}
			return best;
		}
	}

	@Override
	public AddressSetView getAddressSetView(long snap, AddressRange within) {
		return new UnionAddressSetView(
			parts.stream().map(p -> p.getAddressSetView(snap, within)).toList());
	}

	@Override
	public boolean containsAddress(long snap, Address address) {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			for (P p : parts) {
				if (p.containsAddress(snap, address)) {
					return true;
				}
			}
			return false;
		}
	}
}
