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

import com.google.common.collect.Collections2;
import com.google.common.collect.Iterators;

import ghidra.program.model.address.*;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.listing.TraceCodeUnit;
import ghidra.util.*;

public abstract class AbstractComposedDBTraceCodeUnitsView<T extends DBTraceCodeUnitAdapter, //
		P extends AbstractSingleDBTraceCodeUnitsView<? extends T>>
		extends AbstractBaseDBTraceCodeUnitsView<T> {

	protected static int compareForward(TraceCodeUnit a, TraceCodeUnit b) {
		return a.getMinAddress().compareTo(b.getMinAddress());
	}

	protected static int compareBackward(TraceCodeUnit a, TraceCodeUnit b) {
		return b.getMaxAddress().compareTo(a.getMaxAddress());
	}

	protected final Collection<P> parts;

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
			Collections2.transform(parts, p -> p.get(snap, min, max, forward).iterator());
		return () -> new MergeSortingIterator<T>(itCol,
			forward ? DBTraceDefinedUnitsView::compareForward
					: DBTraceDefinedUnitsView::compareBackward);
	}

	@Override
	public Iterable<? extends T> getIntersecting(TraceAddressSnapRange tasr) {
		Collection<? extends Iterator<? extends T>> itCol =
			Collections2.transform(parts, p -> p.getIntersecting(tasr).iterator());
		return () -> Iterators.concat(itCol.iterator());
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
			Collections2.transform(parts, p -> p.getAddressSetView(snap, within)));
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
