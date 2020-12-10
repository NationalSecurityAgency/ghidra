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

import com.google.common.collect.Range;

import generic.NestedIterator;
import ghidra.program.model.address.*;
import ghidra.trace.model.TraceAddressSnapRange;

public abstract class AbstractBaseDBTraceCodeUnitsView<T extends DBTraceCodeUnitAdapter> {

	protected final DBTraceCodeSpace space;

	public AbstractBaseDBTraceCodeUnitsView(DBTraceCodeSpace space) {
		this.space = space;
	}

	public abstract int size();

	public T getBefore(long snap, Address address) {
		Address previous = address.previous();
		if (previous == null) {
			return null;
		}
		return getFloor(snap, previous);
	}

	public abstract T getFloor(long snap, Address address);

	public abstract T getContaining(long snap, Address address);

	public abstract T getAt(long snap, Address address);

	public abstract T getCeiling(long snap, Address address);

	public T getAfter(long snap, Address address) {
		Address next = address.next();
		if (next == null) {
			return null;
		}
		return getCeiling(snap, next);
	}

	public AddressSpace getAddressSpace() {
		return space.space;
	}

	public abstract Iterable<? extends T> get(long snap, Address min, Address max, boolean forward);

	public abstract Iterable<? extends T> getIntersecting(TraceAddressSnapRange tasr);

	public Iterable<? extends T> get(long snap, AddressSetView set, boolean forward) {
		return () -> NestedIterator.start(set.iterator(forward),
			r -> this.get(snap, r, forward).iterator());
	}

	public Iterable<? extends T> get(long snap, AddressRange range, boolean forward) {
		return get(snap, range.getMinAddress(), range.getMaxAddress(), forward);
	}

	public Iterable<? extends T> get(long snap, Address start, boolean forward) {
		return forward //
				? get(snap, start, getAddressSpace().getMaxAddress(), forward)
				: get(snap, getAddressSpace().getMinAddress(), start, forward);
	}

	public Iterable<? extends T> get(long snap, boolean forward) {
		return get(snap, getAddressSpace().getMinAddress(), getAddressSpace().getMaxAddress(),
			forward);
	}

	public abstract AddressSetView getAddressSetView(long snap, AddressRange within);

	public AddressSetView getAddressSetView(long snap) {
		return getAddressSetView(snap, space.all);
	}

	public abstract boolean containsAddress(long snap, Address address);

	public abstract boolean coversRange(Range<Long> span, AddressRange range);

	public boolean coversRange(TraceAddressSnapRange range) {
		return coversRange(range.getLifespan(), range.getRange());
	}

	public abstract boolean intersectsRange(Range<Long> span, AddressRange range);

	public boolean intersectsRange(TraceAddressSnapRange range) {
		return intersectsRange(range.getLifespan(), range.getRange());
	}
}
