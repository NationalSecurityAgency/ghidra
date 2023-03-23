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

import generic.NestedIterator;
import ghidra.program.model.address.*;
import ghidra.trace.model.*;
import ghidra.trace.model.listing.TraceBaseCodeUnitsView;
import ghidra.trace.model.thread.TraceThread;

/**
 * An abstract implementation of a {@link TraceBaseCodeUnitsView} for a specific address space
 *
 * <p>
 * Note that this class does not declare {@link TraceBaseCodeUnitsView} as an implemented interface,
 * thought it does implement it structurally. If it were implemented nominally, the realizations
 * would inherit the same interface twice, with different type parameters, which is not allowed.
 *
 * @param <T> the implementation type of the units contained in the view
 */
public abstract class AbstractBaseDBTraceCodeUnitsView<T extends DBTraceCodeUnitAdapter> {

	protected final DBTraceCodeSpace space;

	/**
	 * Construct a view
	 * 
	 * @param space the space, bound to an address space
	 */
	public AbstractBaseDBTraceCodeUnitsView(DBTraceCodeSpace space) {
		this.space = space;
	}

	public AddressSpace getSpace() {
		return getAddressSpace();
	}

	/**
	 * Get the address space for this view
	 * 
	 * @return the address space
	 */
	protected AddressSpace getAddressSpace() {
		return space.space;
	}

	/**
	 * @see TraceBaseCodeUnitsView#getTrace()
	 */
	public Trace getTrace() {
		return space.manager.getTrace();
	}

	/**
	 * @see TraceBaseCodeUnitsView#getThread()
	 */
	public TraceThread getThread() {
		return space.getThread();
	}

	/**
	 * @see TraceBaseCodeUnitsView#getFrameLevel()
	 */
	public int getFrameLevel() {
		return space.getFrameLevel();
	}

	/**
	 * @see TraceBaseCodeUnitsView#size()
	 */
	public abstract int size();

	/**
	 * @see TraceBaseCodeUnitsView#getBefore(long, Address)
	 */
	public T getBefore(long snap, Address address) {
		Address previous = address.previous();
		if (previous == null) {
			return null;
		}
		return getFloor(snap, previous);
	}

	/**
	 * @see TraceBaseCodeUnitsView#getFloor(long, Address)
	 */
	public abstract T getFloor(long snap, Address address);

	/**
	 * @see TraceBaseCodeUnitsView#getContaining(long, Address)
	 */
	public abstract T getContaining(long snap, Address address);

	/**
	 * @see TraceBaseCodeUnitsView#getAt(long, Address)
	 */
	public abstract T getAt(long snap, Address address);

	/**
	 * @see TraceBaseCodeUnitsView#getCeiling(long, Address)
	 */
	public abstract T getCeiling(long snap, Address address);

	/**
	 * @see TraceBaseCodeUnitsView#getAfter(long, Address)
	 */
	public T getAfter(long snap, Address address) {
		Address next = address.next();
		if (next == null) {
			return null;
		}
		return getCeiling(snap, next);
	}

	/**
	 * @see TraceBaseCodeUnitsView#get(long, Address, Address, boolean)
	 */
	public abstract Iterable<? extends T> get(long snap, Address min, Address max, boolean forward);

	/**
	 * @see TraceBaseCodeUnitsView#getIntersecting(TraceAddressSnapRange)
	 */
	public abstract Iterable<? extends T> getIntersecting(TraceAddressSnapRange tasr);

	/**
	 * @see TraceBaseCodeUnitsView#get(long, AddressSetView, boolean)
	 */
	public Iterable<? extends T> get(long snap, AddressSetView set, boolean forward) {
		return () -> NestedIterator.start(set.iterator(forward),
			r -> this.get(snap, r, forward).iterator());
	}

	/**
	 * @see TraceBaseCodeUnitsView#get(long, AddressRange, boolean)
	 */
	public Iterable<? extends T> get(long snap, AddressRange range, boolean forward) {
		return get(snap, range.getMinAddress(), range.getMaxAddress(), forward);
	}

	/**
	 * @see TraceBaseCodeUnitsView#get(long, Address, boolean)
	 */
	public Iterable<? extends T> get(long snap, Address start, boolean forward) {
		return forward //
				? get(snap, start, getAddressSpace().getMaxAddress(), forward)
				: get(snap, getAddressSpace().getMinAddress(), start, forward);
	}

	/**
	 * @see TraceBaseCodeUnitsView#get(long, boolean)
	 */
	public Iterable<? extends T> get(long snap, boolean forward) {
		return get(snap, getAddressSpace().getMinAddress(), getAddressSpace().getMaxAddress(),
			forward);
	}

	/**
	 * @see TraceBaseCodeUnitsView#getAddressSetView(long, AddressRange)
	 */
	public abstract AddressSetView getAddressSetView(long snap, AddressRange within);

	/**
	 * @see TraceBaseCodeUnitsView#getAddressSetView(long)
	 */
	public AddressSetView getAddressSetView(long snap) {
		return getAddressSetView(snap, space.all);
	}

	/**
	 * @see TraceBaseCodeUnitsView#containsAddress(long, Address)
	 */
	public abstract boolean containsAddress(long snap, Address address);

	/**
	 * @see TraceBaseCodeUnitsView#coversRange(Lifespan, AddressRange)
	 */
	public abstract boolean coversRange(Lifespan span, AddressRange range);

	/**
	 * @see TraceBaseCodeUnitsView#coversRange(TraceAddressSnapRange)
	 */
	public boolean coversRange(TraceAddressSnapRange range) {
		return coversRange(range.getLifespan(), range.getRange());
	}

	/**
	 * @see TraceBaseCodeUnitsView#intersectsRange(Lifespan, AddressRange)
	 */
	public abstract boolean intersectsRange(Lifespan span, AddressRange range);

	/**
	 * @see TraceBaseCodeUnitsView#intersectsRange(TraceAddressSnapRange)
	 */
	public boolean intersectsRange(TraceAddressSnapRange range) {
		return intersectsRange(range.getLifespan(), range.getRange());
	}
}
