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
package ghidra.trace.model.listing;

import com.google.common.collect.Range;

import ghidra.program.model.address.*;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.util.IntersectionAddressSetView;
import ghidra.util.UnionAddressSetView;

/**
 * A view of code units stored in a trace, possibly restricted to a particular subset by type,
 * address space, and/or thread.
 * 
 * @param <T> the type of units in the view
 */
public interface TraceBaseCodeUnitsView<T extends TraceCodeUnit> {
	/**
	 * Get the total number of <em>defined</em> units in this view
	 * 
	 * @return the size
	 */
	int size();

	/**
	 * Get the nearest live unit whose start address is before the given address
	 * 
	 * @param snap the snap during which the unit must be alive
	 * @param address the address which the unit's start must precede
	 * @return the code unit, or {@code null} if it doesn't exist
	 */
	T getBefore(long snap, Address address);

	/**
	 * Get the nearest live unit whose start address is at or before the given address
	 * 
	 * @param snap the snap during which the unit must be alive
	 * @param address the address which the unit's start must equal or precede
	 * @return the code unit, or {@code null} if it doesn't exist
	 */
	T getFloor(long snap, Address address);

	/**
	 * Get the live unit containing the given address
	 * 
	 * @param snap the snap during which the unit must be alive
	 * @param address the address which the unit must contain
	 * @return the code unit, or {@code null} if it doesn't exist
	 */
	T getContaining(long snap, Address address);

	/**
	 * Get the unit starting at exactly this address
	 * 
	 * Note that the unit need only contain the given snap
	 * 
	 * @param snap the snap during which the unit must be alive
	 * @param address the unit's start address
	 * @return the code unit, or {@code null} if it doesn't exist
	 */
	T getAt(long snap, Address address);

	/**
	 * Get the nearest live unit whose start address is at or after the given address
	 * 
	 * @param snap the snap during which the unit must be alive
	 * @param address the address which the unit's start must equal or follow
	 * @return the code unit, or {@code null} if it doesn't exist
	 */
	T getCeiling(long snap, Address address);

	/**
	 * Get the nearest live unit whose start address is after the given address
	 * 
	 * @param snap the snap during which the unit must be alive
	 * @param address the address which the unit's start must follow
	 * @return the code unit, or {@code null} if it doesn't exist
	 */
	T getAfter(long snap, Address address);

	/**
	 * Get the live units whose start addresses are within the specified range
	 * 
	 * @param snap the snap during which the units must be alive
	 * @param min the minimum start address, inclusive
	 * @param max the maximum start address, inclusive
	 * @param forward true to order the units by increasing address, false for descending
	 * @return the iterable of units
	 */
	Iterable<? extends T> get(long snap, Address min, Address max, boolean forward);

	/**
	 * Get the live units whose start addresses are in the given set
	 * 
	 * @param snap the snap during which the units must be alive
	 * @param set the address set
	 * @param forward true to order the units by increasing address, false for descending
	 * @return the iterable of units
	 */
	Iterable<? extends T> get(long snap, AddressSetView set, boolean forward);

	/**
	 * Get the live units whose start addresses are within the specified range
	 * 
	 * @param snap the snap during which the units must be alive
	 * @param range the address range
	 * @param forward true to order the units by increasing address, false for descending
	 * @return the iterable of units
	 */
	Iterable<? extends T> get(long snap, AddressRange range, boolean forward);

	/**
	 * Get the live units whose start addresses are within the specified range
	 * 
	 * @param snap the snap during which the units must be alive
	 * @param start the minimum (forward) or maximum (backward) start address, inclusive
	 * @param forward true to order the units by increasing address, false for descending
	 * @return the iterable of units
	 */
	Iterable<? extends T> get(long snap, Address start, boolean forward);

	/**
	 * Get all the live units
	 * 
	 * @param snap the snap during which the units must be alive
	 * @param forward true to order the units by increasing address, false for descending
	 * @return the iterable of units
	 */
	Iterable<? extends T> get(long snap, boolean forward);

	/**
	 * Get the units which intersect the given box, in no particular order
	 * 
	 * @param tasr the box (snap range by address range)
	 * @return an iterable over the intersecting units
	 */
	Iterable<? extends T> getIntersecting(TraceAddressSnapRange tasr);

	/**
	 * Get all addresses contained by live units at the given snap
	 * 
	 * Note that the ranges in this set may not be coalesced. If a coalesced set is required, wrap
	 * it with {@link UnionAddressSetView}.
	 * 
	 * @param snap the snap during which the units must be alive
	 * @return a (lazy) view of the address set
	 */
	AddressSetView getAddressSetView(long snap);

	/**
	 * Get all addresses contained by live units at the given snap, within a restricted range
	 * 
	 * Note that the ranges in this set may not be coalesced. If a coalesced set is required, wrap
	 * it with {@link UnionAddressSetView}. The returned ranges are not necessarily enclosed by
	 * -within-, but they will intersect it. If strict enclosure is required, wrap the set with
	 * {@link IntersectionAddressSetView}.
	 * 
	 * @param snap the snap during which the units must be alive
	 * @param within the range to restrict the view
	 * @return a (lazy) view of the address set
	 */
	AddressSetView getAddressSetView(long snap, AddressRange within);

	/**
	 * Check if the given address is contained by a live unit
	 * 
	 * @param snap the snap during which the unit must be alive
	 * @param address the address to check
	 * @return true if it is contained, false if not
	 */
	boolean containsAddress(long snap, Address address);

	/**
	 * Check if the given span of snaps and range of addresses is covered by the units
	 * 
	 * This checks if every (snap, address) point within the given box is contained within some code
	 * unit in this view.
	 * 
	 * @param span the span of snaps
	 * @param range the address range
	 * @return true if covered, false otherwise
	 */
	boolean coversRange(Range<Long> span, AddressRange range);

	/**
	 * Check if the given address-snap range is covered by the units
	 * 
	 * This checks if every (snap, address) point within the given box is contained within some code
	 * unit in this view.
	 * 
	 * @param range the address-snap range
	 * @return true if covered, false otherwise
	 */
	boolean coversRange(TraceAddressSnapRange range);

	/**
	 * Check if the given span of snaps and range of addresses intersects any unit
	 * 
	 * This checks if any (snap, address) point within the given box is contained within some code
	 * unit in this view.
	 * 
	 * @param span the span of snaps
	 * @param range the address range
	 * @return true if intersecting, false otherwise
	 */
	boolean intersectsRange(Range<Long> span, AddressRange range);

	/**
	 * Check if the given span of snaps and range of addresses intersects any unit
	 * 
	 * This checks if any (snap, address) point within the given box is contained within some code
	 * unit in this view.
	 * 
	 * @param span the span of snaps
	 * @param range the address range
	 * @return true if intersecting, false otherwise
	 */
	boolean intersectsRange(TraceAddressSnapRange range);
}
