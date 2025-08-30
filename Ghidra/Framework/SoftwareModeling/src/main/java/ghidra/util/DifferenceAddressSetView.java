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
package ghidra.util;

import java.util.Iterator;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSetView;

/**
 * A lazily computed {@link AddressSetView} defined as the difference between two given
 * {@link AddressSetView}s.
 * <p>
 * This is equivalent to using {@link AddressSetView#subtract(AddressSetView)}, but does not
 * materialize the difference. The choice of one over the other depends on the number of ranges in
 * the inputs and the frequency of use of the result. With few ranges, or in cases where you need to
 * access the entire result, anyway, just use the normal {@link AddressRange}. In cases with many,
 * many ranges and where only a small part of the result needs to be computed, use this view. It may
 * also be advantageous to use this view if the inputs are themselves computed lazily.
 */
public class DifferenceAddressSetView extends AbstractAddressSetView {
	private final AddressSetView a;
	private final AddressSetView b;

	/**
	 * Construct the difference between two address sets
	 * 
	 * @param a the minuend
	 * @param b the subtrahend
	 */
	public DifferenceAddressSetView(AddressSetView a, AddressSetView b) {
		this.a = a;
		this.b = b;
	}

	@Override
	public boolean contains(Address addr) {
		return a.contains(addr) && !b.contains(addr);
	}

	@Override
	public boolean contains(Address start, Address end) {
		return a.contains(start, end) && !b.intersects(start, end);
	}

	@Override
	public boolean contains(AddressSetView rangeSet) {
		return a.contains(rangeSet) && !b.intersects(rangeSet);
	}

	@Override
	public AddressRangeIterator getAddressRanges() {
		return AddressRangeIterators.subtract(a.iterator(), b.iterator(), null, true);
	}

	@Override
	public AddressRangeIterator getAddressRanges(boolean forward) {
		return AddressRangeIterators.subtract(a.iterator(forward), b.iterator(forward), null,
			forward);
	}

	@Override
	public AddressRangeIterator getAddressRanges(Address start, boolean forward) {
		// A range preceding the start in the second set may affect the first range 
		Iterator<AddressRange> rev = b.iterator(start, !forward);
		Address bStart;
		if (rev.hasNext()) {
			bStart = forward ? rev.next().getMinAddress() : rev.next().getMaxAddress();
		}
		else {
			bStart = start;
		}
		return AddressRangeIterators.subtract(a.iterator(start, forward),
			b.iterator(bStart, forward), start, forward);
	}

	static AddressRange truncate(AddressRange rng, Address address, AddressSetView v) {
		AddressRangeIterator prevIt = v.getAddressRanges(address, false);
		AddressRange prev = prevIt.hasNext() ? prevIt.next() : null;
		AddressRangeIterator nextIt = v.getAddressRanges(address, true);
		AddressRange next = nextIt.hasNext() ? nextIt.next() : null;

		boolean truncPrev = prev != null && prev.intersects(rng);
		boolean truncNext = next != null && next.intersects(rng);
		if (!truncPrev && !truncNext) {
			return rng;
		}
		Address min = truncPrev ? prev.getMaxAddress().next() : rng.getMinAddress();
		Address max = truncNext ? next.getMinAddress().previous() : rng.getMaxAddress();
		return new AddressRangeImpl(min, max);
	}

	@Override
	public AddressRange getRangeContaining(Address address) {
		AddressRange rng = a.getRangeContaining(address);
		if (rng == null) {
			return null;
		}
		AddressRange sub = b.getRangeContaining(address);
		if (sub != null) {
			return null;
		}
		return truncate(rng, address, b);
	}
}
