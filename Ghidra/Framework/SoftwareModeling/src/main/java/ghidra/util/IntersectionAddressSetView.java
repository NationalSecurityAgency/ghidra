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

import static ghidra.util.MathUtilities.cmax;
import static ghidra.util.MathUtilities.cmin;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.EmptyAddressRangeIterator;

/**
 * A lazily computed {@link AddressSetView} defined as the intersection of two given
 * {@link AddressSetView}s.
 * <p>
 * This is equivalent to using {@link AddressSetView#intersect(AddressSetView)}, but does not
 * materialize the intersection. The choice of one over the other depends on the number of ranges in
 * the inputs and the frequency of use of the result. With few ranges, or in cases where you need to
 * access the entire result, anyway, just use the normal {@link AddressRange}. In cases with many,
 * many ranges and where only a small part of the result needs to be computed, use this view. It may
 * also be advantageous to use this view if the inputs are themselves computed lazily.
 */
public class IntersectionAddressSetView extends AbstractAddressSetView {
	private final AddressSetView a;
	private final AddressSetView b;

	/**
	 * Construct the intersection of two address sets
	 * 
	 * @param a the first set
	 * @param b the second set
	 */
	public IntersectionAddressSetView(AddressSetView a, AddressSetView b) {
		this.a = a;
		this.b = b;
	}

	@Override
	public boolean contains(Address addr) {
		return a.contains(addr) && b.contains(addr);
	}

	@Override
	public boolean contains(Address start, Address end) {
		return a.contains(start, end) && b.contains(start, end);
	}

	@Override
	public boolean contains(AddressSetView rangeSet) {
		return a.contains(rangeSet) && b.contains(rangeSet);
	}

	protected Address findStart(boolean forward) {
		Address aStart;
		Address bStart;
		if (forward) {
			if ((aStart = a.getMinAddress()) == null || (bStart = b.getMinAddress()) == null) {
				return null;
			}
			return cmax(aStart, bStart);
		}
		if ((aStart = a.getMaxAddress()) == null || (bStart = b.getMaxAddress()) == null) {
			return null;
		}
		return cmin(aStart, bStart);
	}

	protected Address adjustStart(Address start, boolean forward) {
		Address aStart;
		Address bStart;
		AddressRangeIterator it;
		if (forward) {
			it = a.getAddressRanges(start, forward);
			if (!it.hasNext()) {
				return null;
			}
			aStart = it.next().getMinAddress();
			it = b.getAddressRanges(start, forward);
			if (!it.hasNext()) {
				return null;
			}
			bStart = it.next().getMinAddress();
			return cmax(aStart, bStart);
		}
		it = a.getAddressRanges(start, forward);
		if (!it.hasNext()) {
			return null;
		}
		aStart = it.next().getMaxAddress();
		it = b.getAddressRanges(start, forward);
		if (!it.hasNext()) {
			return null;
		}
		bStart = it.next().getMaxAddress();
		return cmin(aStart, bStart);
	}

	@Override
	public AddressRangeIterator getAddressRanges() {
		return getAddressRanges(true);
	}

	protected AddressRangeIterator doGetRanges(Address start, boolean forward) {
		if (start == null) {
			return new EmptyAddressRangeIterator();
		}
		return AddressRangeIterators.intersect(
			a.iterator(start, forward),
			b.iterator(start, forward), forward);
	}

	@Override
	public AddressRangeIterator getAddressRanges(boolean forward) {
		return doGetRanges(findStart(forward), forward);
	}

	@Override
	public AddressRangeIterator getAddressRanges(Address start, boolean forward) {
		return doGetRanges(adjustStart(start, forward), forward);
	}

	@Override
	public AddressRange getRangeContaining(Address address) {
		AddressRange ar = a.getRangeContaining(address);
		if (ar == null) {
			return null;
		}
		AddressRange br = b.getRangeContaining(address);
		if (br == null) {
			return null;
		}
		return ar.intersect(br);
	}
}
