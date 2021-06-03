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

import java.util.Collection;
import java.util.Iterator;
import java.util.Map.Entry;

import com.google.common.collect.Iterators;

import ghidra.program.model.address.*;
import ghidra.util.TwoWayBreakdownAddressRangeIterator.Which;

public enum AddressRangeIterators {
	;

	private static class WrappingAddressRangeIterator implements AddressRangeIterator {
		private final Iterator<AddressRange> it;

		public WrappingAddressRangeIterator(Iterator<AddressRange> it) {
			this.it = it;
		}

		@Override
		public boolean hasNext() {
			return it.hasNext();
		}

		@Override
		public AddressRange next() {
			return it.next();
		}

		@Override
		public Iterator<AddressRange> iterator() {
			return this;
		}
	}

	public static AddressRangeIterator castOrWrap(Iterator<AddressRange> it) {
		if (it instanceof AddressRangeIterator) {
			return (AddressRangeIterator) it;
		}
		return new WrappingAddressRangeIterator(it);
	}

	public static AddressRangeIterator union(Collection<Iterator<AddressRange>> iterators,
			boolean forward) {
		return new UnionAddressRangeIterator(iterators, forward);
	}

	protected static boolean doCheckStart(AddressRange range, Address start, boolean forward) {
		if (start == null) {
			return true;
		}
		return forward ? range.getMaxAddress().compareTo(start) >= 0
				: range.getMinAddress().compareTo(start) <= 0;
	}

	public static AddressRangeIterator subtract(Iterator<AddressRange> a, Iterator<AddressRange> b,
			Address start, boolean forward) {
		return new WrappingAddressRangeIterator(Iterators.transform(
			Iterators.filter(new TwoWayBreakdownAddressRangeIterator(a, b, forward),
				e -> doCheckStart(e.getKey(), start, forward) && e.getValue().inSubtract()),
			e -> e.getKey()));
	}

	public static AddressRangeIterator xor(Iterator<AddressRange> a, Iterator<AddressRange> b,
			Address start, boolean forward) {
		Iterator<Entry<AddressRange, Which>> eit =
			new TwoWayBreakdownAddressRangeIterator(a, b, forward);
		Iterator<Entry<AddressRange, Which>> fit = Iterators.filter(eit, e -> e.getValue().inXor());
		Iterator<AddressRange> rit = Iterators.transform(fit, e -> e.getKey());
		// Use union to coalesce just-connected ranges in opposite iterators.
		Iterator<AddressRange> uit = new UnionAddressRangeIterator(rit, forward);
		// Have to do this filter after union, otherwise parts of ranges are omitted.
		Iterator<AddressRange> result = Iterators.filter(uit, r -> doCheckStart(r, start, forward));
		return new WrappingAddressRangeIterator(result);
	}

	public static AddressRangeIterator intersect(Iterator<AddressRange> a, Iterator<AddressRange> b,
			boolean forward) {
		return new WrappingAddressRangeIterator(Iterators.transform(
			Iterators.filter(new TwoWayBreakdownAddressRangeIterator(a, b, forward),
				e -> e.getValue().inIntersect()),
			e -> e.getKey()));
	}
}
