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

import org.apache.commons.collections4.IteratorUtils;

import ghidra.program.model.address.*;
import ghidra.util.TwoWayBreakdownAddressRangeIterator.Which;

/**
 * Utilities for manipulating iterators over {@link AddressRange}s. Notably, this allows the
 * creation of lazily computed set operations on {@link AddressSetView}s.
 */
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

	/**
	 * Utility for satisfying the type checker. This just forwards the method calls so that an
	 * {@link Iterator} over {@link AddressRange} can be used where an {@link AddressRangeIterator}
	 * is required. If only Java had type aliasing....
	 * 
	 * @param it the iterator
	 * @return the wrapper, or the same iterator if it is already an {@link AddressRangeIterator}
	 */
	public static AddressRangeIterator castOrWrap(Iterator<AddressRange> it) {
		if (it instanceof AddressRangeIterator ari) {
			return ari;
		}
		return new WrappingAddressRangeIterator(it);
	}

	/**
	 * Create an iterator over the union of address ranges in the given iterators
	 * 
	 * @see UnionAddressSetView
	 * @param iterators the iterators to union
	 * @param forward true for forward iteration. The given iterators must all return ranges in the
	 *            order indicated by this flag.
	 * @return the iterator over the union
	 */
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

	/**
	 * Create an iterator over the difference between two address range iterators
	 * 
	 * @see DifferenceAddressSetView
	 * @param a the minuend
	 * @param b the subtrahend
	 * @param start the starting address, or null
	 * @param forward true for forward iteration. The given iterators must all return ranges in the
	 *            order indicated by this flag.
	 * @return the iterator over the difference
	 */
	public static AddressRangeIterator subtract(Iterator<AddressRange> a, Iterator<AddressRange> b,
			Address start, boolean forward) {
		return new WrappingAddressRangeIterator(IteratorUtils.transformedIterator(
			IteratorUtils.filteredIterator(new TwoWayBreakdownAddressRangeIterator(a, b, forward),
				e -> doCheckStart(e.getKey(), start, forward) && e.getValue().inSubtract()),
			e -> e.getKey()));
	}

	/**
	 * Create an iterator over the symmetric difference between two address range iterators
	 * 
	 * @see SymmetricDifferenceAddressSetView
	 * @param a the first iterator
	 * @param b the second iterator
	 * @param start the starting address, or null
	 * @param forward true for forward iteration. The given iterators must all return ranges in the
	 *            order indicated by this flag.
	 * @return the iterator over the symmetric difference
	 */
	public static AddressRangeIterator xor(Iterator<AddressRange> a, Iterator<AddressRange> b,
			Address start, boolean forward) {
		Iterator<Entry<AddressRange, Which>> eit =
			new TwoWayBreakdownAddressRangeIterator(a, b, forward);
		Iterator<Entry<AddressRange, Which>> fit =
			IteratorUtils.filteredIterator(eit, e -> e.getValue().inXor());
		Iterator<AddressRange> rit = IteratorUtils.transformedIterator(fit, e -> e.getKey());
		// Use union to coalesce just-connected ranges in opposite iterators.
		Iterator<AddressRange> uit = new UnionAddressRangeIterator(rit, forward);
		// Have to do this filter after union, otherwise parts of ranges are omitted.
		Iterator<AddressRange> result =
			IteratorUtils.filteredIterator(uit, r -> doCheckStart(r, start, forward));
		return new WrappingAddressRangeIterator(result);
	}

	/**
	 * Create an iterator over the intersection between two address range iterators
	 * 
	 * @see IntersectionAddressSetView
	 * @param a the first iterator
	 * @param b the second iterator
	 * @param forward true for forward iteration. The given iterators must all return ranges in the
	 *            order indicated by this flag.
	 * @return the iterator over the symmetric difference
	 */
	public static AddressRangeIterator intersect(Iterator<AddressRange> a, Iterator<AddressRange> b,
			boolean forward) {
		return new WrappingAddressRangeIterator(IteratorUtils.transformedIterator(
			IteratorUtils.filteredIterator(new TwoWayBreakdownAddressRangeIterator(a, b, forward),
				e -> e.getValue().inIntersect()),
			e -> e.getKey()));
	}
}
