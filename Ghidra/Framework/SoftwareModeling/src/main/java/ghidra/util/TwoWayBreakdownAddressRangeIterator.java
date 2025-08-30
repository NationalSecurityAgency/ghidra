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

import java.util.Iterator;
import java.util.Map.Entry;

import generic.util.*;
import ghidra.program.model.address.*;
import ghidra.util.TwoWayBreakdownAddressRangeIterator.Which;

/**
 * An iterator that takes two iterators over address ranges and "breaks down" where they do and do
 * not overlap. Consider one iterator L that contains only [1,3], and another R that contains only
 * [2,4]. The two could be plotted:
 * 
 * <pre>
 *  1  2  3  4
 * [---L---]
 *    [---R---]
 * </pre>
 * 
 * <p>
 * This will return an iterator over range-which pairs. "Which" indicates which iterators include
 * the given range, {@link Which#LEFT}, {@link Which#RIGHT}, or {@link Which#BOTH}. There is no
 * {@code NONE}, so gaps are omitted. For the example above:
 * 
 * <pre>
 *  1  2  3  4
 * [L][-B--][R]
 * </pre>
 * 
 * <p>
 * This supports the computation of difference, symmetric difference, and intersection. <b>NOTE:</b>
 * Clients cannot save the entries returned by the iterator. The entry is only valid during
 * iteration, and it is reused by the iterator for each subsequent entry.
 */
public class TwoWayBreakdownAddressRangeIterator
		extends AbstractPeekableIterator<Entry<AddressRange, Which>> {

	/**
	 * Indicates which of the input iterators contain a range
	 */
	public enum Which {
		/** Only the left included the range */
		LEFT(true, false),
		/** Only the right included the range */
		RIGHT(false, true),
		/** Both included the range */
		BOTH(true, true);

		private Which(boolean includesLeft, boolean includesRight) {
			this.includesLeft = includesLeft;
			this.includesRight = includesRight;
		}

		/** Indicates the the left iterator includes this range */
		public final boolean includesLeft;
		/** Indicates that the right iterator includes this range */
		public final boolean includesRight;

		/**
		 * Check if this range is included in the difference: {@code left - right}
		 * 
		 * @return true if included
		 */
		public boolean inSubtract() {
			return this == LEFT;
		}

		/**
		 * Check if this range is included in the symmetric difference: {@code left Δ right}
		 * 
		 * @return true if included
		 */
		public boolean inXor() {
			return this == LEFT || this == RIGHT;
		}

		/**
		 * Check if this range is included in the intersection: {@code left ∩ right}
		 * 
		 * @return true if included
		 */
		public boolean inIntersect() {
			return this == BOTH;
		}
	}

	/**
	 * A mutable map entry
	 */
	public static class MyEntry implements Entry<AddressRange, Which> {
		private AddressRange key;
		private Which val;

		@Override
		public AddressRange getKey() {
			return key;
		}

		@Override
		public Which getValue() {
			return val;
		}

		@Override
		public Which setValue(Which value) {
			throw new UnsupportedOperationException();
		}
	}

	private final PeekableIterator<AddressRange> lit;
	private final PeekableIterator<AddressRange> rit;
	private final boolean forward;

	private AddressSpace curSpace = null;
	private Address cur = null; // max/min address of next range expected

	private final MyEntry entry = new MyEntry();

	/**
	 * Create an iterator that "breaks down" the two address range iterators.
	 * 
	 * @param lit the iterator of ranges on the left
	 * @param rit the iterator of ranges on the right
	 * @param forward true for forward iteration, false for reverse. The input iterators must be
	 *            ordered according to this flag.
	 */
	public TwoWayBreakdownAddressRangeIterator(Iterator<AddressRange> lit,
			Iterator<AddressRange> rit, boolean forward) {
		this.lit = PeekableIterators.castOrWrap(lit);
		this.rit = PeekableIterators.castOrWrap(rit);
		this.forward = forward;

		initCur();
	}

	private void initCur() {
		if (lit.hasNext()) {
			cur = getStart(this.lit.peek());
		}
		if (rit.hasNext()) {
			Address a = getStart(rit.peek());
			cur = cur == null ? a : first(cur, a);
		}
		curSpace = cur == null ? null : cur.getAddressSpace();
	}

	private Address getBefore(AddressRange r, AddressSpace beforeSpace) {
		if (forward) {
			Address prev = r.getMinAddress().previous();
			if (prev != null) {
				return prev;
			}
			return beforeSpace.getMaxAddress();
		}
		Address next = r.getMaxAddress().next();
		if (next != null) {
			return next;
		}
		return beforeSpace.getMinAddress();
	}

	private Address getStart(AddressRange r) {
		return forward ? r.getMinAddress() : r.getMaxAddress();
	}

	private Address getEnd(AddressRange r) {
		return forward ? r.getMaxAddress() : r.getMinAddress();
	}

	private Address getAfter(AddressRange r) {
		return forward ? r.getMaxAddress().next() : r.getMinAddress().previous();
	}

	private Address first(Address a, Address b) {
		return forward ? cmin(a, b) : cmax(a, b);
	}

	private Address last(Address a, Address b) {
		return forward ? cmax(a, b) : cmin(a, b);
	}

	private int cmp(Address a, Address b) {
		return forward ? a.compareTo(b) : b.compareTo(a);
	}

	private AddressRange truncateRange(Address beg, Address end) {
		return forward ? new AddressRangeImpl(cmax(cur, beg), end)
				: new AddressRangeImpl(end, cmin(cur, beg));
	}

	private AddressRange truncateRange(AddressRange rng) {
		if (!rng.contains(cur)) {
			return rng;
		}
		return forward ? truncateRange(rng.getMinAddress(), rng.getMaxAddress())
				: truncateRange(rng.getMaxAddress(), rng.getMinAddress());
	}

	private void findSuitable(PeekableIterator<AddressRange> it) {
		while (it.hasNext() && cmp(getEnd(it.peek()), cur) < 0) {
			it.next();
		}
	}

	private void advanceSpace(PeekableIterator<AddressRange> it) {
		while (it.hasNext() && it.peek().getAddressSpace() == curSpace) {
			it.next();
		}
	}

	private void advanceSpace() {
		advanceSpace(lit);
		advanceSpace(rit);
	}

	private void advance() {
		cur = getAfter(entry.key);
		if (cur == null) { // ended at an extreme
			advanceSpace();
			initCur();
		}
	}

	@Override
	protected Entry<AddressRange, Which> seekNext() {
		if (cur == null) {
			return null;
		}
		findSuitable(lit);
		findSuitable(rit);

		boolean ln = lit.hasNext();
		boolean rn = rit.hasNext();
		if (!ln && !rn) {
			return null;
		}
		if (ln && !rn) {
			entry.key = truncateRange(lit.next());
			entry.val = Which.LEFT;
			advance();
			return entry;
		}
		if (!ln && rn) {
			entry.key = truncateRange(rit.next());
			entry.val = Which.RIGHT;
			advance();
			return entry;
		}

		// Advance past empty space
		Address adv = first(getStart(lit.peek()), getStart(rit.peek()));
		cur = cur == null ? adv : last(cur, adv);

		boolean lc = cmp(getStart(lit.peek()), cur) <= 0;
		boolean rc = cmp(getStart(rit.peek()), cur) <= 0;
		if (lc && rc) {
			Address beg = last(getStart(lit.peek()), getStart(rit.peek()));
			Address end = first(getEnd(lit.peek()), getEnd(rit.peek()));
			entry.key = truncateRange(beg, end);
			entry.val = Which.BOTH;
			advance();
			return entry;
		}
		if (lc && !rc) {
			Address beg = getStart(lit.peek());
			Address end = first(getEnd(lit.peek()), getBefore(rit.peek(), beg.getAddressSpace()));
			entry.key = truncateRange(beg, end);
			entry.val = Which.LEFT;
			advance();
			return entry;
		}
		if (!lc && rc) {
			Address beg = getStart(rit.peek());
			Address end = first(getEnd(rit.peek()), getBefore(lit.peek(), beg.getAddressSpace()));
			entry.key = truncateRange(beg, end);
			entry.val = Which.RIGHT;
			advance();
			return entry;
		}
		throw new AssertionError();
	}
}
