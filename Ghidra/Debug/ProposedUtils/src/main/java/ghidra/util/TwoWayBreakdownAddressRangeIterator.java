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

import static ghidra.util.ComparatorMath.cmax;
import static ghidra.util.ComparatorMath.cmin;

import java.util.Iterator;
import java.util.Map.Entry;

import generic.util.PeekableIterator;
import ghidra.program.model.address.*;
import ghidra.util.TwoWayBreakdownAddressRangeIterator.Which;

public class TwoWayBreakdownAddressRangeIterator
		extends AbstractPeekableIterator<Entry<AddressRange, Which>> {

	public enum Which {
		LEFT(true, false), RIGHT(false, true), BOTH(true, true);

		private Which(boolean includesLeft, boolean includesRight) {
			this.includesLeft = includesLeft;
			this.includesRight = includesRight;
		}

		public final boolean includesLeft;
		public final boolean includesRight;

		public boolean inSubtract() {
			return this == LEFT;
		}

		public boolean inXor() {
			return this == LEFT || this == RIGHT;
		}

		public boolean inIntersect() {
			return this == BOTH;
		}
	}

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

	private Address cur = null; // max/min address of next range expected

	private final MyEntry entry = new MyEntry();

	public TwoWayBreakdownAddressRangeIterator(Iterator<AddressRange> lit,
			Iterator<AddressRange> rit, boolean forward) {
		this.lit = PeekableIterators.castOrWrap(lit);
		this.rit = PeekableIterators.castOrWrap(rit);
		this.forward = forward;

		if (this.lit.hasNext()) {
			cur = getStart(this.lit.peek());
		}
		if (this.rit.hasNext()) {
			Address a = getStart(this.rit.peek());
			cur = cur == null ? a : first(cur, a);
		}
	}

	private Address getBefore(AddressRange r) {
		return forward ? r.getMinAddress().previous() : r.getMaxAddress().next();
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
			cur = getAfter(entry.key);
			return entry;
		}
		if (!ln && rn) {
			entry.key = truncateRange(rit.next());
			entry.val = Which.RIGHT;
			cur = getAfter(entry.key);
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
			cur = getAfter(entry.key);
			return entry;
		}
		if (lc && !rc) {
			Address beg = getStart(lit.peek());
			Address end = first(getEnd(lit.peek()), getBefore(rit.peek()));
			entry.key = truncateRange(beg, end);
			entry.val = Which.LEFT;
			cur = getAfter(entry.key);
			return entry;
		}
		if (!lc && rc) {
			Address beg = getStart(rit.peek());
			Address end = first(getEnd(rit.peek()), getBefore(lit.peek()));
			entry.key = truncateRange(beg, end);
			entry.val = Which.RIGHT;
			cur = getAfter(entry.key);
			return entry;
		}
		throw new AssertionError();
	}
}
