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

import java.util.Collection;
import java.util.Iterator;

import generic.util.PeekableIterator;
import ghidra.program.model.address.*;

public class UnionAddressRangeIterator extends AbstractPeekableIterator<AddressRange>
		implements AddressRangeIterator {
	private final PeekableIterator<AddressRange> mit;
	private final boolean forward;

	/**
	 * Coalesce (by union) ranges from a single iterator
	 * 
	 * The ranges must be returned in order: in the forward direction, by increasing min address; in
	 * the reverse direction, by decreasing max address.
	 * 
	 * @param it the iterator
	 * @param forward true to coalesce in the forward direction, false for reverse
	 */
	public UnionAddressRangeIterator(Iterator<AddressRange> it, boolean forward) {
		this.mit = PeekableIterators.castOrWrap(it);
		this.forward = forward;
	}

	/**
	 * Union into a single range iterator, several range iterators
	 * 
	 * The ranges will be coalesced so that each returned range is disconnected from any other. The
	 * ranges of each iterator must be returned in order by direction. While not recommended, the
	 * ranges of each iterator may overlap, so long as they are sorted as in
	 * {@link #UnionAddressRangeIterator(Iterator, boolean)}
	 * 
	 * @param iterators the iterators to union
	 * @param forward true to union in the forward direction, false for reverse
	 */
	public UnionAddressRangeIterator(Collection<Iterator<AddressRange>> iterators,
			boolean forward) {
		this.mit = new MergeSortingIterator<AddressRange>(iterators,
			forward ? AddressRangeComparators.FORWARD : AddressRangeComparators.BACKWARD);
		this.forward = forward;
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return this;
	}

	@Override
	protected AddressRange seekNext() {
		if (!mit.hasNext()) {
			return null;
		}
		AddressRange peek = mit.peek();
		Address min = peek.getMinAddress();
		Address max = peek.getMaxAddress();
		while (true) {
			mit.next();
			if (!mit.hasNext()) {
				break;
			}
			peek = mit.peek();
			if (peek.getAddressSpace() != min.getAddressSpace()) {
				break;
			}
			if (forward) {
				Address n = max.next();
				if (n != null && peek.getMinAddress().compareTo(n) > 0) {
					break;
				}
				max = cmax(max, peek.getMaxAddress());
			}
			else {
				Address p = min.previous();
				if (p != null && peek.getMaxAddress().compareTo(p) < 0) {
					break;
				}
				min = cmin(min, peek.getMinAddress());
			}
		}
		return new AddressRangeImpl(min, max);
	}
}
