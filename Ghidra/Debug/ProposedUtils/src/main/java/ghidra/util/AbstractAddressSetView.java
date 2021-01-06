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
import java.util.List;

import ghidra.program.model.address.*;

public abstract class AbstractAddressSetView implements AddressSetView {

	protected static Address fixStart(AddressRangeIterator rev, Address start, boolean forward) {
		if (!rev.hasNext()) {
			return start;
		}
		AddressRange rng = rev.next();
		if (!rng.contains(start)) {
			return start;
		}
		return forward ? rng.getMinAddress() : rng.getMaxAddress();
	}

	@Override
	public boolean isEmpty() {
		return !iterator().hasNext();
	}

	@Override
	public boolean contains(Address start, Address end) {
		AddressRangeIterator dit = AddressRangeIterators.subtract(
			new AddressSet(start, end).iterator(), iterator(start, true), null, true);
		return !dit.hasNext();
	}

	@Override
	public boolean contains(AddressSetView rangeSet) {
		AddressRangeIterator dit = AddressRangeIterators.subtract(rangeSet.iterator(),
			iterator(rangeSet.getMinAddress(), true), null, true);
		return !dit.hasNext();
	}

	@Override
	public Address getMinAddress() {
		AddressRangeIterator it = getAddressRanges(true);
		return it.hasNext() ? it.next().getMinAddress() : null;
	}

	@Override
	public Address getMaxAddress() {
		AddressRangeIterator it = getAddressRanges(false);
		return it.hasNext() ? it.next().getMaxAddress() : null;
	}

	@Override
	public int getNumAddressRanges() {
		int count = 0;
		for (@SuppressWarnings("unused")
		AddressRange r : this) {
			count++;
		}
		return count;
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return getAddressRanges();
	}

	@Override
	public Iterator<AddressRange> iterator(boolean forward) {
		return getAddressRanges(forward);
	}

	@Override
	public Iterator<AddressRange> iterator(Address start, boolean forward) {
		return getAddressRanges(start, forward);
	}

	@Override
	public long getNumAddresses() {
		long count = 0;
		for (AddressRange r : this) {
			count += r.getLength();
		}
		return count;
	}

	@Override
	public AddressIterator getAddresses(boolean forward) {
		return new AddressIteratorAdapter(iterator(forward), forward);
	}

	@Override
	public AddressIterator getAddresses(Address start, boolean forward) {
		return new AddressIteratorAdapter(iterator(start, forward), start, forward);
	}

	@Override
	public boolean hasSameAddresses(AddressSetView view) {
		AddressRangeIterator ait = this.getAddressRanges();
		AddressRangeIterator bit = view.getAddressRanges();
		while (ait.hasNext() && bit.hasNext()) {
			AddressRange ar = ait.next();
			AddressRange br = bit.next();
			if (!ar.equals(br)) {
				return false;
			}
		}
		if (ait.hasNext() || bit.hasNext()) {
			return false;
		}
		return true;
	}

	@Override
	public AddressRange getFirstRange() {
		Iterator<AddressRange> it = iterator(true);
		return it.hasNext() ? it.next() : null;
	}

	@Override
	public AddressRange getLastRange() {
		Iterator<AddressRange> it = iterator(false);
		return it.hasNext() ? it.next() : null;
	}

	@Override
	public boolean intersects(AddressSetView addrSet) {
		AddressRangeIterator iit =
			AddressRangeIterators.intersect(this.iterator(addrSet.getMinAddress(), true),
				addrSet.iterator(this.getMinAddress(), true), true);
		return iit.hasNext();
	}

	@Override
	public boolean intersects(Address start, Address end) {
		AddressRangeIterator iit = AddressRangeIterators.intersect(this.iterator(start, true),
			List.of((AddressRange) new AddressRangeImpl(start, end)).iterator(), true);
		return iit.hasNext();
	}

	@Override
	public AddressSet intersect(AddressSetView view) {
		return new AddressSet(new IntersectionAddressSetView(this, view));
	}

	@Override
	public AddressSet intersectRange(Address start, Address end) {
		return intersect(new AddressSet(start, end));
	}

	@Override
	public AddressSet union(AddressSetView addrSet) {
		return new AddressSet(new UnionAddressSetView(this, addrSet));
	}

	@Override
	public AddressSet subtract(AddressSetView addrSet) {
		return new AddressSet(new DifferenceAddressSetView(this, addrSet));
	}

	@Override
	public AddressSet xor(AddressSetView addrSet) {
		return new AddressSet(new SymmetricDifferenceAddressSetView(this, addrSet));
	}

	@Override
	public Address findFirstAddressInCommon(AddressSetView set) {
		AddressRangeIterator iit =
			AddressRangeIterators.intersect(iterator(), set.iterator(), true);
		return iit.hasNext() ? iit.next().getMinAddress() : null;
	}

	@Override
	public AddressRange getRangeContaining(Address address) {
		AddressRangeIterator it = getAddressRanges(address, true);
		if (!it.hasNext()) {
			return null;
		}
		AddressRange rng = it.next();
		if (!rng.contains(address)) {
			return null;
		}
		return rng;
	}
}
