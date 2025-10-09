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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSetView;

/**
 * A lazily computed {@link AddressSetView} defined as the symmetric difference between two given
 * {@link AddressSetView}s.
 * <p>
 * There is no equivalent method in {@link AddressSetView}, but it could be computed using a
 * combination of {@link AddressSetView#subtract(AddressSetView)} and
 * {@link AddressSetView#union(AddressSetView)}. However, this class does not materialize the
 * result. The choice of one over the other depends on the number of ranges in the inputs and the
 * frequency of use of the result. With few ranges, or in cases where you need to access the entire
 * result, anyway, just use the normal {@link AddressRange}. In cases with many, many ranges and
 * where only a small part of the result needs to be computed, use this view. It may also be
 * advantageous to use this if the inputs are themselves computed lazily.
 */
public class SymmetricDifferenceAddressSetView extends AbstractAddressSetView {
	private final AddressSetView a;
	private final AddressSetView b;

	/**
	 * Construct the symmetric difference between two address sets
	 * 
	 * @param a the first set
	 * @param b the second set
	 */
	public SymmetricDifferenceAddressSetView(AddressSetView a, AddressSetView b) {
		this.a = a;
		this.b = b;
	}

	@Override
	public boolean contains(Address addr) {
		return a.contains(addr) ^ b.contains(addr);
	}

	@Override
	public AddressRangeIterator getAddressRanges() {
		return AddressRangeIterators.xor(a.iterator(), b.iterator(), null, true);
	}

	@Override
	public AddressRangeIterator getAddressRanges(boolean forward) {
		return AddressRangeIterators.xor(a.iterator(forward), b.iterator(forward), null, forward);
	}

	protected static Address fixStart(AddressRangeIterator rev, boolean forward) {
		if (!rev.hasNext()) {
			return null;
		}
		AddressRange rng = rev.next();
		return forward ? rng.getMinAddress() : rng.getMaxAddress();
	}

	protected static Address rewindIfBounding(AddressRangeIterator rev, Address start,
			boolean forward) {
		if (!rev.hasNext()) {
			return null;
		}
		AddressRange rng = rev.next();
		if (forward) {
			if (rng.getMaxAddress().isSuccessor(start)) {
				return rng.getMinAddress();
			}
		}
		else {
			if (start.isSuccessor(rng.getMinAddress())) {
				return rng.getMaxAddress();
			}
		}
		return null;
	}

	@Override
	public AddressRangeIterator getAddressRanges(Address start, boolean forward) {
		// Need to coalesce in reverse to initialize (XOR disjoint,connected will coalesce)
		AddressRangeIterator rev = AddressRangeIterators.xor(a.iterator(start, !forward),
			b.iterator(start, !forward), start, !forward);
		Address fixedStart = fixStart(rev, start, forward);
		// Also, something farther back than start may affect first range
		// Reverse each independently to find such a range
		Address fixA =
			rewindIfBounding(a.getAddressRanges(fixedStart, !forward), fixedStart, forward);
		if (fixA != null) {
			fixedStart = fixA;
		}
		else {
			Address fixB =
				rewindIfBounding(b.getAddressRanges(fixedStart, !forward), fixedStart, forward);
			if (fixB != null) {
				fixedStart = fixB;
			}
		}

		return AddressRangeIterators.xor(a.iterator(fixedStart, forward),
			b.iterator(fixedStart, forward), start, forward);
	}

	@Override
	public AddressRange getRangeContaining(Address address) {
		AddressRange ar = a.getRangeContaining(address);
		AddressRange br = b.getRangeContaining(address);
		if ((ar != null) == (br != null)) {
			return null;
		}
		AddressRange rng = ar != null ? ar : br;
		AddressSetView v = ar != null ? b : a;
		return DifferenceAddressSetView.truncate(rng, address, v);
	}
}
