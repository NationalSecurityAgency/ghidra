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

import java.util.Arrays;
import java.util.Collection;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSetView;

/**
 * A lazily computed {@link AddressSetView} defined as the union of many given
 * {@link AddressSetView}s.
 * <p>
 * This is equivalent to using {@link AddressSetView#union(AddressSetView)}, but does not
 * materialize the difference. The choice of one over the other depends on the number of ranges in
 * the inputs and the frequency of use of the result. With few ranges, or in cases where you need to
 * access the entire result, anyway, just use the normal {@link AddressRange}. In cases with many,
 * many ranges and where only a small part of the result needs to be computed, use this view. It may
 * also be advantageous to use this if the inputs are themselves computed lazily.
 * <p>
 * This follows the conventions expected of an {@link AddressSetView} in that the returned ranges
 * are disjoint. Thus, it will combine intersecting and abutting ranges from among the inputs. For
 * example, the union of [[1,2]] and [[3,4]] is [[1,4]].
 */
public class UnionAddressSetView extends AbstractAddressSetView {
	private final Collection<AddressSetView> views;

	/**
	 * Construct the union of the given address set views
	 * 
	 * @param views the input sets
	 */
	public UnionAddressSetView(AddressSetView... views) {
		this(Arrays.asList(views));
	}

	/**
	 * Construct the union of the given address set views
	 * 
	 * @param views the input sets
	 */
	public UnionAddressSetView(Collection<AddressSetView> views) {
		this.views = views;
	}

	@Override
	public boolean contains(Address addr) {
		for (AddressSetView v : views) {
			if (v.contains(addr)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean isEmpty() {
		for (AddressSetView v : views) {
			if (!v.isEmpty()) {
				return false;
			}
		}
		return true;
	}

	@Override
	public Address getMinAddress() {
		Address result = null;
		for (AddressSetView v : views) {
			Address candMin = v.getMinAddress();
			if (candMin == null) {
				continue;
			}
			if (result == null) {
				result = candMin;
				continue;
			}
			result = cmin(result, candMin);
		}
		return result;
	}

	@Override
	public Address getMaxAddress() {
		Address result = null;
		for (AddressSetView v : views) {
			Address candMin = v.getMaxAddress();
			if (candMin == null) {
				continue;
			}
			if (result == null) {
				result = candMin;
				continue;
			}
			result = cmax(result, candMin);
		}
		return result;
	}

	@Override
	public AddressRangeIterator getAddressRanges() {
		return AddressRangeIterators.union(views.stream().map(v -> v.iterator()).toList(), true);
	}

	@Override
	public AddressRangeIterator getAddressRanges(boolean forward) {
		return AddressRangeIterators.union(views.stream().map(v -> v.iterator(forward)).toList(),
			forward);
	}

	@Override
	public AddressRangeIterator getAddressRanges(Address start, boolean forward) {
		// Need to coalesce in reverse to initialize
		AddressRangeIterator rev = AddressRangeIterators.union(
			views.stream().map(v -> v.iterator(start, !forward)).toList(), !forward);
		Address fixedStart = fixStart(rev, start, forward);
		return AddressRangeIterators
				.union(views.stream().map(v -> v.iterator(fixedStart, forward)).toList(), forward);
	}
}
