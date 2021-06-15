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

import java.util.Arrays;
import java.util.Collection;

import com.google.common.collect.Collections2;

import ghidra.program.model.address.*;

public class UnionAddressSetView extends AbstractAddressSetView {
	private final Collection<AddressSetView> views;

	public UnionAddressSetView(AddressSetView... views) {
		this(Arrays.asList(views));
	}

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
		return AddressRangeIterators.union(Collections2.transform(views, v -> v.iterator()), true);
	}

	@Override
	public AddressRangeIterator getAddressRanges(boolean forward) {
		return AddressRangeIterators.union(Collections2.transform(views, v -> v.iterator(forward)),
			forward);
	}

	@Override
	public AddressRangeIterator getAddressRanges(Address start, boolean forward) {
		// Need to coalesce in reverse to initialize
		AddressRangeIterator rev = AddressRangeIterators.union(
			Collections2.transform(views, v -> v.iterator(start, !forward)), !forward);
		Address fixedStart = fixStart(rev, start, forward);
		return AddressRangeIterators.union(
			Collections2.transform(views, v -> v.iterator(fixedStart, forward)), forward);
	}
}
