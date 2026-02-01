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

import java.util.Comparator;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;

/**
 * Comparators used for sorting address ranges
 */
public enum AddressRangeComparators implements Comparator<AddressRange> {
	/**
	 * Compare ranges by their minimum address and order them smallest first.
	 */
	FORWARD {
		@Override
		public int compare(AddressRange a, AddressRange b) {
			return a.getMinAddress().compareTo(b.getMinAddress());
		}
	},
	/**
	 * Compare ranges by their maximum address and order them largest first.
	 * 
	 * @implNote Which address is compared might not ordinarily matter, since {@link AddressSet}
	 *           requires a disjoint union of ranges. However, these comparators often compare
	 *           ranges from different sets, e.g., in order to merge two or more iterators. Thus, in
	 *           reverse, we want to ensure ranges are ordered by their <em>maximum</em> address.
	 */
	BACKWARD {
		@Override
		public int compare(AddressRange a, AddressRange b) {
			return b.getMaxAddress().compareTo(a.getMaxAddress());
		}
	};
}
