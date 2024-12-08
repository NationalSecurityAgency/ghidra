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
package ghidra.features.bsim.gui.search.dialog;

import java.util.*;

import ghidra.features.bsim.gui.filters.BSimFilterType;
import ghidra.features.bsim.query.protocol.BSimFilter;

/**
 * Maintains the set of current filters in a nicer way than BSimFiler which breaks them down into
 * filter pieces that doesn't maintain any order.
 */
public class BSimFilterSet {
	List<FilterEntry> filterEntries = new ArrayList<>();

	public BSimFilterSet() {

	}

	private BSimFilterSet(BSimFilterSet set) {
		filterEntries.addAll(set.filterEntries);
	}

	/**
	 * Adds a filter entry to this set of filters
	 * @param filterType the BSimFilterType for the added filter
	 * @param values the list of values for the given filter type
	 */
	public void addEntry(BSimFilterType filterType, List<String> values) {
		filterEntries.add(new FilterEntry(filterType, values));
	}

	/**
	 * Returns the number of filter entries in this filter set.
	 * @return the number of filter entries in this filter set
	 */
	public int size() {
		return filterEntries.size();
	}

	/**
	 * Returns the corresponding BSimFilter for this FilterSet.
	 * @return the corresponding BSimFilter for this FilterSet
	 */
	public BSimFilter getBSimFilter() {
		BSimFilter bsimFilter = new BSimFilter();
		for (FilterEntry filterEntry : filterEntries) {
			BSimFilterType filterType = filterEntry.filterType;
			List<String> values = filterEntry.values;

			for (String filterVal : values) {
				bsimFilter.addAtom(filterType, filterVal.trim());
			}
		}
		return bsimFilter;
	}

	/**
	 * Returns a copy of this FilterSet.
	 * @return a copy of this FilterSet
	 */
	public BSimFilterSet copy() {
		return new BSimFilterSet(this);
	}

	/**
	 * Returns the filter entries contains in this FilterSet.
	 * @return the filter entries contains in this FilterSet
	 */
	public List<FilterEntry> getFilterEntries() {
		return filterEntries;
	}

	/**
	 * Removes all filter entries for the given FilterType.
	 * @param filterType the type of filters to be removed from this set
	 */
	public void removeAll(BSimFilterType filterType) {
		Iterator<FilterEntry> it = filterEntries.iterator();
		while (it.hasNext()) {
			if (it.next().filterType.equals(filterType)) {
				it.remove();
			}
		}
	}

	// A record that represents a single filter value (filter type and its values)
	public record FilterEntry(BSimFilterType filterType, List<String> values) {/**/}
}
