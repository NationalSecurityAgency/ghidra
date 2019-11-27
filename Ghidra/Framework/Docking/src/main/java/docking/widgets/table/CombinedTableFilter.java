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
package docking.widgets.table;

import java.util.*;

/**
 * Combines multiple Table Filters into a single TableFilter that can be applied.  All contained
 * filters must pass for this combined filter to pass.
 *
 * @param <T> the type of table row objects.
 */
public class CombinedTableFilter<T> implements TableFilter<T> {

	private final List<TableFilter<T>> filters = new ArrayList<>();

	public CombinedTableFilter(TableFilter<T> filter1, TableFilter<T> filter2,
			TableFilter<T> filter3) {

		addIfNotNull(filter1);
		addIfNotNull(filter2);
		addIfNotNull(filter3);
	}

	private void addIfNotNull(TableFilter<T> filter) {
		if (filter != null) {
			filters.add(filter);
		}
	}

	@Override
	public boolean acceptsRow(T rowObject) {
		for (TableFilter<T> tableFilter : filters) {
			if (!tableFilter.acceptsRow(rowObject)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public boolean isEmpty() {
		return filters.isEmpty();
	}

	/**
	 * Returns the number of sub-filters in this combined filter.
	 *
	 * @return  the number of sub-filters in this combined filter.
	 */
	public int getFilterCount() {
		return filters.size();
	}

	/**
	 * Returns the filter at the given index into the list of sub filters.
	 * @param index the index of the filter to retrieve
	 *
	 * @return the i'th filter.
	 */
	public TableFilter<?> getFilter(int index) {
		return filters.get(index);
	}

	@Override
	public boolean isSubFilterOf(TableFilter<?> tableFilter) {
		if (!(tableFilter instanceof CombinedTableFilter)) {
			return false;
		}

		CombinedTableFilter<?> other = (CombinedTableFilter<?>) tableFilter;
		if (getFilterCount() != other.getFilterCount()) {
			return false;
		}
		if (getFilterCount() == 0) {
			return false; // if we are both empty then not a sub filter
		}
		for (int i = 0; i < getFilterCount(); i++) {
			if (!getFilter(i).isSubFilterOf(other.getFilter(i))) {
				return false;
			}
		}
		return true;
	}

	@Override
	public boolean hasColumnFilter(int modelIndex) {
		for (TableFilter<?> tableFilter : filters) {
			if (tableFilter.hasColumnFilter(modelIndex)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public int hashCode() {
		// not meant to put in hashing structures; the data for equals may change over time
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}

		CombinedTableFilter<?> other = (CombinedTableFilter<?>) obj;
		if (!Objects.equals(filters, other.filters)) {
			return false;
		}
		return true;
	}

}
