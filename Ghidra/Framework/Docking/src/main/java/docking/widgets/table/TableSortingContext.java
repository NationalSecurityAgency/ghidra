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

public class TableSortingContext<T> {

	private TableSortState sortState;
	private Comparator<T> comparator;

	public TableSortingContext(TableSortState sortState, Comparator<T> comparator) {
		this.sortState = Objects.requireNonNull(sortState);
		this.comparator = Objects.requireNonNull(comparator);
	}

	public Comparator<T> getComparator() {
		return comparator;
	}

	public TableSortState getSortState() {
		return sortState;
	}

	/**
	 * Returns true if there are no columns marked as sorted, which represents a 'no sort' state
	 * 
	 * @return true if there are no columns sorted
	 */
	public boolean isUnsorted() {
		return sortState.isUnsorted();
	}

	public boolean isReverseOf(TableSortingContext<T> otherContext) {
		int sortedColumnCount = sortState.getSortedColumnCount();
		if (sortedColumnCount != 1) {
			return false; // can only reverse a single column sort
		}

		int otherSortedColumnCount = otherContext.sortState.getSortedColumnCount();
		if (sortedColumnCount != otherSortedColumnCount) {
			return false;
		}

		Iterator<ColumnSortState> iterator = sortState.iterator();
		ColumnSortState onlyItem = iterator.next();
		int columnIndex = onlyItem.getColumnModelIndex();

		Iterator<ColumnSortState> otherIterator = otherContext.sortState.iterator();
		ColumnSortState otherOnlyItem = otherIterator.next();
		int otherColumnIndex = otherOnlyItem.getColumnModelIndex();

		// must be the same column
		if (columnIndex != otherColumnIndex) {
			return false;
		}

		// must be opposite directions
		return onlyItem.getSortDirection() != otherOnlyItem.getSortDirection();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}

		if (!(obj instanceof TableSortingContext)) {
			return false;
		}

		@SuppressWarnings("rawtypes")
		TableSortingContext other = (TableSortingContext) obj;
		if (!sortState.equals(other.sortState)) {
			return false;
		}

		return true;
// comparators do not override equals, so we can't rely on this call		
//		return comparator.equals(other.comparator);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
// see the equals methods		
//		result = prime * result + ((comparator == null) ? 0 : comparator.hashCode());
		result = prime * result + ((sortState == null) ? 0 : sortState.hashCode());
		return result;
	}

	@Override
	public String toString() {
		return sortState.toString();
	}
}
