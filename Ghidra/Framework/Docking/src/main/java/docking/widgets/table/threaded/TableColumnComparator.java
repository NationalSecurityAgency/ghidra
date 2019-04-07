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
package docking.widgets.table.threaded;

import java.util.Comparator;

import docking.widgets.table.SortedTableModel;

public class TableColumnComparator<T> implements Comparator<T> {
	private ThreadedTableModel<T, ?> model;
	private final int sortColumn;
	private Comparator<Object> columnComparator;

	public TableColumnComparator(ThreadedTableModel<T, ?> model,
			Comparator<Object> columnComparator, int sortColumn) {
		this.model = model;
		this.columnComparator = columnComparator;
		this.sortColumn = sortColumn;
	}

	@Override
	public int compare(T t1, T t2) {
		if (t1 == t2) {
			return 0;
		}

		Object o1 = model.getCachedColumnValueForRow(t1, sortColumn);
		Object o2 = model.getCachedColumnValueForRow(t2, sortColumn);

		if (o1 == null || o2 == null) {
			return handleNullValues(o1, o2);
		}

		if (columnComparator != null) {
			return columnComparator.compare(o1, o2);
		}

		return SortedTableModel.DEFAULT_COMPARATOR.compare(o1, o2);
	}

	private int handleNullValues(Object o1, Object o2) {
		// If both values are null return 0
		if (o1 == null && o2 == null) {
			return 0;
		}

		if (o1 == null) { // Define null less than everything.
			return -1;
		}

		return 1; // o2 is null, so the o1 comes after
	}

	public int getSortColumn() {
		return sortColumn;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (obj.getClass() != getClass()) {
			return false;
		}

		@SuppressWarnings("rawtypes")
		TableColumnComparator other = (TableColumnComparator) obj;
		return (sortColumn == other.sortColumn);
	}

	@Override
	public int hashCode() {
		return sortColumn;
	}
}
