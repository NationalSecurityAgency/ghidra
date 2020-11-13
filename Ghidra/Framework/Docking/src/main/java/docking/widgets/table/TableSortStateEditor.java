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

import docking.widgets.table.ColumnSortState.SortDirection;

public class TableSortStateEditor {
	private List<ColumnSortState> sortStates = new ArrayList<>();

	public TableSortStateEditor() {
		// for creating from scratch
	}

	public TableSortStateEditor(TableSortState tableSortState) {
		for (ColumnSortState sortState : tableSortState) {
			sortStates.add(sortState);
		}
	}

	public void addSortedColumn(ColumnSortState sortState) {
		validateColumns(sortState.getColumnModelIndex());
		sortStates.add(sortState);
	}

	public void addSortedColumn(int columnIndex) {
		addSortedColumn(columnIndex, SortDirection.ASCENDING);
	}

	public void addSortedColumn(int columnIndex, SortDirection direction) {
		addSortedColumn(new ColumnSortState(columnIndex, direction, getNextColumnSortOrder()));
	}

	public ColumnSortState getColumnSortState(int sortStateIndex) {
		return sortStates.get(sortStateIndex);
	}

	private int getNextColumnSortOrder() {
		return getSortedColumnCount() + 1;
	}

	public void removeSortedColumn(int columnIndex) {
		int existingIndex = indexOf(columnIndex);
		if (existingIndex < 0) {
			throw new IllegalArgumentException("Attempted to remove a column that is not sorted.");
		}
		sortStates.remove(existingIndex);
		recalculateSortOrder();
	}

	private void recalculateSortOrder() {
		for (int i = 0; i < sortStates.size(); i++) {
			sortStates.get(i).setSortOrder(i + 1);
		}
	}

	public void flipColumnSortDirection(int columnIndex) {
		int existingIndex = indexOf(columnIndex);
		if (existingIndex < 0) {
			throw new IllegalArgumentException(
				"Cannot change sort direction " + "when column is not sorted");
		}

		ColumnSortState sortState = sortStates.get(existingIndex);
		sortStates.set(existingIndex, sortState.createFlipState());
	}

	private void validateColumns(int columnIndex) {
		int existingIndex = indexOf(columnIndex);
		if (existingIndex >= 0) {
			throw new IllegalStateException("Cannot add a sort state when one " +
				"is already set at column: " + columnIndex);
		}
	}

	private int indexOf(int columnIndex) {
		for (int i = 0; i < sortStates.size(); i++) {
			ColumnSortState sortState = sortStates.get(i);
			if (sortState.getColumnModelIndex() == columnIndex) {
				return i;
			}
		}
		return -1;
	}

	public Iterator<ColumnSortState> iterator() {
		return Collections.unmodifiableList(sortStates).iterator();
	}

	public TableSortState createTableSortState() {
		return new TableSortState(sortStates);
	}

	public void clear() {
		sortStates.clear();
	}

	public boolean isColumnSorted(int columnIndex) {
		return indexOf(columnIndex) != -1;
	}

	public int getSortedColumnCount() {
		return sortStates.size();
	}

}
