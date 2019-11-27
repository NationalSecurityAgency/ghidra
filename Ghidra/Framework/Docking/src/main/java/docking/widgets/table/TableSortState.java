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

import org.jdom.Element;

import docking.widgets.table.ColumnSortState.SortDirection;

/**
 * Represents the concept of a table's sorted state, which is the number of sorted columns, their
 * sort order and their sort direction.
 * 
 * You can create instances of this class via the {@link TableSortStateEditor}.
 */
public class TableSortState implements Iterable<ColumnSortState> {

	private static final String XML_TABLE_SORT_STATE = "TABLE_SORT_STATE";

	private List<ColumnSortState> columnSortStates = new ArrayList<>();

	/**
	 * Creates a sort state that represents being unsorted
	 * @return a sort state that represents being unsorted
	 */
	public static TableSortState createUnsortedSortState() {
		return new TableSortState();
	}

	/**
	 * Creates a sort state with the given column as the sorted column (sorted ascending).
	 * 
	 * @param columnIndex The column to sort
	 * @return a sort state with the given column as the sorted column (sorted ascending).
	 * @see TableSortStateEditor
	 */
	public static TableSortState createDefaultSortState(int columnIndex) {
		return new TableSortState(new ColumnSortState(columnIndex, SortDirection.ASCENDING, 1));
	}

	/**
	 * Creates a sort state with the given column as the sorted column in the given direction.
	 * 
	 * @param columnIndex The column to sort
	 * @param isAscending True to sort ascending; false to sort descending
	 * @return a sort state with the given column as the sorted column (sorted ascending).
	 * @see TableSortStateEditor
	 */
	public static TableSortState createDefaultSortState(int columnIndex, boolean isAscending) {
		SortDirection sortDirection =
			isAscending ? SortDirection.ASCENDING : SortDirection.DESCENDING;
		return new TableSortState(new ColumnSortState(columnIndex, sortDirection, 1));
	}

	public TableSortState() {
		// default constructor
	}

	public TableSortState(List<ColumnSortState> sortStates) {
		List<Integer> sortOrders = new ArrayList<>();
		List<Integer> columnIndices = new ArrayList<>();
		for (ColumnSortState state : sortStates) {
			int sortOrder = state.getSortOrder();
			if (sortOrders.contains(sortOrder)) {
				throw new IllegalArgumentException(
					"Attempt to set table sort columns with duplicate sort order: " + sortOrder);
			}

			int columnModelIndex = state.getColumnModelIndex();
			if (columnIndices.contains(columnModelIndex)) {
				throw new IllegalArgumentException(
					"Attempt to set table sort columns with duplicate columns specified: " +
						columnModelIndex);
			}

			sortOrders.add(sortOrder);
			columnIndices.add(columnModelIndex);
		}

		this.columnSortStates = new ArrayList<>(sortStates);
	}

	public TableSortState(ColumnSortState columnSortState) {
		columnSortStates.add(columnSortState);
	}

	@Override
	public Iterator<ColumnSortState> iterator() {
		return Collections.unmodifiableList(columnSortStates).iterator();
	}

	public int getSortedColumnCount() {
		return columnSortStates.size();
	}

	public boolean isUnsorted() {
		return columnSortStates.isEmpty();
	}

	public ColumnSortState getColumnSortState(int columnIndex) {
		for (ColumnSortState sortState : columnSortStates) {
			if (sortState.getColumnModelIndex() == columnIndex) {
				return sortState;
			}
		}
		return null;
	}

	public List<ColumnSortState> getAllSortStates() {
		return new ArrayList<>(columnSortStates);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}

		if (!(obj instanceof TableSortState)) {
			return false;
		}
		TableSortState other = (TableSortState) obj;
		return columnSortStates.equals(other.columnSortStates);
	}

	@Override
	public int hashCode() {
		return columnSortStates.hashCode();
	}

	public static TableSortState restoreFromXML(Element element) {
		List<?> tableSortStateElementList = element.getChildren(XML_TABLE_SORT_STATE);
		if (tableSortStateElementList == null || tableSortStateElementList.size() == 0) {
			return null; // the given element contains no sort state data
		}

		Element sortStateElement = (Element) tableSortStateElementList.get(0);
		List<?> children = sortStateElement.getChildren(ColumnSortState.XML_COLUMN_SORT_STATE);

		List<ColumnSortState> columnStates = new ArrayList<>(children.size());
		for (Object object : children) {
			columnStates.add(ColumnSortState.restoreFromXML((Element) object));
		}

		return new TableSortState(columnStates);
	}

	public Element writeToXML() {
		Element element = new Element(XML_TABLE_SORT_STATE);
		for (ColumnSortState sortState : columnSortStates) {
			Element sortStateElement = sortState.writeToXML();
			element.addContent(sortStateElement);
		}
		return element;
	}

	@Override
	public String toString() {
		return columnSortStates.toString();
	}
}
