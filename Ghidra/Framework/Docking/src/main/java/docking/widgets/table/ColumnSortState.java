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

import org.jdom.Element;

/**
 * Not meant to be created by users.  They should instead use the {@link TableSortStateEditor}.
 */
public class ColumnSortState {

	static final String XML_COLUMN_SORT_STATE = "COLUMN_SORT_STATE";
	private static final String XML_COLUMN_MODEL_INDEX = "COLUMN_MODEL_INDEX";
	private static final String XML_SORT_DIRECTION = "SORT_DIRECTION";
	private static final String XML_SORT_ORDER = "SORT_ORDER";

	public enum SortDirection {
		ASCENDING, DESCENDING, UNSORTED;

		public boolean isAscending() {
			return this == ASCENDING;
		}

		@Override
		public String toString() {
			if (isAscending()) {
				return "ascending";
			}
			return "descending";
		}

		public static SortDirection getSortDirection(String direction) {
			if (direction.equals("ascending")) {
				return ASCENDING;
			}
			return DESCENDING;
		}
	}

	private int columnModelIndex;
	private SortDirection sortDirection;
	private int sortOrder_OneBased = -1;

	ColumnSortState(int columnModelIndex, SortDirection sortDirection, int sortOrder) {
		if (columnModelIndex < 0) {
			throw new IllegalArgumentException("Column index cannot be negative");
		}
		this.columnModelIndex = columnModelIndex;
		this.sortDirection = sortDirection;
		this.sortOrder_OneBased = sortOrder;
	}

	void setSortOrder(int sortOrder) {
		this.sortOrder_OneBased = sortOrder;
	}

	public int getSortOrder() {
		return sortOrder_OneBased;
	}

	public int getColumnModelIndex() {
		return columnModelIndex;
	}

	public boolean isAscending() {
		return sortDirection.isAscending();
	}

	public SortDirection getSortDirection() {
		return sortDirection;
	}

	public ColumnSortState createFlipState() {
		ColumnSortState newSortState = new ColumnSortState(columnModelIndex,
			isAscending() ? SortDirection.DESCENDING : SortDirection.ASCENDING, sortOrder_OneBased);
		return newSortState;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + columnModelIndex;
		result = prime * result + ((sortDirection == null) ? 0 : sortDirection.hashCode());
		result = prime * result + sortOrder_OneBased;
		return result;
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

		ColumnSortState other = (ColumnSortState) obj;
		if (columnModelIndex != other.columnModelIndex) {
			return false;
		}

		if (sortDirection == null) {
			if (other.sortDirection != null) {
				return false;
			}
		}
		else if (!sortDirection.equals(other.sortDirection)) {
			return false;
		}

		if (sortOrder_OneBased != other.sortOrder_OneBased) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + "[column:" + columnModelIndex + ",direction:" +
			sortDirection + ",order:" + sortOrder_OneBased + "]";
	}

	public static ColumnSortState restoreFromXML(Element element) {
		String modelIndexValue = element.getAttributeValue(XML_COLUMN_MODEL_INDEX);
		int modelIndex = Integer.parseInt(modelIndexValue);

		String sortOrderValue = element.getAttributeValue(XML_SORT_ORDER);
		int sortOrder = Integer.parseInt(sortOrderValue);

		String sortDirectionValue = element.getAttributeValue(XML_SORT_DIRECTION);
		SortDirection sortDirection = SortDirection.getSortDirection(sortDirectionValue);

		return new ColumnSortState(modelIndex, sortDirection, sortOrder);
	}

	Element writeToXML() {
		Element sortStateElement = new Element(XML_COLUMN_SORT_STATE);
		sortStateElement.setAttribute(XML_COLUMN_MODEL_INDEX, Integer.toString(columnModelIndex));
		sortStateElement.setAttribute(XML_SORT_DIRECTION, sortDirection.toString());
		sortStateElement.setAttribute(XML_SORT_ORDER, Integer.toString(sortOrder_OneBased));
		return sortStateElement;
	}
}
