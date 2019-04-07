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

import java.util.Comparator;

import javax.swing.table.TableModel;

/**
 * A table model that allows for setting the sorted column and direction.
 */
public interface SortedTableModel extends TableModel {

	public static final Comparator<Object> DEFAULT_COMPARATOR = new DefaultComparator();

	/**
	 * Sort order in ascending order.
	 */
	public final static boolean ASCENDING_ORDER = true;

	/**
	 * Sort order in descending order.
	 */
	public final static boolean DESCENDING_ORDER = false;

	/**
	 * Returns true if the specified columnIndex is sortable.
	 * @param columnIndex the column index
	 * @return true if the specified columnIndex is sortable
	 */
	public boolean isSortable(int columnIndex);

	public int getPrimarySortColumnIndex();

	public void setTableSortState(TableSortState tableSortState);

	public TableSortState getTableSortState();

	/**
	 * Adds a listener to be notified when the sort state of this model changes. 
	 * <br>
	 * <b>Note: the listener may be stored in a weak collection, which means you have to 
	 *          maintain a handle to the listener so that it does not get garbage collected.
	 * </b>
	 * @param l the listener
	 */
	public void addSortListener(SortListener l);

//==================================================================================================
// Inner Classes
//==================================================================================================

	public static class DefaultComparator implements Comparator<Object> {
		@Override
		@SuppressWarnings("unchecked")
		// we checked cast to be safe
		public int compare(Object o1, Object o2) {

			if (o1 == null || o2 == null) {
				return handleNullValues(o1, o2);
			}

			if (String.class == o1.getClass() && String.class == o2.getClass()) {
				return compareAsStrings(o1, o2);
			}

			if (Comparable.class.isAssignableFrom(o1.getClass()) && o1.getClass() == o2.getClass()) {
				@SuppressWarnings("rawtypes")
				Comparable comparable = (Comparable) o1;
				int result = comparable.compareTo(o2);
				return result;
			}

			// give up and use the toString()
			return compareAsStrings(o1, o2);
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

		private int compareAsStrings(Object o1, Object o2) {
			String s1 = o1.toString();
			String s2 = o2.toString();
			return s1.compareToIgnoreCase(s2);
		}
	}

}
