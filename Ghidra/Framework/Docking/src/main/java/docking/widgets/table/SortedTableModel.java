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

import javax.swing.table.TableModel;

/**
 * A table model that allows for setting the sorted column(s) and direction
 */
public interface SortedTableModel extends TableModel {

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

	/**
	 * Returns the column index that is the primary sorted column; -1 if no column is sorted
	 * 
	 * @return the index
	 */
	public int getPrimarySortColumnIndex();

	/**
	 * Sets the sort state for this table model
	 * @param state the sort state
	 */
	public void setTableSortState(TableSortState state);

	/**
	 * Gets the sort state of this sorted model
	 * @return the current sort state
	 */
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
}
