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
package docking.widgets.trable;

/**
 * Row model for a {@link GTrable}.
 *
 * @param <T> the row object type
 */
public interface GTrableRowModel<T> {

	/**
	 * {@return the total number of rows include open child rows.}
	 */
	public int getRowCount();

	/**
	 * {@return the row object for the given index.}
	 * @param rowIndex the index of the row to retrieve
	 */
	public T getRow(int rowIndex);

	/**
	 * {@return true if the row at the given index can be expanded}
	 * @param rowIndex the row to test if expandable
	 */
	public boolean isExpandable(int rowIndex);

	/**
	 * {@return true if the row at the given index is expanded.}
	 * @param rowIndex the index of the row to test for expanded
	 */
	public boolean isExpanded(int rowIndex);

	/**
	 * Collapse the row at the given row index.
	 * @param rowIndex the index of the row to collapse
	 * @return the total number of rows removed due to collapsing the row
	 */
	public int collapseRow(int rowIndex);

	/**
	 * Expand the row at the given row index.
	 * @param rowIndex the index of the row to expand
	 * @return the total number of rows added due to the expand
	 */
	public int expandRow(int rowIndex);

	/**
	 * {@return the indent level of the row at the given index.}
	 * @param rowIndex the index of the row to get its indent level
	 */
	public int getIndentLevel(int rowIndex);

	/**
	 * Adds a listener to the list that is notified each time a change
	 * to the data model occurs.
	 *
	 * @param l the listener to be notified
	 */
	public void addListener(GTrableModeRowlListener l);

	/**
	 * Removes a listener from the list that is notified each time a
	 * change to the model occurs.
	 *
	 * @param l the listener to remove
	 */
	public void removeListener(GTrableModeRowlListener l);

}
