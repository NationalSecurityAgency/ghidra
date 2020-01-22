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

import java.util.List;

public interface RowObjectFilterModel<ROW_OBJECT> extends RowObjectTableModel<ROW_OBJECT> {

	/**
	 * This property allows for the disabling of 'sub-filtering'.  When enabled, which is the
	 * default, data from current filters will be reused when additional filter criteria is
	 * added to that current filter.  For example,
	 * <blockquote>
	 * <p>
	 * Given a table has a 'contains' filter with a text value of 'bob',
	 * <p>
	 * then, if the users types an 'o' into the filter field, producing a value of 'bobo',
	 * <p>
	 * then the data that matched 'bob' will be used as the data to filter for the new 'bobo'
	 * text.
	 * </blockquote>
	 *
	 * <p>The downside of this is that we cache data for every completed filter.  So, in a
	 * degenerate case, with a large dataset, with many incremental filtering steps, where each
	 * did not significantly reduce the previous set of data, the table could then consume
	 * a large amount of memory, roughly equal to <code>allData.size() * numberOfFilterSteps</code>
	 *
	 * <p>Most tables do not have enough data for this to have a significant impact.
	 */
	public static String SUB_FILTERING_DISABLED_PROPERTY = "tables.subfilter.disabled";

	public void setTableFilter(TableFilter<ROW_OBJECT> filter);

	public TableFilter<ROW_OBJECT> getTableFilter();

	public boolean isFiltered();

	public int getUnfilteredRowCount();

	public List<ROW_OBJECT> getUnfilteredData();

	public int getModelRow(int viewRow);

	public int getViewRow(int modelRow);

	/**
	 * Returns the view index of the given item.  When filtered, this is the index is the smaller,
	 * visible set of data; when unfiltered, this index is the same as that returned by
	 * {@link #getModelIndex(Object)}.
	 * 
	 * <p>This operation will be O(n) unless the implementation is sorted, in which case the 
	 * operation is O(log n), as it uses a binary search.
	 * 
	 * @param t the item 
	 * @return the view index
	 */
	public int getViewIndex(ROW_OBJECT t);

	/**
	 * Returns the model index of the given item.  When filtered, this is the index is the larger,
	 * set of data; when unfiltered, this index is the same as that returned by
	 * {@link #getModelIndex(Object)}.
	 * 
	 * <p>This operation will be O(n) unless the implementation is sorted, in which case the 
	 * operation is O(log n), as it uses a binary search.
	 * 
	 * @param t the item 
	 * @return the model index
	 */
	public int getModelIndex(ROW_OBJECT t);
}
