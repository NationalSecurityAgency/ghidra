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

public interface TableFilter<ROW_OBJECT> {

	/**
	 * Returns true if this filter matches the given row (data)
	 *
	 * @param rowObject the current row object
	 * @return true if the element at the given row matches this filter.
	 */
	public boolean acceptsRow(ROW_OBJECT rowObject);

	/**
	 * Returns true if this filter is a more specific version of the given filter.
	 *
	 * <P>For example, if this filter is a 'starts with' text filter, with the
	 * value of 'bobo', then if the given filter is also a 'starts with' filter,
	 * with a value of 'bob', then this
	 * filter is considered a sub-filter of the given sub-filter.
	 *
	 * @param tableFilter the filter to check
	 * @return true if this filter is a sub-filter of the given filter
	 */
	public boolean isSubFilterOf(TableFilter<?> tableFilter);

	/**
	 * Returns true if the there is a column filter on the column specified
	 *
	 * @param columnModelIndex the model index of the column to test for column filters.
	 * @return  true if the there is a column filter on the column specified.
	 */
	public default boolean hasColumnFilter(int columnModelIndex) {
		return false;
	}

	/**
	 * A method that allows filters to report that they have nothing to actually filter.  This
	 * is useful for empty/null filters.
	 * 
	 * @return true if this filter will not perform any filtering
	 */
	public default boolean isEmpty() {
		return false;
	}
}
