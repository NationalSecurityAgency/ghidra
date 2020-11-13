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
package docking.widgets.table.sort;

import java.util.Comparator;
import java.util.Objects;

import docking.widgets.table.RowObjectTableModel;
import docking.widgets.table.TableComparators;

/**
 * A comparator for a specific column that will take in a T row object, extract the value
 * for the given column and then call the give comparator
 * 
 * @param <T> the row type
 */
public class RowBasedColumnComparator<T> implements Comparator<T> {

	protected RowObjectTableModel<T> model;
	protected int sortColumn;
	protected Comparator<Object> columnComparator;
	protected Comparator<Object> backupRowComparator = TableComparators.getNoSortComparator();

	/**
	 * Constructs this class with the given column comparator that will get called after the
	 * given row is converted to the column value for the given sort column
	 * 
	 * @param model the table model using this comparator
	 * @param sortColumn the column being sorted
	 * @param comparator the column comparator to use for sorting
	 */
	public RowBasedColumnComparator(RowObjectTableModel<T> model, int sortColumn,
			Comparator<Object> comparator) {
		this.model = model;
		this.sortColumn = sortColumn;
		this.columnComparator = Objects.requireNonNull(comparator);
	}

	/**
	 * This version of the constructor is used for the default case where the client will 
	 * supply a backup row comparator that will get called if the given column comparator returns
	 * a '0' value.
	 * 
	 * @param model the table model using this comparator
	 * @param sortColumn the column being sorted
	 * @param comparator the column comparator to use for sorting
	 * @param backupRowComparator the backup row comparator
	 */
	public RowBasedColumnComparator(RowObjectTableModel<T> model, int sortColumn,
			Comparator<Object> comparator, Comparator<Object> backupRowComparator) {
		this.model = model;
		this.sortColumn = sortColumn;
		this.columnComparator = Objects.requireNonNull(comparator);
		this.backupRowComparator = Objects.requireNonNull(backupRowComparator);
	}

	@Override
	public int compare(T t1, T t2) {
		if (t1 == t2) {
			return 0;
		}

		Object value1 = getColumnValue(t1);
		Object value2 = getColumnValue(t2);

		if (value1 == null || value2 == null) {
			return TableComparators.compareWithNullValues(value1, value2);
		}

		int result = columnComparator.compare(value1, value2);
		if (result != 0) {
			return result;
		}

		// 
		// At this point we have one of two cases:
		// 1) the column comparator is a non-default comparator that has returned 0, which means
		//    the column values should sort the same, or
		// 2) the column comparator is a default/non-specific comparator, which means that the 
		//    column values should sort the same, or *that the default comparator could not 
		//    figure out how to sort them.
		//
		// In case 1, this backup comparator will be just a stub comparator; in case 2, this 
		// backup comparator is not a stub and will do something reasonable for the sort, 
		// depending upon how the model created this class.
		//
		return backupRowComparator.compare(value1, value2);
	}

	protected Object getColumnValue(T t) {
		return model.getColumnValueForRow(t, sortColumn);
	}
}
