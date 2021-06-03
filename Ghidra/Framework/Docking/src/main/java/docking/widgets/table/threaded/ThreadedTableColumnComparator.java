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

import docking.widgets.table.sort.RowBasedColumnComparator;

/**
 * A comparator for comparing table column values for threaded table models.  This comparator
 * uses the column cache of the {@link ThreadedTableModel}.
 *
 * @param <T> the row type
 */
public class ThreadedTableColumnComparator<T> extends RowBasedColumnComparator<T> {
	private ThreadedTableModel<T, ?> threadedModel;

	/**
	 * Constructs this class with the given column comparator that will get called after the
	 * given row is converted to the column value for the given sort column
	 * 
	 * @param model the table model using this comparator
	 * @param sortColumn the column being sorted
	 * @param comparator the column comparator to use for sorting
	 * @see RowBasedColumnComparator
	 */
	public ThreadedTableColumnComparator(ThreadedTableModel<T, ?> model, int sortColumn,
			Comparator<Object> comparator) {
		super(model, sortColumn, comparator);
		this.threadedModel = model;
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
	 * @see RowBasedColumnComparator
	 */
	public ThreadedTableColumnComparator(ThreadedTableModel<T, ?> model, int sortColumn,
			Comparator<Object> comparator, Comparator<Object> backupRowComparator) {
		super(model, sortColumn, comparator, backupRowComparator);
		this.threadedModel = model;
	}

	@Override
	protected Object getColumnValue(T t) {
		return threadedModel.getCachedColumnValueForRow(t, sortColumn);
	}
}
