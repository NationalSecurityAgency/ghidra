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

import docking.widgets.table.sort.ColumnRenderedValueBackupComparator;
import docking.widgets.table.sort.RowBasedColumnComparator;

/**
 * A version of {@link ColumnRenderedValueBackupComparator} that uses the 
 * {@link ThreadedTableModel}'s cache for column lookups
 *
 * @param <T> the row type
 */
public class ThreadedBackupRowComparator<T> extends ColumnRenderedValueBackupComparator<T> {

	private ThreadedTableModel<T, ?> threadedModel;

	/**
	 * Constructs this class with the given column comparator that will get called after the
	 * given row is converted to the column value for the given sort column
	 * 
	 * @param model the table model using this comparator
	 * @param sortColumn the column being sorted
	 * @see RowBasedColumnComparator
	 */
	public ThreadedBackupRowComparator(ThreadedTableModel<T, ?> model, int sortColumn) {
		super(model, sortColumn);
		this.threadedModel = model;
	}

	@Override
	protected Object getColumnValue(T t) {
		return threadedModel.getCachedColumnValueForRow(t, sortColumn);
	}
}
