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

import java.util.Collections;
import java.util.List;

import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.task.TaskMonitor;

public abstract class ThreadedEnumeratedColumnTableModel<
	C extends Enum<C> & EnumeratedTableColumn<C, R>, R> extends ThreadedTableModel<R, Void> {

	private final List<C> cols;

	protected ThreadedEnumeratedColumnTableModel(ServiceProvider serviceProvider, String name,
			Class<C> colType, TaskMonitor monitor, boolean loadIncrementally) {
		super(name, serviceProvider, monitor, loadIncrementally);
		this.cols = List.of(colType.getEnumConstants());

		reloadColumns();
	}

	/**
	 * Get the default sort order of the table
	 * 
	 * @return the list of columns in order of descending priority
	 */
	public List<C> defaultSortOrder() {
		return Collections.emptyList();
	}

	@Override
	protected TableColumnDescriptor<R> createTableColumnDescriptor() {
		return EnumeratedColumnTableModel.createTableColumnDescriptor(cols, defaultSortOrder());
	}

	@Override
	public Void getDataSource() {
		return null;
	}
}
