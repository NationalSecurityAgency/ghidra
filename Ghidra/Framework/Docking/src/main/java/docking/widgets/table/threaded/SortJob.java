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

import docking.widgets.table.TableSortingContext;
import ghidra.util.task.TaskMonitor;

public class SortJob<T> extends TableUpdateJob<T> {

	SortJob(ThreadedTableModel<T, ?> model, TaskMonitor monitor,
			TableSortingContext<T> sortingContext, boolean forceSort) {
		super(model, monitor);
		setForceFilter(false); // only sorting
		requestSort(sortingContext, forceSort);
	}

	@Override
	public synchronized boolean requestFilter() {
		//
		// This is a request to fully filter the table's data (like when the filter changes).
		// In this case, we had disabled 'force filter', as the sorting did not need it. 
		// However, when the client asks to filter, make sure we filter.
		//
		boolean canFilter = super.requestFilter();
		if (canFilter) {
			setForceFilter(true); // reset, since we had turned it off above; now we have to filter
		}
		return canFilter;
	}
}
