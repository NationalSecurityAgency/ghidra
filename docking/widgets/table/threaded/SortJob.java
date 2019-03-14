/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.util.task.TaskMonitor;
import docking.widgets.table.TableSortingContext;

public class SortJob<T> extends TableUpdateJob<T> {

	SortJob(ThreadedTableModel<T, ?> model, TaskMonitor monitor,
			TableSortingContext<T> sortingContext, boolean forceSort) {
		super(model, monitor);
		setForceFilter(false); // only sorting
		sort(sortingContext, forceSort);
	}

	@Override
	public synchronized boolean filter() {
		boolean canFilter = super.filter();
		if (canFilter) {
			setForceFilter(true); // reset, since we had turned it off above; now we have to filter
		}
		return canFilter;
	}
}
