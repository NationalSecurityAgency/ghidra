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

import java.util.List;

import docking.widgets.table.AddRemoveListItem;
import ghidra.util.task.TaskMonitor;

public class AddRemoveJob<T> extends TableUpdateJob<T> {
	AddRemoveJob(ThreadedTableModel<T, ?> model, List<AddRemoveListItem<T>> addRemoveList,
			TaskMonitor monitor) {
		super(model, monitor);
		setForceFilter(false); // the item will do its own sorting and filtering
		this.addRemoveList = addRemoveList;
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
