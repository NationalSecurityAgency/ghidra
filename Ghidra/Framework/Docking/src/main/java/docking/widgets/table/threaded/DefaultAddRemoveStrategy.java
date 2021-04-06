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
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A strategy that uses the table's sort state to perform a binary search of items to be added
 * and removed.   
 *
 * @param <T> the row type
 */
public class DefaultAddRemoveStrategy<T> implements TableAddRemoveStrategy<T> {

	@Override
	public void process(List<AddRemoveListItem<T>> addRemoveList, TableData<T> updatedData,
			TaskMonitor monitor) throws CancelledException {

		int n = addRemoveList.size();
		monitor.setMessage("Adding/Removing " + n + " items...");
		monitor.initialize(n);

		// Note: this class does not directly perform a binary such, but instead relies on that
		//       work to be done by the call to TableData.remove()
		for (int i = 0; i < n; i++) {
			AddRemoveListItem<T> item = addRemoveList.get(i);
			T value = item.getValue();
			if (item.isChange()) {
				updatedData.remove(value);
				updatedData.insert(value);
			}
			else if (item.isRemove()) {
				updatedData.remove(value);
			}
			else if (item.isAdd()) {
				updatedData.insert(value);
			}
			monitor.checkCanceled();
			monitor.setProgress(i);
		}
		monitor.setMessage("Done adding/removing");
	}

}
