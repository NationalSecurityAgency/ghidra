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

import java.util.*;

import docking.widgets.table.AddRemoveListItem;
import docking.widgets.table.TableSortingContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A strategy that uses the table's sort state to perform a binary search of items to be added
 * and removed.   
 *
 * <P>This strategy is aware that some items may not be correctly removed, such as database items
 * that have been deleted externally to the table.   These items may require a brute force update
 * to achieve removal.
 *
 * @param <T> the row type
 */
public class DefaultAddRemoveStrategy<T> implements TableAddRemoveStrategy<T> {

	@Override
	public void process(List<AddRemoveListItem<T>> addRemoveList, TableData<T> tableData,
			TaskMonitor monitor) throws CancelledException {

		int n = addRemoveList.size();
		monitor.setMessage("Adding/Removing " + n + " items...");
		monitor.initialize(n);

		Set<T> failedToRemove = new HashSet<>();

		// Note: this class does not directly perform a binary search, but instead relies on that
		//       work to be done by the call to TableData.remove()
		for (int i = 0; i < n; i++) {
			AddRemoveListItem<T> item = addRemoveList.get(i);
			T value = item.getValue();
			if (item.isChange()) {
				tableData.remove(value);
				tableData.insert(value);
			}
			else if (item.isRemove()) {
				if (!tableData.remove(value)) {
					failedToRemove.add(value);
				}
			}
			else if (item.isAdd()) {
				tableData.insert(value);
			}
			monitor.checkCanceled();
			monitor.setProgress(i);
		}

		if (!failedToRemove.isEmpty()) {
			int size = failedToRemove.size();
			String message = size == 1 ? "1 deleted item..." : size + " deleted items...";
			monitor.setMessage("Removing " + message);

			tableData.process((data, sortContext) -> {
				return expungeLostItems(failedToRemove, data, sortContext);
			});
		}

		monitor.setMessage("Done adding/removing");
	}

	private List<T> expungeLostItems(Set<T> toRemove, List<T> data,
			TableSortingContext<T> sortContext) {

		List<T> newList = new ArrayList<>(data.size() - toRemove.size());
		for (int i = 0; i < data.size(); i++) {
			T rowObject = data.get(i);
			if (!toRemove.contains(rowObject)) {
				newList.add(rowObject);
			}
		}

		return newList;
	}

}
