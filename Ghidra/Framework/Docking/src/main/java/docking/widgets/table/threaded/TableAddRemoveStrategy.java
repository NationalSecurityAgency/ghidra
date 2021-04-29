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
 * A strategy to perform table add and remove updates
 *
 * @param <T> the row type
 */
public interface TableAddRemoveStrategy<T> {

	/**
	 * Adds to and removes from the table data those items in the given add/remove list
	 * @param addRemoveList the items to add/remove
	 * @param tableData the table's data
	 * @param monitor the monitor
	 * @throws CancelledException if the monitor is cancelled
	 */
	public void process(List<AddRemoveListItem<T>> addRemoveList, TableData<T> tableData,
			TaskMonitor monitor) throws CancelledException;
}
