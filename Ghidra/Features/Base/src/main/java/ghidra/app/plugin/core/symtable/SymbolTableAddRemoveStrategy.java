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
package ghidra.app.plugin.core.symtable;

import java.util.*;

import docking.widgets.table.AddRemoveListItem;
import docking.widgets.table.threaded.TableAddRemoveStrategy;
import docking.widgets.table.threaded.TableData;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This strategy attempts to optimize removal of db objects that have been deleted.  The issue with
 * deleted db objects is that they may no longer have their attributes, which means we cannot
 * use any of those attributes that may have been used as the basis for sorting.  We use the 
 * table's sort to perform a binary search of existing symbols for removal.  If the binary search
 * does not work, then removal operations will require slow list traversal.   Additionally, 
 * some clients use proxy objects in add/remove list to signal which object needs to be removed, 
 * since the original object is no longer available to the client.    Using these proxy objects
 * in a binary search may lead to exceptions if the proxy has unsupported methods called when 
 * searching.
 * 
 * <P>This strategy will has guilty knowledge of client proxy object usage.   The proxy objects
 * are coded such that the {@code hashCode()} and {@code equals()} methods will match those 
 * methods of the data's real objects.   
 *
 * @param <T> the row type
 */
public class SymbolTableAddRemoveStrategy<T> implements TableAddRemoveStrategy<T> {

	@Override
	public void process(List<AddRemoveListItem<T>> addRemoveList, TableData<T> tableData,
			TaskMonitor monitor) throws CancelledException {

		// 
		// Hash map the existing values so that we can use any object inside the add/remove list
		// as a key into this map to get the matching existing value.
		//
		Map<T, T> hashed = new HashMap<>();
		for (T t : tableData) {
			hashed.put(t, t);
		}

		int n = addRemoveList.size();
		monitor.setMessage("Adding/Removing " + n + " items...");
		monitor.initialize(n);
		for (int i = 0; i < n; i++) {
			AddRemoveListItem<T> item = addRemoveList.get(i);
			T value = item.getValue();
			if (item.isChange()) {
				T toRemove = hashed.get(value);
				if (toRemove != null) {
					tableData.remove(toRemove);
				}
				tableData.insert(value);
			}
			else if (item.isRemove()) {
				T toRemove = hashed.get(value);
				if (toRemove != null) {
					tableData.remove(toRemove);
				}
			}
			else if (item.isAdd()) {
				tableData.insert(value);
			}
			monitor.checkCanceled();
			monitor.setProgress(i);
		}
		monitor.setMessage("Done adding/removing");
	}
}
