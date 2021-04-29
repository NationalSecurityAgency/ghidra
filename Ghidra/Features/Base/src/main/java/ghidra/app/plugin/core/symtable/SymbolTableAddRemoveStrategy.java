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

import static docking.widgets.table.AddRemoveListItem.Type.*;

import java.util.*;

import docking.widgets.table.AddRemoveListItem;
import docking.widgets.table.TableSortingContext;
import docking.widgets.table.threaded.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The symbol table users a {@link ThreadedTableModel}.  This model does not correctly function
 * with data that can change outside of the table.   The symbol table's row objects are the 
 * {@link Symbol} db objects.   These db objects can be changed by the user and by analysis
 * while table is loaded.   The problem with this is that the table's sort can be broken when 
 * symbols are to be added, removed or re-inserted, as this process requires a binary search which
 * will be broken if the criteria used to sort the data has changed.   Effectively, a symbol 
 * change can break the binary search if that symbol stays in a previously sorted position, but
 * has updated data that would put the symbol in a new position if sorted again.  For example, 
 * if the table is sorted on name and the name of a symbol changes, then future uses of the
 * binary search will be broken while that symbol is still in the position that matches its old
 * name.
 * <p>
 * This issue has been around for quite some time.  To completely fix this issue, each row object
 * of the symbol table would need to be immutable, at least on the sort criteria.   We could fix
 * this in the future if the *mostly correct* sorting behavior is not good enough.  For now, the
 * client can trigger a re-sort (e.g., by opening and closing the table) to fix the slightly 
 * out-of-sort data.
 * <p>
 * The likelihood of the sort being inconsistent now relates directly to how many changed symbols
 * are in the table at the time of an insert.   The more changes symbols, the higher the chance
 * of a stale/misplaced symbol being used during a binary search, thus producing an invalid insert
 * position.  
 * <p>
 * This strategy is setup to mitigate the number of invalid symbols in the table at the
 * time the inserts are applied.   The basic workflow of this algorithm is:
 * <pre>
 * 1) condense the add / remove requests to remove duplicate efforts
 * 2) process all removes first
 *    --all pure removes
 *    --all removes as part of a re-insert
 * 3) process all items that failed to remove due to the sort data changing
 * 4) process all adds (this step will fail if the data contains mis-sorted items)
 *    --all adds as part of a re-insert
 *    --all pure adds
 * </pre>
 * 
 * Step 3, processing failed removals, is done to avoid a brute force lookup at each removal 
 * request.   
 * 
 * <P>This strategy has knowledge of client proxy object usage.   The proxy objects
 * are coded such that the {@code hashCode()} and {@code equals()} methods will match those 
 * methods of the data's real objects.
 */
public class SymbolTableAddRemoveStrategy implements TableAddRemoveStrategy<Symbol> {

	@Override
	public void process(List<AddRemoveListItem<Symbol>> addRemoveList, TableData<Symbol> tableData,
			TaskMonitor monitor) throws CancelledException {

		Set<AddRemoveListItem<Symbol>> items = coalesceAddRemoveItems(addRemoveList);

		// 
		// Hash map the existing values so that we can use any object inside the add/remove list
		// as a key into this map to get the matching existing value.  Using the existing value
		// enables the binary search to work when the add/remove item is a proxy object, but the
		// existing item still has the data used to sort it.  If the sort data has changed, then
		// even this step will not allow the TableData to find the item in a search.
		//
		Map<Symbol, Symbol> hashed = new HashMap<>();
		for (Symbol symbol : tableData) {
			hashed.put(symbol, symbol);
		}

		Set<Symbol> failedToRemove = new HashSet<>();

		int n = items.size();
		monitor.setMessage("Removing " + n + " items...");
		monitor.initialize(n);

		Iterator<AddRemoveListItem<Symbol>> it = items.iterator();
		while (it.hasNext()) {
			AddRemoveListItem<Symbol> item = it.next();
			Symbol value = item.getValue();
			if (item.isChange()) {
				Symbol toRemove = hashed.remove(value);
				remove(tableData, toRemove, failedToRemove);
				monitor.incrementProgress(1);
			}
			else if (item.isRemove()) {
				Symbol toRemove = hashed.remove(value);
				remove(tableData, toRemove, failedToRemove);
				it.remove();
			}
			monitor.checkCanceled();
		}

		if (!failedToRemove.isEmpty()) {
			int size = failedToRemove.size();
			String message = size == 1 ? "1 old symbol..." : size + " old symbols...";
			monitor.setMessage("Removing " + message);

			tableData.process((data, sortContext) -> {
				return expungeLostItems(failedToRemove, data, sortContext);
			});
		}

		n = items.size();
		monitor.setMessage("Adding " + n + " items...");
		it = items.iterator();
		while (it.hasNext()) {
			AddRemoveListItem<Symbol> item = it.next();
			Symbol value = item.getValue();
			if (item.isChange()) {
				tableData.insert(value);
				hashed.put(value, value);
			}
			else if (item.isAdd()) {
				tableData.insert(value);
				hashed.put(value, value);
			}
			monitor.checkCanceled();
			monitor.incrementProgress(1);
		}

		monitor.setMessage("Done adding/removing");
	}

	private Set<AddRemoveListItem<Symbol>> coalesceAddRemoveItems(
			List<AddRemoveListItem<Symbol>> addRemoveList) {

		Map<Long, AddRemoveListItem<Symbol>> map = new HashMap<>();

		for (AddRemoveListItem<Symbol> item : addRemoveList) {

			if (item.isChange()) {
				handleChange(item, map);
			}
			else if (item.isAdd()) {
				handleAdd(item, map);
			}
			else {
				handleRemove(item, map);
			}
		}

		return new HashSet<>(map.values());
	}

	private void handleAdd(AddRemoveListItem<Symbol> item,
			Map<Long, AddRemoveListItem<Symbol>> map) {

		long id = item.getValue().getID();
		AddRemoveListItem<Symbol> existing = map.get(id);
		if (existing == null) {
			map.put(id, item);
			return;
		}

		if (existing.isChange()) {
			return; // change -> add; keep the change
		}
		if (existing.isAdd()) {
			return; // already an add
		}

		// remove -> add; make a change
		map.put(id, new AddRemoveListItem<>(CHANGE, existing.getValue()));
	}

	private void handleRemove(AddRemoveListItem<Symbol> item,
			Map<Long, AddRemoveListItem<Symbol>> map) {

		long id = item.getValue().getID();
		AddRemoveListItem<Symbol> existing = map.get(id);
		if (existing == null) {
			map.put(id, item);
			return;
		}

		if (existing.isChange()) {
			map.put(id, item); // change -> remove; just do the remove
			return;
		}
		if (existing.isRemove()) {
			return;
		}

		// add -> remove; do no work
		map.remove(id);
	}

	private void handleChange(AddRemoveListItem<Symbol> item,
			Map<Long, AddRemoveListItem<Symbol>> map) {

		long id = item.getValue().getID();
		AddRemoveListItem<Symbol> existing = map.get(id);
		if (existing == null) {
			map.put(id, item);
			return;
		}

		if (!existing.isChange()) {
			// either add or remove followed by a change; keep the change
			map.put(id, item);
		}

		// otherwise, we had a change followed by a change; keep just 1 change
	}

	private void remove(TableData<Symbol> tableData, Symbol symbol, Set<Symbol> failedToRemove) {
		if (symbol == null) {
			return;
		}

		if (!tableData.remove(symbol)) {
			failedToRemove.add(symbol);
		}
	}

	/*
	 * Removes the given set of items that were unsuccessfully removed from the table as part of 
	 * the add/remove process.   These items could not be removed because some part of their 
	 * state has changed such that the binary search performed during the normal remove process
	 * cannot locate the item in the table data.   This algorithm will check the given set of 
	 * items against the entire list of table data, locating the item to be removed.   
	 */
	private List<Symbol> expungeLostItems(Set<Symbol> toRemove, List<Symbol> data,
			TableSortingContext<Symbol> sortContext) {

		if (sortContext.isUnsorted()) {
			// this can happen if the data is unsorted and we were asked to remove an item that 
			// was never in the table for some reason
			return data;
		}

		// Copy to a new list those items that are not marked for removal.  This saves the 
		// list move its items every time a remove takes place
		List<Symbol> newList = new ArrayList<>(data.size() - toRemove.size());
		for (int i = 0; i < data.size(); i++) {
			Symbol rowObject = data.get(i);
			if (!toRemove.contains(rowObject)) {
				newList.add(rowObject);
			}
		}

		return newList;
	}
}
