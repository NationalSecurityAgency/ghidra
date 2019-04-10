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
package ghidra.app.tablechooser;

import java.util.*;

import docking.widgets.table.*;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.AddressTableColumn;
import ghidra.util.task.TaskMonitor;

public class TableChooserTableModel extends AddressBasedTableModel<AddressableRowObject> {

	// we maintain this list so that any future reload operations can load the original user data
	// (the downside of this is that two lists are maintained)
	Set<AddressableRowObject> myPrivateList = new HashSet<AddressableRowObject>();

	public TableChooserTableModel(String title, ServiceProvider serviceProvider, Program program,
			TaskMonitor monitor) {
		super(title, serviceProvider, program, monitor);
	}

	@Override
	public synchronized void addObject(AddressableRowObject rowObject) {
		myPrivateList.add(rowObject);
		super.addObject(rowObject);
	}

	@Override
	public synchronized void removeObject(AddressableRowObject obj) {
		myPrivateList.remove(obj);
		super.removeObject(obj);
	}

	public synchronized boolean containsObject(AddressableRowObject obj) {
		// checking this list allows us to work around the threaded nature of our parent
		return myPrivateList.contains(obj);
	}

	@Override
	public Address getAddress(int row) {
		return getRowObject(row).getAddress();
	}

	@Override
	protected synchronized void doLoad(Accumulator<AddressableRowObject> accumulator,
			TaskMonitor monitor) throws CancelledException {
		accumulator.addAll(myPrivateList);
	}

	public <T> void addCustomColumn(ColumnDisplay<T> columnDisplay) {
		addTableColumn(new ColumnDisplayDynamicTableColumnAdapter<T>(columnDisplay));
	}

	@Override
	protected Comparator<AddressableRowObject> createSortComparator(int columnIndex) {
		DynamicTableColumn<AddressableRowObject, ?, ?> column = getColumn(columnIndex);
		if (!(column instanceof ColumnDisplayDynamicTableColumnAdapter<?>)) {
			return super.createSortComparator(columnIndex);
		}
		return (ColumnDisplayDynamicTableColumnAdapter<?>) column;
	}

	@Override
	protected TableColumnDescriptor<AddressableRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<AddressableRowObject> descriptor =
			new TableColumnDescriptor<AddressableRowObject>();

		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new AddressTableColumn()), 1, true);

		return descriptor;
	}
}
