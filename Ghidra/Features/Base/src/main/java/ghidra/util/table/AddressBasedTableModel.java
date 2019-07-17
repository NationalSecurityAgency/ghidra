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
package ghidra.util.table;

import docking.widgets.table.*;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.table.field.*;
import ghidra.util.task.TaskMonitor;

public abstract class AddressBasedTableModel<ROW_TYPE> extends GhidraProgramTableModel<ROW_TYPE> {

	public AddressBasedTableModel(String title, ServiceProvider serviceProvider, Program program,
			TaskMonitor monitor) {
		this(title, serviceProvider, program, monitor, false);
	}

	public AddressBasedTableModel(String title, ServiceProvider serviceProvider, Program program,
			TaskMonitor monitor, boolean loadIncrementally) {
		super(title, serviceProvider, program, monitor, loadIncrementally);
	}

	public abstract Address getAddress(int row);

	@SuppressWarnings({ "unchecked", "rawtypes" })
	// We create an untyped column descriptor.  However, we are assigning it to a typed variable, 
	// which guarantees that we only put homogeneous objects into the descriptor.
	@Override
	protected TableColumnDescriptor<ROW_TYPE> createTableColumnDescriptor() {
		TableColumnDescriptor<ROW_TYPE> descriptor = new TableColumnDescriptor();

		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new AddressTableColumn()), 1, true);
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new LabelTableColumn()));
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new CodeUnitTableColumn()));

		return descriptor;
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int column) {
		if (row < 0 || row >= filteredData.size()) {
			return null;
		}

		ROW_TYPE rowObject = filteredData.get(row);
		DynamicTableColumn<ROW_TYPE, ?, ?> tableColumn = getColumn(column);
		if (tableColumn instanceof ProgramLocationTableColumn<?, ?>) {

			@SuppressWarnings("unchecked") // we checked			
			ProgramLocationTableColumn<ROW_TYPE, ?> programField =
				(ProgramLocationTableColumn<ROW_TYPE, ?>) tableColumn;
			ProgramLocation loc = programField.getProgramLocation(rowObject,
				getColumnSettings(column), getProgram(), serviceProvider);
			if (loc != null) {
				return loc;
			}
		}

		Address address = getAddress(row, column);
		if (address != null) {
			return new ProgramLocation(getProgram(), address);
		}

		return null;
	}

	private Address getAddress(int row, int column) {
		DynamicTableColumn<ROW_TYPE, ?, ?> tableColumn = getColumn(column);

		if (tableColumn instanceof ProgramLocationTableColumn<?, ?>) {
			@SuppressWarnings("unchecked")
			// we checked
			ProgramLocationTableColumn<ROW_TYPE, ?> programLocationColumn =
				(ProgramLocationTableColumn<ROW_TYPE, ?>) tableColumn;
			Settings settings = getColumnSettings(column);
			ROW_TYPE rowObject = filteredData.get(row);
			Object value =
				programLocationColumn.getValue(rowObject, settings, getProgram(), serviceProvider);
			if (value instanceof Address) {
				return (Address) value;
			}

			if (value instanceof ProgramLocation) {
				ProgramLocation programLocation = (ProgramLocation) value;
				return programLocation.getByteAddress();
			}

			ProgramLocation location = programLocationColumn.getProgramLocation(rowObject, settings,
				getProgram(), serviceProvider);
			if (location != null) {
				return location.getByteAddress();
			}
		}

		ROW_TYPE storageValue = filteredData.get(row);
		Object columnValueForRow = getColumnValueForRow(storageValue, column);
		if (columnValueForRow instanceof Address) {
			return (Address) columnValueForRow;
		}
		return getAddress(row); // TODO Perhaps this should return null?
	}

	@Override
	public ProgramSelection getProgramSelection(int[] rows) {
		AddressSet addressSet = new AddressSet();
		for (int element : rows) {
			Address addr = getAddress(element);
			if (addr.isMemoryAddress()) {
				addressSet.addRange(addr, addr);
			}
		}
		return new ProgramSelection(addressSet);
	}

}
