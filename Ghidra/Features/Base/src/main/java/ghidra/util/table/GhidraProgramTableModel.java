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
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.table.field.*;
import ghidra.util.task.TaskMonitor;

public abstract class GhidraProgramTableModel<ROW_TYPE>
		extends ThreadedTableModel<ROW_TYPE, Program> implements ProgramTableModel {

	protected Program program;

	protected GhidraProgramTableModel(String modelName, ServiceProvider serviceProvider,
			Program program, TaskMonitor monitor) {
		this(modelName, serviceProvider, program, monitor, false);
	}

	protected GhidraProgramTableModel(String modelName, ServiceProvider serviceProvider,
			Program program, TaskMonitor monitor, boolean loadIncrementally) {
		super(modelName, serviceProvider, monitor, loadIncrementally);
		this.program = program;
	}

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

	public void setProgram(Program program) {
		Program originalProgram = this.program;
		this.program = program;

		if (originalProgram != program) {
			clearData();
		}
	}

	/**
	 * Extension point for getting a row-specific program.  Most models don't need this
	 * capability.
	 * @param t The ROW_TYPE row object
	 * @return the program
	 */
	protected Program getProgramForRow(ROW_TYPE t) {
		return getProgram();
	}

	@Override
	public Program getProgram() {
		return program;
	}

	@Override
	public Program getDataSource() {
		return getProgram();
	}

	@Override
	public void dispose() {
		program = null;
		super.dispose();
	}

	/**
	 * Returns an address for the given row and column.
	 * @param modelRow the model row
	 * @param modelColumn the column row
	 * @return the address
	 */
	public Address getAddress(int modelRow, int modelColumn) {

		//
		// Try to find an address for the given cell.
		//
		// 1) Prefer columns that have a ProgramLocation, as they are already used for navigation.
		//
		ROW_TYPE rowObject = filteredData.get(modelRow);
		DynamicTableColumn<ROW_TYPE, ?, ?> tableColumn = getColumn(modelColumn);
		if (tableColumn instanceof ProgramLocationTableColumn<?, ?>) {
			@SuppressWarnings("unchecked")
			// we checked
			ProgramLocationTableColumn<ROW_TYPE, ?> programLocationColumn =
				(ProgramLocationTableColumn<ROW_TYPE, ?>) tableColumn;
			Settings settings = getColumnSettings(modelColumn);
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

		//
		// 2) See if the given cell value is an Address
		//
		Object columnValue = getColumnValueForRow(rowObject, modelColumn);
		if (columnValue instanceof Address) {
			return (Address) columnValue;
		}

		//
		// 3) Check to see if we can get an Address directly from my row object
		//
		Address address = getAddress(modelRow);
		if (address != null) {
			return address;
		}

		//
		// 4) Check for the case where we are using a mapped column that converted the current row
		// object into an Address row object.
		// 
		Object mappedRowObject = getMappedRowObject(tableColumn, rowObject, modelColumn);
		if (mappedRowObject instanceof Address) {
			return (Address) mappedRowObject;
		}

		return null;
	}

	/**
	 * Returns the best Address for the given row.  
	 * <P>
	 * Implementation Note: this class will only return an Address if this model's row type is
	 * Address.  Clients that know how to get an Address for a given row should override this 
	 * method.
	 * @param modelRow the row
	 * @return the Address or null
	 */
	public Address getAddress(int modelRow) {
		ROW_TYPE rowObject = filteredData.get(modelRow);
		if (rowObject instanceof Address) {
			return (Address) rowObject;
		}
		return null;
	}

	/**
	 * If the given column supports row mapping, then use that column to get the mapped row.  In 
	 * this case, our table may have a row object, like Function, that the column maps to another
	 * type that it needs, like Address.
	 * 
	 * @param tableColumn the table column
	 * @param currentRowObject the table's actual non-mapped row value
	 * @param columnIndex the column index
	 * @return the mapped row value or null
	 */
	@SuppressWarnings("unchecked")
	private Object getMappedRowObject(DynamicTableColumn<ROW_TYPE, ?, ?> tableColumn,
			ROW_TYPE currentRowObject, int columnIndex) {

		if (tableColumn instanceof MappedTableColumn) {
			@SuppressWarnings("rawtypes")
			MappedTableColumn mappedColumn = (MappedTableColumn) tableColumn;
			return mappedColumn.map(currentRowObject, getProgram(), serviceProvider);
		}
		return null;
	}

	@Override
	public ProgramLocation getProgramLocation(int modelRow, int modelColumn) {
		if (modelRow < 0 || modelRow >= filteredData.size()) {
			return null;
		}

		ROW_TYPE rowObject = filteredData.get(modelRow);
		DynamicTableColumn<ROW_TYPE, ?, ?> tableColumn = getColumn(modelColumn);
		if (tableColumn instanceof ProgramLocationTableColumn<?, ?>) {

			@SuppressWarnings("unchecked") // we checked			
			ProgramLocationTableColumn<ROW_TYPE, ?> programField =
				(ProgramLocationTableColumn<ROW_TYPE, ?>) tableColumn;
			ProgramLocation loc = programField.getProgramLocation(rowObject,
				getColumnSettings(modelColumn), getProgram(), serviceProvider);
			if (loc != null) {
				return loc;
			}
		}

		Address address = getAddress(modelRow, modelColumn);
		if (address != null) {
			return new ProgramLocation(getProgram(), address);
		}

		return null;
	}

	@Override
	public ProgramSelection getProgramSelection(int[] modelRows) {
		AddressSet addressSet = new AddressSet();
		for (int element : modelRows) {
			Address addr = getAddress(element);
			if (addr.isMemoryAddress()) {
				addressSet.addRange(addr, addr);
			}
		}
		return new ProgramSelection(addressSet);
	}
}
