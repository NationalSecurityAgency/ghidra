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
package ghidra.app.plugin.core.reachability;

import java.util.*;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.PreviewTableCellData;
import ghidra.util.table.field.PreviewTableColumn;
import ghidra.util.task.TaskMonitor;

public class FRPathsModel extends AddressBasedTableModel<FRVertex> {

	private List<FRVertex> path = Collections.emptyList();

	protected FRPathsModel(ServiceProvider serviceProvider, Program program) {
		super("Function Reachability Paths Model", serviceProvider, program, null);
	}

	@Override
	protected TableColumnDescriptor<FRVertex> createTableColumnDescriptor() {
		TableColumnDescriptor<FRVertex> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new FunctionTableColumn());
		descriptor.addVisibleColumn(new FRPreviewTableColumn());
		return descriptor;
	}

	@Override
	protected void doLoad(Accumulator<FRVertex> accumulator, TaskMonitor monitor)
			throws CancelledException {
		accumulator.addAll(path);
	}

	@Override
	protected Comparator<FRVertex> createSortComparator(int columnIndex) {
		return (o1, o2) -> path.indexOf(o1) - path.indexOf(o2);
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return false;
	}

	void setPath(List<FRVertex> path) {
		this.path = path;
		reload();
	}

	@Override
	public Address getAddress(int row) {
		// for navigation, we want to go to the place that called the function at the given row
		Address address = getReferentAddress(row);
		if (address != null) {
			return address;
		}

		FRVertex v = getRowObject(row);
		return v.getAddress();
	}

	private Address getReferentAddress(int row) {
		if (row == 0) {
			return null; // nobody calls the first function--it is the start
		}

		// get the previous row object, that is who calls this object
		FRVertex rowObject = getRowObject(row);
		FRVertex caller = getRowObject(row - 1);
		CodeBlockReference reference = rowObject.getReference(caller);

		if (reference == null) {
			// shouldn't happen
			return null;
		}

		return reference.getReferent();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class FunctionTableColumn
			extends AbstractDynamicTableColumn<FRVertex, String, Program> {

		@Override
		public String getColumnName() {
			return "Function";
		}

		@Override
		public String getValue(FRVertex rowObject, Settings settings, Program p, ServiceProvider sp)
				throws IllegalArgumentException {
			FunctionManager fm = p.getFunctionManager();
			Function f = fm.getFunctionAt(rowObject.getAddress());
			return f.toString();
		}

	}

	private class FRPreviewTableColumn
			extends AbstractDynamicTableColumn<FRVertex, PreviewTableCellData, Program> {

		private PreviewTableColumn previewTableColumn = new PreviewTableColumn();

		@Override
		public String getColumnName() {
			return "From";
		}

		@Override
		public String getColumnDescription() {
			return "A preview of the code unit calling this function";
		}

		@Override
		public PreviewTableCellData getValue(FRVertex rowObject, Settings settings, Program data,
				ServiceProvider sp) throws IllegalArgumentException {

			int row = getRowIndex(rowObject);
			if (row == 0) {
				return null; // nobody calls the first function--it is the start
			}

			// get the previous row object, that is who calls this object
			FRVertex caller = getRowObject(row - 1);
			CodeBlockReference reference = rowObject.getReference(caller);
			if (reference == null) {
				return null;
			}

			Address address = reference.getReferent();
			ProgramLocation location = new ProgramLocation(data, address);
			PreviewTableCellData preview =
				previewTableColumn.getValue(location, settings, data, sp);
			return preview;
		}
	}
}
