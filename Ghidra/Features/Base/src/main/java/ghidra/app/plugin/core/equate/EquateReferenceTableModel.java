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
package ghidra.app.plugin.core.equate;

import java.util.*;

import docking.widgets.table.*;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.table.ProgramTableModel;

class EquateReferenceTableModel extends GDynamicColumnTableModel<EquateReference, Object>
		implements ProgramTableModel {

	private EquateTablePlugin plugin;
	private List<EquateReference> referenceList = new ArrayList<>();
	private Equate currentEquate = null;

	EquateReferenceTableModel(EquateTablePlugin plugin) {
		super(plugin.getTool());
		this.plugin = plugin;
	}

	@Override
	public String getName() {
		return "Equate References";
	}

	@Override
	public List<EquateReference> getModelData() {
		return referenceList;
	}

	@Override
	public Program getProgram() {
		return plugin.getProgram();
	}

	@Override
	protected TableColumnDescriptor<EquateReference> createTableColumnDescriptor() {

		TableColumnDescriptor<EquateReference> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new EquateReferenceAddressColumn());
		descriptor.addVisibleColumn(new EquateOperandIndexColumn());

		return descriptor;
	}

	@Override
	public Object getDataSource() {
		return null;
	}

	Equate getEquate() {
		return currentEquate;
	}

	void setEquate(Equate equate) {
		this.currentEquate = equate;

		populateReferences();
	}


	private void populateReferences() {
		referenceList.clear();

		Program program = getProgram();
		if (program == null) {
			return;
		}

		EquateTable equateTable = program.getEquateTable();
		if (equateTable == null || currentEquate == null) {
			return;
		}

		// @formatter:off
		Arrays.asList(currentEquate.getReferences())
			.forEach(r -> referenceList.add(r));
		// @formatter:on

		fireTableDataChanged();
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int column) {
		EquateReference reference = getRowObject(row);
		OperandFieldLocation loc = new OperandFieldLocation(getProgram(), reference.getAddress(),
			null, null, null, reference.getOpIndex(), 0);
		return loc;
	}

	@Override
	public ProgramSelection getProgramSelection(int[] rows) {
		AddressSet addressSet = new AddressSet();
		for (int row : rows) {
			EquateReference reference = getRowObject(row);
			Address addr = reference.getAddress();
			addressSet.addRange(addr, addr);
		}
		return new ProgramSelection(addressSet);
	}

	private class EquateReferenceAddressColumn
			extends AbstractDynamicTableColumn<EquateReference, Address, Object> {

		@Override
		public String getColumnName() {
			return "Ref Addr";
		}

		@Override
		public Address getValue(EquateReference rowObject, Settings settings, Object data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getAddress();
		}

	}

	private class EquateOperandIndexColumn
			extends AbstractDynamicTableColumn<EquateReference, Short, Object> {

		@Override
		public String getColumnName() {
			return "Op Index";
		}

		@Override
		public Short getValue(EquateReference rowObject, Settings settings, Object data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getOpIndex();
		}

	}
}
