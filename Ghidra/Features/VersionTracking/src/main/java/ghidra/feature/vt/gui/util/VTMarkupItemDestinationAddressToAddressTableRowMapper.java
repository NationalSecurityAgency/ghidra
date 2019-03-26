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
package ghidra.feature.vt.gui.util;

import docking.widgets.table.DynamicTableColumn;
import docking.widgets.table.TableRowMapper;
import ghidra.docking.settings.Settings;
import ghidra.feature.vt.api.main.VTMarkupItem;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.table.*;
import ghidra.util.table.field.ProgramLocationTableColumn;

public class VTMarkupItemDestinationAddressToAddressTableRowMapper extends
		ProgramLocationTableRowMapper<VTMarkupItem, Address> {

	@Override
	public <COLUMN_TYPE> DynamicTableColumn<VTMarkupItem, COLUMN_TYPE, Program> createMappedTableColumn(
			DynamicTableColumn<Address, COLUMN_TYPE, Program> destinationColumn) {
		if (destinationColumn instanceof ProgramLocationTableColumn<?, ?>) {
			ProgramLocationTableColumn<Address, COLUMN_TYPE> programColumn =
				(ProgramLocationTableColumn<Address, COLUMN_TYPE>) destinationColumn;
			return new VTMarkupItemDestinationWrappedMappedProgramLocationTableColumn<COLUMN_TYPE>(
				this, programColumn);
		}

		return new VTMarkupItemDestinationWrappedMappedTableColumn<COLUMN_TYPE>(this,
			destinationColumn);
	}

	@Override
	public Address map(VTMarkupItem rowObject, Program program, ServiceProvider serviceProvider) {
		return rowObject.getDestinationAddress();
	}

	private class VTMarkupItemDestinationWrappedMappedProgramLocationTableColumn<COLUMN_TYPE>
			extends MappedProgramLocationTableColumn<VTMarkupItem, Address, COLUMN_TYPE> {

		public VTMarkupItemDestinationWrappedMappedProgramLocationTableColumn(
				ProgramLocationTableRowMapper<VTMarkupItem, Address> mapper,
				ProgramLocationTableColumn<Address, COLUMN_TYPE> tableColumn) {
			super(mapper, tableColumn, "VTMarkupItemDestination." +
				tableColumn.getUniqueIdentifier());
		}

		@Override
		public String getColumnDisplayName(Settings settings) {
			return "Dest " + super.getColumnDisplayName(settings);
		}

		@Override
		public String getColumnDescription() {
			return super.getColumnName() + " (for a markup items's destination address)";
		}

		@Override
		public String getColumnName() {
			return "Dest " + super.getColumnName();
		}
	}

	private class VTMarkupItemDestinationWrappedMappedTableColumn<COLUMN_TYPE> extends
			ProgramMappedTableColumn<VTMarkupItem, Address, COLUMN_TYPE> {

		public VTMarkupItemDestinationWrappedMappedTableColumn(
				TableRowMapper<VTMarkupItem, Address, Program> mapper,
				DynamicTableColumn<Address, COLUMN_TYPE, Program> tableColumn) {
			super(mapper, tableColumn, "VTMarkupItemDestination." +
				tableColumn.getUniqueIdentifier());
		}

		@Override
		public String getColumnDisplayName(Settings settings) {
			return "Dest " + super.getColumnDisplayName(settings);
		}

		@Override
		public String getColumnDescription() {
			return super.getColumnName() + " (for a markup items's destination address)";
		}

		@Override
		public String getColumnName() {
			return "Dest " + super.getColumnName();
		}
	}
}
