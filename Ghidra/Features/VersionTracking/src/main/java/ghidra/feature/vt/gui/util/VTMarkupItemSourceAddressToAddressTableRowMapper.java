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
import docking.widgets.table.MappedTableColumn;
import ghidra.docking.settings.Settings;
import ghidra.feature.vt.api.main.VTMarkupItem;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.table.*;
import ghidra.util.table.field.ProgramLocationTableColumn;

public class VTMarkupItemSourceAddressToAddressTableRowMapper extends
		ProgramLocationTableRowMapper<VTMarkupItem, Address> {

	@Override
	public <COLUMN_TYPE> DynamicTableColumn<VTMarkupItem, COLUMN_TYPE, Program> createMappedTableColumn(
			DynamicTableColumn<Address, COLUMN_TYPE, Program> SourceColumn) {
		if (SourceColumn instanceof ProgramLocationTableColumn<?, ?>) {
			ProgramLocationTableColumn<Address, COLUMN_TYPE> programColumn =
				(ProgramLocationTableColumn<Address, COLUMN_TYPE>) SourceColumn;
			return new VTMarkupItemSourceWrappedMappedProgramLocationTableColumn<COLUMN_TYPE>(this,
				programColumn);
		}

		return new VTMarkupItemSourceWrappedMappedTableColumn<COLUMN_TYPE>(this, SourceColumn);
	}

	@Override
	public Address map(VTMarkupItem rowObject, Program program, ServiceProvider serviceProvider) {
		return rowObject.getSourceAddress();
	}

	private class VTMarkupItemSourceWrappedMappedProgramLocationTableColumn<COLUMN_TYPE> extends
			MappedProgramLocationTableColumn<VTMarkupItem, Address, COLUMN_TYPE> {

		public VTMarkupItemSourceWrappedMappedProgramLocationTableColumn(
				ProgramLocationTableRowMapper<VTMarkupItem, Address> mapper,
				ProgramLocationTableColumn<Address, COLUMN_TYPE> tableColumn) {
			super(mapper, tableColumn, "VTMarkupItemSource." + tableColumn.getUniqueIdentifier());
		}

		@Override
		public String getColumnDisplayName(Settings settings) {
			return "Source " + super.getColumnDisplayName(settings);
		}

		@Override
		public String getColumnDescription() {
			return super.getColumnName() + " (for a markup items's Source address)";
		}

		@Override
		public String getColumnName() {
			return "Source " + super.getColumnName();
		}
	}

	private class VTMarkupItemSourceWrappedMappedTableColumn<COLUMN_TYPE> extends
			MappedTableColumn<VTMarkupItem, Address, COLUMN_TYPE, Program> {

		public VTMarkupItemSourceWrappedMappedTableColumn(
				ProgramLocationTableRowMapper<VTMarkupItem, Address> mapper,
				DynamicTableColumn<Address, COLUMN_TYPE, Program> tableColumn) {
			super(mapper, tableColumn, "VTMarkupItemSource." + tableColumn.getUniqueIdentifier());
		}

		@Override
		public String getColumnDisplayName(Settings settings) {
			return "Source " + super.getColumnDisplayName(settings);
		}

		@Override
		public String getColumnDescription() {
			return super.getColumnName() + " (for a markup items's Source address)";
		}

		@Override
		public String getColumnName() {
			return "Source " + super.getColumnName();
		}
	}
}
