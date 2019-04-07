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
import ghidra.feature.vt.api.main.VTAssociation;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.table.MappedProgramLocationTableColumn;
import ghidra.util.table.ProgramLocationTableRowMapper;
import ghidra.util.table.field.ProgramLocationTableColumn;

public class VTMatchDestinationAddressToAddressTableRowMapper extends
		ProgramLocationTableRowMapper<VTMatch, Address> {

	@Override
	public <COLUMN_TYPE> DynamicTableColumn<VTMatch, COLUMN_TYPE, Program> createMappedTableColumn(
			DynamicTableColumn<Address, COLUMN_TYPE, Program> destinationColumn) {
		if (destinationColumn instanceof ProgramLocationTableColumn<?, ?>) {
			ProgramLocationTableColumn<Address, COLUMN_TYPE> programColumn =
				(ProgramLocationTableColumn<Address, COLUMN_TYPE>) destinationColumn;
			return new VTMatchDestinationWrappedMappedProgramLocationTableColumn<COLUMN_TYPE>(this,
				programColumn);
		}

		return new VTMatchDestinationWrappedMappedTableColumn<COLUMN_TYPE>(this, destinationColumn);
	}

	@Override
	public Address map(VTMatch rowObject, Program program, ServiceProvider serviceProvider) {
		VTAssociation association = rowObject.getAssociation();
		return association.getDestinationAddress();
	}

	private class VTMatchDestinationWrappedMappedProgramLocationTableColumn<COLUMN_TYPE> extends
			MappedProgramLocationTableColumn<VTMatch, Address, COLUMN_TYPE> {

		public VTMatchDestinationWrappedMappedProgramLocationTableColumn(
				ProgramLocationTableRowMapper<VTMatch, Address> mapper,
				ProgramLocationTableColumn<Address, COLUMN_TYPE> tableColumn) {
			super(mapper, tableColumn, "VTMatchDestination." + tableColumn.getUniqueIdentifier());
		}

		@Override
		public COLUMN_TYPE getValue(VTMatch rowObject, Settings settings, Program data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			Program destinationProgram =
				rowObject.getMatchSet().getSession().getDestinationProgram();
			return super.getValue(rowObject, settings, destinationProgram, serviceProvider);
		}

		@Override
		public String getColumnDisplayName(Settings settings) {
			return "Dest " + super.getColumnDisplayName(settings);
		}

		@Override
		public String getColumnDescription() {
			return super.getColumnName() + " (for a match's destination address)";
		}

		@Override
		public String getColumnName() {
			return "Dest " + super.getColumnName();
		}
	}

	private class VTMatchDestinationWrappedMappedTableColumn<COLUMN_TYPE> extends
			MappedTableColumn<VTMatch, Address, COLUMN_TYPE, Program> {

		public VTMatchDestinationWrappedMappedTableColumn(
				ProgramLocationTableRowMapper<VTMatch, Address> mapper,
				DynamicTableColumn<Address, COLUMN_TYPE, Program> tableColumn) {
			super(mapper, tableColumn, "VTMatchDestination." + tableColumn.getUniqueIdentifier());
		}

		@Override
		public COLUMN_TYPE getValue(VTMatch rowObject, Settings settings, Program data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			Program destinationProgram =
				rowObject.getMatchSet().getSession().getDestinationProgram();
			return super.getValue(rowObject, settings, destinationProgram, serviceProvider);
		}

		@Override
		public String getColumnDisplayName(Settings settings) {
			return "Dest " + super.getColumnDisplayName(settings);
		}

		@Override
		public String getColumnDescription() {
			return super.getColumnName() + " (for a match's destination address)";
		}

		@Override
		public String getColumnName() {
			return "Dest " + super.getColumnName();
		}
	}
}
