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

import docking.widgets.table.MappedTableColumn;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.table.field.ProgramLocationTableColumn;

public class MappedProgramLocationTableColumn<ROW_TYPE, EXPECTED_ROW_TYPE, COLUMN_TYPE>
		extends MappedTableColumn<ROW_TYPE, EXPECTED_ROW_TYPE, COLUMN_TYPE, Program>
		implements ProgramLocationTableColumn<ROW_TYPE, COLUMN_TYPE> {

	protected MappedProgramLocationTableColumn(
			ProgramLocationTableRowMapper<ROW_TYPE, EXPECTED_ROW_TYPE> mapper,
			ProgramLocationTableColumn<EXPECTED_ROW_TYPE, COLUMN_TYPE> tableColumn) {
		super(mapper, tableColumn);
	}

	protected MappedProgramLocationTableColumn(
			ProgramLocationTableRowMapper<ROW_TYPE, EXPECTED_ROW_TYPE> mapper,
			ProgramLocationTableColumn<EXPECTED_ROW_TYPE, COLUMN_TYPE> tableColumn,
			String uniqueIdentier) {
		super(mapper, tableColumn, uniqueIdentier);
	}

	@Override
	@SuppressWarnings({ "unchecked", "rawtypes" })
	// we know since we took it in the constructor
	public ProgramLocation getProgramLocation(ROW_TYPE rowObject, Settings settings,
			Program program, ServiceProvider serviceProvider) {

		if (rowObject instanceof ProgramLocation) {
			// prefer the real thing over the table column's version
			return (ProgramLocation) rowObject;
		}

		EXPECTED_ROW_TYPE mappedValue = mapper.map(rowObject, program, serviceProvider);
		return ((ProgramLocationTableColumn) tableColumn).getProgramLocation(mappedValue, settings,
			program, serviceProvider);
	}

}
