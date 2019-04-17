/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
import ghidra.program.model.listing.Program;

public class ProgramMappedTableColumn<ROW_TYPE, EXPECTED_ROW_TYPE, COLUMN_TYPE> extends
		MappedTableColumn<ROW_TYPE, EXPECTED_ROW_TYPE, COLUMN_TYPE, Program> {

	protected ProgramMappedTableColumn(TableRowMapper<ROW_TYPE, EXPECTED_ROW_TYPE, Program> mapper,
			DynamicTableColumn<EXPECTED_ROW_TYPE, COLUMN_TYPE, Program> tableColumn) {
		this(mapper, tableColumn, tableColumn.getUniqueIdentifier());
	}

	protected ProgramMappedTableColumn(TableRowMapper<ROW_TYPE, EXPECTED_ROW_TYPE, Program> mapper,
			DynamicTableColumn<EXPECTED_ROW_TYPE, COLUMN_TYPE, Program> tableColumn,
			String uniqueIdentifier) {
		super(mapper, tableColumn, uniqueIdentifier);
	}

}
