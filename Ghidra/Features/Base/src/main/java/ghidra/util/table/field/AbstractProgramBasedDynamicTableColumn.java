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
package ghidra.util.table.field;

import docking.widgets.table.AbstractDynamicTableColumn;
import ghidra.program.model.listing.Program;

public abstract class AbstractProgramBasedDynamicTableColumn<ROW_TYPE, COLUMN_TYPE> extends
		AbstractDynamicTableColumn<ROW_TYPE, COLUMN_TYPE, Program> {

	// just a stub/marker to mark our DATA_SOURCE as the Program type

	public AbstractProgramBasedDynamicTableColumn() {
		super();
	}

	public AbstractProgramBasedDynamicTableColumn(String uniqueID) {
		super(uniqueID);
	}
}
