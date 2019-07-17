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
package ghidra.app.tablechooser;

import java.util.Comparator;

import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;

public class ColumnDisplayDynamicTableColumnAdapter<COLUMN_TYPE>
		extends AbstractProgramBasedDynamicTableColumn<AddressableRowObject, COLUMN_TYPE>
		implements Comparator<AddressableRowObject> {

	private final ColumnDisplay<COLUMN_TYPE> display;

	public ColumnDisplayDynamicTableColumnAdapter(ColumnDisplay<COLUMN_TYPE> display) {
		super(display.getColumnName());
		this.display = display;
	}

	@Override
	public Class<COLUMN_TYPE> getColumnClass() {
		return display.getColumnClass();
	}

	@Override
	public String getColumnName() {
		return display.getColumnName();
	}

	@Override
	public COLUMN_TYPE getValue(AddressableRowObject rowObject, Settings settings, Program program,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		return display.getColumnValue(rowObject);
	}

	@Override
	public int compare(AddressableRowObject o1, AddressableRowObject o2) {
		return display.compare(o1, o2);
	}
}
