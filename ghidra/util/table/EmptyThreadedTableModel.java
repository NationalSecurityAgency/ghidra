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

import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.task.TaskMonitor;
import docking.widgets.table.*;
import docking.widgets.table.threaded.ThreadedTableModelStub;

/**
 * An empty implementation of the ThreadedTableModel.
 */
public class EmptyThreadedTableModel<T> extends ThreadedTableModelStub<T> {

	private String[] columnNames;

	/**
	 * Constructs a new empty table model.
	 * @param modelName the name of the model.
	 * @param columnNames the column names.
	 */
	public EmptyThreadedTableModel(String modelName, String[] columnNames) {
		super(modelName, null);
		this.columnNames = columnNames;
	}

	@Override
	protected void doLoad(Accumulator<T> accumulator, TaskMonitor monitor) {
		// stub
	}

	public Program getProgram() {
		return null;
	}

	public ProgramLocation getProgramLocation(int row, int column) {
		return null;
	}

	public ProgramSelection getProgramSelection(int[] rows) {
		return null;
	}

	@Override
	protected TableColumnDescriptor<T> createTableColumnDescriptor() {
		TableColumnDescriptor<T> descriptor = new TableColumnDescriptor<T>();

		for (String columnName : columnNames) {
			descriptor.addVisibleColumn(new NamedEmptyTableColumn(columnName));
		}

		return descriptor;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class NamedEmptyTableColumn extends AbstractDynamicTableColumnStub<T, String> {

		private final String columnName;

		NamedEmptyTableColumn(String columnName) {
			this.columnName = columnName;
		}

		@Override
		public String getValue(T rowObject, Settings settings, ServiceProvider provider)
				throws IllegalArgumentException {
			return null;
		}

		@Override
		public String getColumnName() {
			return columnName;
		}

	}
}
