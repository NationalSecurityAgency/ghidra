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
package sarif.model;

import java.util.List;
import java.util.Map;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.task.TaskMonitor;

/**
 * Just a generic table model that can handle an arbitrary number and type of
 * columns
 *
 */
public class SarifResultsTableModelFactory {
	/*
	 * Created a factory because we supply an arbitrary list of columns, and so to
	 * dynamically create the TableModel it needs to know which columns it needs in
	 * `TableColumnDescriptor` but you can't set the local variable before the
	 * `super` call
	 */
	private List<SarifColumnKey> sColumns; // Used for the TableColumnDescriptor

	public SarifResultsTableModelFactory(List<SarifColumnKey> cols) {
		sColumns = cols;
	}

	public SarifResultsTableModel createModel(String description, PluginTool tool, Program program, SarifDataFrame df) {
		return new SarifResultsTableModel(description, tool, program, df);
	}

	@SuppressWarnings("serial")
	public class SarifResultsTableModel extends AddressBasedTableModel<Map<String, Object>> {
		private SarifDataFrame df;

		public SarifResultsTableModel(String description, PluginTool tool, Program program, SarifDataFrame df) {
			super(description, tool, program, null);
			this.df = df;
		}

		public SarifDataFrame getDataFrame() {
			return this.df;
		}

		@Override
		public Address getAddress(int row) {
			return (Address) this.getRowObject(row).get("Address");
		}

		@Override
		protected void doLoad(Accumulator<Map<String, Object>> accumulator, TaskMonitor monitor)
				throws CancelledException {
			for (Map<String, Object> result : df.getTableResults()) {
				accumulator.add(result);
			}
		}

		@Override
		protected TableColumnDescriptor<Map<String, Object>> createTableColumnDescriptor() {
			TableColumnDescriptor<Map<String, Object>> descriptor = new TableColumnDescriptor<>();
			for (SarifColumnKey column : sColumns) {
				if (column.getName().equals("Address")) {
					descriptor.addVisibleColumn(new Column<Address>(column.getName(), Address.class));
				} else if (column.isHidden()) {
					descriptor.addHiddenColumn(new Column<String>(column.getName(), String.class));
				} else {
					descriptor.addVisibleColumn(new Column<String>(column.getName(), String.class));
				}
			}
			return descriptor;
		}

		public class Column<T> extends AbstractDynamicTableColumn<Map<String, Object>, T, Object> {
			private String name;
			private Class<T> type;

			/**
			 * @param name
			 * @param type Need to specify the type so that the filter table behaves how you
			 *             would expect
			 */
			public Column(String name, Class<T> type) {
				this.name = name;
				this.type = type;
			}

			@Override
			public String getColumnName() {
				return this.name;
			}

			@Override
			public Class<T> getColumnClass() {
				return type;
			}

			@SuppressWarnings("unchecked")
			@Override
			public T getValue(Map<String, Object> rowObject, Settings settings, Object data,
					ServiceProvider serviceProvider) throws IllegalArgumentException {
				Object object = rowObject.get(this.name);
				return (T) object;
			}
		}
	}
}
