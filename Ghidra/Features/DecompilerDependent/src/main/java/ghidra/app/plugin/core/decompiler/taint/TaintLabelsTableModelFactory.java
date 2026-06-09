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
package ghidra.app.plugin.core.decompiler.taint;

import java.util.List;
import java.util.Map;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighVariable;
import ghidra.util.Msg;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.task.TaskMonitor;

public class TaintLabelsTableModelFactory {

	private List<String> sColumns; // Used for the TableColumnDescriptor

	public TaintLabelsTableModelFactory(List<String> cols) {
		sColumns = cols;
	}

	public TaintLabelsTableModel createModel(String description, TaintPlugin plugin,
			Program program, TaintLabelsDataFrame df, TaintLabelsTableProvider provider) {
		return new TaintLabelsTableModel(description, plugin, program, df, provider);
	}

	public class TaintLabelsTableModel extends AddressBasedTableModel<Map<String, Object>> {
		private static final long serialVersionUID = 1L;
		private TaintLabelsDataFrame df;
		private TaintLabelsTableProvider provider;
		private TaintPlugin plugin;

		public TaintLabelsTableModel(String description, TaintPlugin plugin, Program program,
				TaintLabelsDataFrame df, TaintLabelsTableProvider provider) {
			super(description, plugin.getTool(), program, null);
			this.df = df;
			this.provider = provider;
			this.plugin = plugin;
		}

		@Override
		public boolean isCellEditable(int row, int col) {
			String colName = this.getColumnName(col);
			if (colName == "Selected" || colName == "Label")
				return true;
			return false;
		}

		@Override
		public void setValueAt(Object obj, int row, int col) {

			String colName = this.getColumnName(col);

			Msg.info(this, "Set (" + row + "," + col + ") with colName: " + colName + " Value: " +
				obj.toString());

			// The table retains instances of the column -> data mappings when it accumulates.
			Map<String, Object> mapping = provider.filterTable.getRowObject(row);
			TaintLabel tlabel = (TaintLabel) mapping.get("Taint Label Object");

			switch (colName) {

				case "Selected" -> {
					boolean selected = (boolean) mapping.get(colName);
					mapping.put(colName, !selected);
					// TODO This should just change the instance that is the same as what is in State...
					tlabel.toggle();
					plugin.toggleMarginIcon(tlabel);
				}
				case "Label" -> {
					String newLabel = (String) obj;
					mapping.put(colName, newLabel);
					tlabel.setLabel(newLabel);
				}
				default -> {
					Msg.warn(this, "Unable to set value at "+colName);
				}
			}
		}

		public TaintLabelsDataFrame getDataFrame() {
			return this.df;
		}

		@Override
		public Address getAddress(int row) {
			return (Address) this.getRowObject(row).get("Address");
		}

		@Override
		protected void doLoad(Accumulator<Map<String, Object>> accumulator, TaskMonitor monitor)
				throws CancelledException {

			Msg.info(this, "doLoad attempting to load the table.");

			// tableResults is a list of Maps; each map is a row in the table.
			for (Map<String, Object> result : df.getData()) {

				Msg.info(this, "Loading: " + result.get("Taint Label Object"));

				if (monitor.isCancelled()) {
					monitor.clearCancelled();
					break;
				}

				accumulator.add(result);
			}
		}

		@Override
		protected TableColumnDescriptor<Map<String, Object>> createTableColumnDescriptor() {

			TableColumnDescriptor<Map<String, Object>> descriptor = new TableColumnDescriptor<>();

			for (String columnName : sColumns) {

				switch (columnName) {
					case "Address":
					case "Function Address":
						descriptor.addVisibleColumn(new AddressColumn(columnName));
						break;
					case "Category":
					case "Name":
						descriptor.addVisibleColumn(new StringColumn(columnName));
						break;
					case "Selected":
						descriptor.addVisibleColumn(new BooleanColumn(columnName));
						break;
					case "Taint Label Object":
						descriptor.addHiddenColumn(new TaintLabelColumn(columnName));
						break;
					default:
						descriptor.addVisibleColumn(new Column(columnName));
						break;
				}
			}
			return descriptor;
		}

		public class Column
				extends AbstractDynamicTableColumn<Map<String, Object>, Object, Object> {
			private String columnName;

			public Column(String name) {
				columnName = name;
			}

			@Override
			public String getColumnName() {
				return columnName;
			}

			@Override
			public Object getValue(Map<String, Object> rowObject, Settings settings, Object data,
					ServiceProvider sp) throws IllegalArgumentException {
				return rowObject.get(getColumnName());
			}

		}

		public class HighVariableColumn
				extends AbstractDynamicTableColumn<Map<String, Object>, HighVariable, Object> {
			private String columnName;

			public HighVariableColumn(String name) {
				columnName = name;
			}

			@Override
			public String getColumnName() {
				return columnName;
			}

			@Override
			public HighVariable getValue(Map<String, Object> rowObject, Settings settings,
					Object data, ServiceProvider sp) throws IllegalArgumentException {
				return (HighVariable) rowObject.get(getColumnName());
			}

		}

		public class TaintLabelColumn
				extends AbstractDynamicTableColumn<Map<String, Object>, TaintLabel, Object> {
			private String columnName;

			public TaintLabelColumn(String name) {
				columnName = name;
			}

			@Override
			public String getColumnName() {
				return columnName;
			}

			@Override
			public TaintLabel getValue(Map<String, Object> rowObject, Settings settings,
					Object data, ServiceProvider sp) throws IllegalArgumentException {
				return (TaintLabel) rowObject.get(getColumnName());
			}
		}

		public class StringColumn
				extends AbstractDynamicTableColumn<Map<String, Object>, String, Object> {
			private String name;

			public StringColumn(String name) {
				this.name = name;
			}

			@Override
			public String getColumnName() {
				return this.name;
			}

			@Override
			public String getValue(Map<String, Object> rowObject, Settings settings, Object data,
					ServiceProvider sp) throws IllegalArgumentException {

				// pull out of the table row, the data associated with this COLUMN.
				Object o = rowObject.get(this.name);
				if (o == null) {
					return "NULL";
				}
				return o.toString();
			}

		}

		public class BooleanColumn
				extends AbstractDynamicTableColumn<Map<String, Object>, Boolean, Object> {
			private String name;

			public BooleanColumn(String name) {
				this.name = name;
			}

			@Override
			public String getColumnName() {
				return this.name;
			}

			@Override
			public Boolean getValue(Map<String, Object> rowObject, Settings settings, Object data,
					ServiceProvider sp) throws IllegalArgumentException {
				return (Boolean) rowObject.get(this.name);
			}

		}

		public class AddressColumn
				extends AbstractDynamicTableColumn<Map<String, Object>, Address, Object> {
			private String name;

			public AddressColumn(String name) {
				this.name = name;
			}

			@Override
			public String getColumnName() {
				return this.name;
			}

			@Override
			public Address getValue(Map<String, Object> rowObject, Settings settings, Object data,
					ServiceProvider sp) throws IllegalArgumentException {
				return (Address) rowObject.get(this.name);
			}

		}

		public class IntegerColumn
				extends AbstractDynamicTableColumn<Map<String, Object>, Integer, Object> {
			private String name;

			public IntegerColumn(String name) {
				this.name = name;
			}

			@Override
			public String getColumnName() {
				return this.name;
			}

			@Override
			public Integer getValue(Map<String, Object> rowObject, Settings settings, Object data,
					ServiceProvider sp) throws IllegalArgumentException {
				Object o = rowObject.get(this.name);
				if (o == null) {
					return -1;
				}
				return (Integer) o;
			}

		}
	}
}
