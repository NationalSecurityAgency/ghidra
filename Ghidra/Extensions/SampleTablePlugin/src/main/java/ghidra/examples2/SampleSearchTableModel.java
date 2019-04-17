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
package ghidra.examples2;

import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.task.TaskMonitor;
import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;

public class SampleSearchTableModel extends AddressBasedTableModel<SearchResults> {

	private SampleSearcher searcher;

	public SampleSearchTableModel(SampleSearcher searcher, PluginTool tool) {
		super("Sample Search Results", tool, searcher.getProgram(), null);
		this.searcher = searcher;
	}

	@Override
	protected void doLoad(Accumulator<SearchResults> accumulator, TaskMonitor monitor)
			throws CancelledException {
		searcher.search(accumulator, monitor);
	}

	@Override
	protected TableColumnDescriptor<SearchResults> createTableColumnDescriptor() {
		TableColumnDescriptor<SearchResults> descriptor =
			new TableColumnDescriptor<SearchResults>();

		descriptor.addVisibleColumn(new MyAddressColumn());
		descriptor.addVisibleColumn(new MyValueColumn());

		return descriptor;
	}

	private class MyAddressColumn extends
			AbstractDynamicTableColumn<SearchResults, Address, Object> {

		@Override
		public String getColumnName() {
			return "Address";
		}

		@Override
		public Address getValue(SearchResults rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getAddress();
		}
	}

	private class MyValueColumn extends AbstractDynamicTableColumn<SearchResults, String, Object> {

		@Override
		public String getColumnName() {
			return "Value";
		}

		@Override
		public String getValue(SearchResults rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getDisplayValue();
		}
	}

	@Override
	public Address getAddress(int row) {
		return getRowObject(row).getAddress();
	}
}
