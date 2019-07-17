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
package ghidra.examples;

import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorSplitter;

import java.util.List;

import docking.widgets.table.*;
import docking.widgets.table.threaded.ThreadedTableModelStub;

class SampleTableModel extends ThreadedTableModelStub<FunctionStatsRowObject> {

	private SampleTablePlugin plugin;

	SampleTableModel(SampleTablePlugin plugin) {
		super("Sample Table Model", plugin.getTool());
		this.plugin = plugin;
	}

	@Override
	protected TableColumnDescriptor<FunctionStatsRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<FunctionStatsRowObject> descriptor =
			new TableColumnDescriptor<FunctionStatsRowObject>();

		descriptor.addVisibleColumn(new FunctionNameTableColumn());
		descriptor.addVisibleColumn(new AlgorithmTableColumn());
		descriptor.addVisibleColumn(new ScoreTableColumn(), 0, true); // default sorted column
		descriptor.addHiddenColumn(new AddressTableColumn()); // hidden by default

		return descriptor;
	}

	@Override
	protected void doLoad(Accumulator<FunctionStatsRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {
		if (!plugin.resetExisingTableData()) {
			accumulator.addAll(getModelData());
		}

		Function function = plugin.getFunction();
		if (function == null) {
			return; // not inside a function
		}

		List<FunctionAlgorithm> algorithms = plugin.getAlgorithms();
		TaskMonitor[] taskMonitors =
			TaskMonitorSplitter.splitTaskMonitor(monitor, algorithms.size());
		for (int i = 0; i < algorithms.size(); i++) {
			FunctionAlgorithm algorithm = algorithms.get(i);
			TaskMonitor subMonitor = taskMonitors[i];
			subMonitor.setMessage("Computing score using " + algorithm.getName());
			int score = algorithm.score(function, subMonitor);
			String name = algorithm.getName();
			accumulator.add(new FunctionStatsRowObject(function, name, score));
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class FunctionNameTableColumn extends
			AbstractDynamicTableColumn<FunctionStatsRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Name";
		}

		@Override
		public String getValue(FunctionStatsRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getFunctionName();
		}
	}

	private class AlgorithmTableColumn extends
			AbstractDynamicTableColumn<FunctionStatsRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Algorithm";
		}

		@Override
		public String getValue(FunctionStatsRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getAlgorithmName();
		}
	}

	private class ScoreTableColumn extends
			AbstractDynamicTableColumn<FunctionStatsRowObject, Integer, Object> {

		@Override
		public String getColumnName() {
			return "Score";
		}

		@Override
		public Integer getValue(FunctionStatsRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getScore();
		}
	}

	private class AddressTableColumn extends
			AbstractDynamicTableColumn<FunctionStatsRowObject, Address, Object> {

		@Override
		public String getColumnName() {
			return "Address";
		}

		@Override
		public Address getValue(FunctionStatsRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getAddress();
		}
	}
}
