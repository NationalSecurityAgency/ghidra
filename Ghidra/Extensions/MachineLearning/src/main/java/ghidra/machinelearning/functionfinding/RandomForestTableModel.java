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
package ghidra.machinelearning.functionfinding;

import java.math.BigDecimal;
import java.util.List;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModelStub;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A table model for tables that display information about random forests trained to find
 * function starts.
 */
public class RandomForestTableModel extends ThreadedTableModelStub<RandomForestRowObject> {

	private static final String MODEL_NAME = "Random Forest Evaluations";
	private List<RandomForestRowObject> rowObjects;

	/**
	 * Creates a table model 
	 * @param serviceProvider service provider
	 * @param rowObjects rows of table
	 */
	public RandomForestTableModel(ServiceProvider serviceProvider,
			List<RandomForestRowObject> rowObjects) {
		super(MODEL_NAME, serviceProvider);
		this.rowObjects = rowObjects;
	}

	@Override
	protected void doLoad(Accumulator<RandomForestRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {
		accumulator.addAll(rowObjects);

	}

	@Override
	protected TableColumnDescriptor<RandomForestRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<RandomForestRowObject> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new NumPreBytesColumn());
		descriptor.addVisibleColumn(new NumInitialBytesColumn());
		descriptor.addVisibleColumn(new SamplingFactorColumn());
		descriptor.addVisibleColumn(new FalsePositivesColumn(), 1, true);
		descriptor.addVisibleColumn(new PrecisionTableColumn());
		descriptor.addVisibleColumn(new RecallTableColumn(), 2, false);
		return descriptor;
	}

	/**
	 *  Table column classes
	 */

	class NumPreBytesColumn
			extends AbstractDynamicTableColumn<RandomForestRowObject, Integer, Object> {

		@Override
		public String getColumnName() {
			return "Pre-Bytes";
		}

		@Override
		public Integer getValue(RandomForestRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getNumPreBytes();
		}
	}

	class NumInitialBytesColumn
			extends AbstractDynamicTableColumn<RandomForestRowObject, Integer, Object> {

		@Override
		public String getColumnName() {
			return "Initial Bytes";
		}

		@Override
		public Integer getValue(RandomForestRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getNumInitialBytes();
		}
	}

	class SamplingFactorColumn
			extends AbstractDynamicTableColumn<RandomForestRowObject, Integer, Object> {

		@Override
		public String getColumnName() {
			return "Factor";
		}

		@Override
		public Integer getValue(RandomForestRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getSamplingFactor();
		}
	}

	class PrecisionTableColumn
			extends AbstractDynamicTableColumn<RandomForestRowObject, BigDecimal, Object> {

		@Override
		public String getColumnName() {
			return "Precision";
		}

		@Override
		public BigDecimal getValue(RandomForestRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getPrecision();
		}
	}

	class RecallTableColumn
			extends AbstractDynamicTableColumn<RandomForestRowObject, BigDecimal, Object> {

		@Override
		public String getColumnName() {
			return "Recall";
		}

		@Override
		public BigDecimal getValue(RandomForestRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getRecall();
		}
	}

	class FalsePositivesColumn
			extends AbstractDynamicTableColumn<RandomForestRowObject, Integer, Object> {

		@Override
		public String getColumnName() {
			return "False Positives";
		}

		@Override
		public Integer getValue(RandomForestRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getNumFalsePositives();
		}
	}
}
