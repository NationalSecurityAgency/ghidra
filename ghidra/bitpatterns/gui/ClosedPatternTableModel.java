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
package ghidra.bitpatterns.gui;

import java.awt.Font;
import java.util.List;

import javax.swing.JTable;
import javax.swing.table.TableModel;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModelStub;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.task.TaskMonitor;

/**
 * 
 * This class describes the tables used to display the patterns found by
 * the pattern miner.
 *
 */
public class ClosedPatternTableModel extends ThreadedTableModelStub<ClosedPatternRowObject> {
	private List<ClosedPatternRowObject> rowObjects;

	private static final String MODEL_NAME = "Closed Patterns";
	private static final int MONOSPACE_FONT_SIZE = 16;

	/**
	 * Creates a table model for closed patterns mined from byte sequences
	 * @param rowObjects
	 * @param serviceProvider
	 */
	public ClosedPatternTableModel(List<ClosedPatternRowObject> rowObjects,
			ServiceProvider serviceProvider) {
		super(MODEL_NAME, serviceProvider);
		this.rowObjects = rowObjects;

	}

	protected GColumnRenderer<String> monospacedRenderer = new AbstractGColumnRenderer<String>() {
		@Override
		protected void configureFont(JTable table, TableModel model, int column) {
			Font f = new Font("monospaced", getFixedWidthFont().getStyle(), MONOSPACE_FONT_SIZE);
			setFont(f);
		}

		@Override
		public String getFilterString(String t, Settings settings) {
			return t;
		}
	};

	@Override
	protected void doLoad(Accumulator<ClosedPatternRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {
		if (rowObjects != null) {
			accumulator.addAll(rowObjects);
		}

	}

	@Override
	protected TableColumnDescriptor<ClosedPatternRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<ClosedPatternRowObject> descriptor =
			new TableColumnDescriptor<ClosedPatternRowObject>();
		descriptor.addVisibleColumn(new ClosedPatternTableColumn());
		descriptor.addVisibleColumn(new ClosedPatternFixedBitsTableColumn(), 0, false);//default sorted column
		descriptor.addVisibleColumn(new ClosedPatternNumOccurrencesTableColumn());
		descriptor.addVisibleColumn(new ClosedPatternPercentageTableColumn());
		return descriptor;
	}

	//==================================================================================================
	// Inner Classes
	//==================================================================================================

	class ClosedPatternTableColumn
			extends AbstractDynamicTableColumn<ClosedPatternRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Byte Sequence";
		}

		@Override
		public GColumnRenderer<String> getColumnRenderer() {
			return monospacedRenderer;
		}

		@Override
		public String getValue(ClosedPatternRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getDittedString();
		}

	}

	class ClosedPatternNumOccurrencesTableColumn
			extends AbstractDynamicTableColumn<ClosedPatternRowObject, Integer, Object> {

		@Override
		public String getColumnName() {
			return "Number of Occurrences";
		}

		@Override
		public Integer getValue(ClosedPatternRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getNumOccurrences();
		}

	}

	class ClosedPatternFixedBitsTableColumn
			extends AbstractDynamicTableColumn<ClosedPatternRowObject, Integer, Object> {

		@Override
		public String getColumnName() {
			return "Fixed Bits";
		}

		@Override
		public Integer getValue(ClosedPatternRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getNumFixedBits();
		}

	}

	class ClosedPatternPercentageTableColumn
			extends AbstractDynamicTableColumn<ClosedPatternRowObject, Double, Object> {

		@Override
		public String getColumnName() {
			return "Percentage";
		}

		@Override
		public Double getValue(ClosedPatternRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getPercentage();
		}
	}

}
