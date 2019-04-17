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
/**
 * This class is used to create tables containing {@code ByteSequenceRowObject}s
 */
package ghidra.bitpatterns.gui;

import java.awt.Font;
import java.util.List;

import javax.swing.JTable;
import javax.swing.table.TableModel;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModelStub;
import ghidra.bitpatterns.info.ByteSequenceRowObject;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.bytesearch.DittedBitSequence;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.task.TaskMonitor;

public class ByteSequenceTableModel extends ThreadedTableModelStub<ByteSequenceRowObject> {
	private static final int MONOSPACE_FONT_SIZE = 16;
	List<ByteSequenceRowObject> rowObjects;

	public ByteSequenceTableModel(FunctionBitPatternsExplorerPlugin plugin,
			List<ByteSequenceRowObject> rowObjects) {
		super("Function Start Patterns", plugin.getTool());
		this.rowObjects = rowObjects;
	}

	/**
	 * Displays the byte sequences in monospace font
	 */
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
	protected void doLoad(Accumulator<ByteSequenceRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {
		if (rowObjects != null) {
			accumulator.addAll(rowObjects);
		}
	}

	@Override
	protected TableColumnDescriptor<ByteSequenceRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<ByteSequenceRowObject> descriptor =
			new TableColumnDescriptor<ByteSequenceRowObject>();
		descriptor.addVisibleColumn(new ByteSequenceTableColumn());
		descriptor.addVisibleColumn(new ByteSequenceNumOccurrencesTableColumn(), 0, false);// default sorted column
		descriptor.addVisibleColumn(new ByteSequencePercentageTableColumn());
		return descriptor;
	}

	/**
	 * Merges the {@link DittedBitSequence}s corresponding to the selected rows.  
	 * @return merged seqeuences ({@code null} if no sequences are selected)
	 */
	public DittedBitSequence mergeSelectedRows() {
		List<ByteSequenceRowObject> rows = getLastSelectedObjects();
		if (rows.size() == 0) {
			return null;
		}
		DittedBitSequence currentMerge = ByteSequenceRowObject.merge(rows);
		return currentMerge;
	}

	//==================================================================================================
	// Inner Classes
	//==================================================================================================

	class ByteSequenceTableColumn
			extends AbstractDynamicTableColumn<ByteSequenceRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Byte Sequence";
		}

		@Override
		public String getValue(ByteSequenceRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getSequence();
		}

		@Override
		public GColumnRenderer<String> getColumnRenderer() {
			return monospacedRenderer;
		}
	}

	class ByteSequenceNumOccurrencesTableColumn
			extends AbstractDynamicTableColumn<ByteSequenceRowObject, Integer, Object> {

		@Override
		public String getColumnName() {
			return "Number Of Occurrences";
		}

		@Override
		public Integer getValue(ByteSequenceRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getNumOccurrences();
		}
	}

	class ByteSequencePercentageTableColumn
			extends AbstractDynamicTableColumn<ByteSequenceRowObject, Double, Object> {

		@Override
		public String getColumnName() {
			return "Percentage";
		}

		@Override
		public Double getValue(ByteSequenceRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getPercentage();
		}
	}

}
