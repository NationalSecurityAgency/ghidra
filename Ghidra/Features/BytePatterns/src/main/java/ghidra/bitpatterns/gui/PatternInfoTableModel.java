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

import javax.swing.JTable;
import javax.swing.table.TableModel;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModelStub;
import ghidra.bitpatterns.info.PatternType;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.task.TaskMonitor;

/**
 * Table model for table to display selected patterns
 */

public class PatternInfoTableModel extends ThreadedTableModelStub<PatternInfoRowObject> {

	private static final String MODEL_NAME = "Pattern Clipboard";
	private FunctionBitPatternsExplorerPlugin plugin;
	private static final int NOTE_COLUMN = 2;
	private static final int ALIGNMENT_COLUMN = 5;
	private static final int MONOSPACE_FONT_SIZE = 14;

	public PatternInfoTableModel(FunctionBitPatternsExplorerPlugin plugin) {
		super(MODEL_NAME, plugin.getTool());
		this.plugin = plugin;
	}

	@Override
	protected void doLoad(Accumulator<PatternInfoRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {
		accumulator.addAll(plugin.getPatterns());
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
	public boolean isCellEditable(int row, int columnIndex) {
		if (columnIndex == NOTE_COLUMN) {
			return true;
		}
		//alignment only matters for post-patterns
		if (columnIndex == ALIGNMENT_COLUMN) {
			PatternInfoRowObject rowObject = filteredData.get(row);
			return (rowObject.getPatternType().equals(PatternType.FIRST));
		}
		return false;
	}

	@Override
	public void setValueAt(Object aValue, int row, int columnIndex) {
		if (row < 0 || row >= filteredData.size()) {
			return;
		}
		PatternInfoRowObject rowObject = filteredData.get(row);
		if (columnIndex == NOTE_COLUMN) {
			rowObject.setNote((String) aValue);
		}
		if (columnIndex == ALIGNMENT_COLUMN) {
			Integer newValue = (Integer) aValue;
			//alignment must be a power of 2
			if (newValue <= 0) {
				rowObject.setAlignment(null);
				return;
			}
			if ((newValue & (newValue - 1)) == 0) {
				rowObject.setAlignment((Integer) aValue);
			}
			else {
				rowObject.setAlignment(null);
			}
		}
	}

	@Override
	protected TableColumnDescriptor<PatternInfoRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<PatternInfoRowObject> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new PatternTypeTableColumn(), 1, true);
		descriptor.addVisibleColumn(new DittedBitSequenceTableColumn());
		descriptor.addVisibleColumn(new NoteTableColumn());
		descriptor.addVisibleColumn(new BitsOfCheckTableColumn());
		descriptor.addVisibleColumn(new ContextRegisterFilterTableColumn());
		descriptor.addVisibleColumn(new AlignmentTableColumn());

		return descriptor;
	}

	/*********************************************************************************************/
	//==================================================================================================
	// Inner Classes
	//==================================================================================================

	class PatternTypeTableColumn
			extends AbstractDynamicTableColumn<PatternInfoRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Pattern Type";
		}

		@Override
		public String getValue(PatternInfoRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			if (rowObject.getPatternType().equals(PatternType.FIRST)) {
				return "POST";
			}
			return "PRE";
		}
	}

	class NoteTableColumn extends AbstractDynamicTableColumn<PatternInfoRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Note";
		}

		@Override
		public String getValue(PatternInfoRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getNote();
		}
	}

	class DittedBitSequenceTableColumn
			extends AbstractDynamicTableColumn<PatternInfoRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Bit Sequence";
		}

		@Override
		public GColumnRenderer<String> getColumnRenderer() {
			return monospacedRenderer;
		}

		@Override
		public String getValue(PatternInfoRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getDittedBitSequence().getHexString();
		}
	}

	class BitsOfCheckTableColumn
			extends AbstractDynamicTableColumn<PatternInfoRowObject, Integer, Object> {

		@Override
		public String getColumnName() {
			return "Bits of Check";
		}

		@Override
		public Integer getValue(PatternInfoRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getDittedBitSequence().getNumFixedBits();
		}
	}

	class ContextRegisterFilterTableColumn
			extends AbstractDynamicTableColumn<PatternInfoRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Context Register Filter";
		}

		@Override
		public String getValue(PatternInfoRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			if (rowObject.getContextRegisterFilter() == null) {
				return null;
			}
			return rowObject.getContextRegisterFilter().getCompactString();
		}
	}

	class AlignmentTableColumn
			extends AbstractDynamicTableColumn<PatternInfoRowObject, Integer, Object> {

		@Override
		public String getColumnName() {
			return "Alignment";
		}

		@Override
		public Integer getValue(PatternInfoRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getAlignment();
		}
	}

}
