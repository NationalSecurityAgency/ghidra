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
import ghidra.bitpatterns.info.PatternEvalRowObject;
import ghidra.bitpatterns.info.PatternMatchType;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.task.TaskMonitor;

public class PatternEvalTabelModel extends AddressBasedTableModel<PatternEvalRowObject> {
	private static final int MONOSPACE_FONT_SIZE = 14;
	private List<PatternEvalRowObject> rowObjects;

	/**
	 * Defines the table format for the Pattern Evaluation table
	 * @param plugin plugin
	 * @param program data source
	 * @param rowObjects row object for pattern evaluation table
	 */
	public PatternEvalTabelModel(FunctionBitPatternsExplorerPlugin plugin, Program program,
			List<PatternEvalRowObject> rowObjects) {
		super("Pattern Evaluation", plugin.getTool(), program, null);
		this.rowObjects = rowObjects;
	}

	@Override
	public Address getAddress(int row) {
		PatternEvalRowObject rowObject = this.getRowObject(row);
		return rowObject.getMatchedAddress();

	}

	protected final GColumnRenderer<String> monospacedRenderer =
		new AbstractGColumnRenderer<String>() {
			@Override
			protected void configureFont(JTable table, TableModel model, int column) {
				Font f =
					new Font("monospaced", getFixedWidthFont().getStyle(), MONOSPACE_FONT_SIZE);
				setFont(f);
			}

			@Override
			public String getFilterString(String t, Settings settings) {
				return t;
			}
		};

	@Override
	protected TableColumnDescriptor<PatternEvalRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<PatternEvalRowObject> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new AddressTableColumn());
		descriptor.addVisibleColumn(new MatchTypeTableColumn(), 0, true);
		descriptor.addVisibleColumn(new PostBitsColumn());
		descriptor.addVisibleColumn(new TotalBitsColumn());
		descriptor.addVisibleColumn(new PatternStringTableColumn());
		return descriptor;
	}

	@Override
	protected void doLoad(Accumulator<PatternEvalRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {
		if (rowObjects != null) {
			accumulator.addAll(rowObjects);
		}
	}

	//******************************************************************************************//

	private class MatchTypeTableColumn
			extends AbstractDynamicTableColumn<PatternEvalRowObject, PatternMatchType, Object> {

		@Override
		public String getColumnName() {
			return "Match Type";
		}

		@Override
		public PatternMatchType getValue(PatternEvalRowObject rowObject, Settings settings,
				Object data, ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getMatchType();
		}
	}

	private class AddressTableColumn
			extends AbstractDynamicTableColumn<PatternEvalRowObject, Address, Object> {

		@Override
		public String getColumnName() {
			return "Address";
		}

		@Override
		public Address getValue(PatternEvalRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getMatchedAddress();
		}
	}

	private class PostBitsColumn
			extends AbstractDynamicTableColumn<PatternEvalRowObject, Integer, Object> {

		@Override
		public String getColumnName() {
			return "Postbits";
		}

		@Override
		public Integer getValue(PatternEvalRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getPostBits();
		}
	}

	private class TotalBitsColumn
			extends AbstractDynamicTableColumn<PatternEvalRowObject, Integer, Object> {

		@Override
		public String getColumnName() {
			return "Totalbits";
		}

		@Override
		public Integer getValue(PatternEvalRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getTotalBits();
		}
	}

	private class PatternStringTableColumn
			extends AbstractDynamicTableColumn<PatternEvalRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Pattern";
		}

		@Override
		public GColumnRenderer<String> getColumnRenderer() {
			return monospacedRenderer;
		}

		@Override
		public String getValue(PatternEvalRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getPatternString();
		}
	}

}
