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

import java.util.List;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.bitpatterns.info.ByteSequenceRowObject;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.task.TaskMonitor;

/**
 * This class extends {@link ByteSequenceTableModel} to add a column displaying
 * the instructions disassembled from the bytes.
 *
 */
public class DisassembledByteSequenceTableModel extends ByteSequenceTableModel {

	/**
	 * Creates a {@link DisassembledByteSequenceTableModel} for displaying sequences of bytes along
	 * with disassembly.
	 * @param plugin the plugin
	 * @param rowObjects {@link ByteSequenceRowObject}s containing the bytes to analyze.
	 */
	public DisassembledByteSequenceTableModel(FunctionBitPatternsExplorerPlugin plugin,
			List<ByteSequenceRowObject> rowObjects) {
		super(plugin, rowObjects);
		this.rowObjects = rowObjects;
	}

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
		descriptor.addVisibleColumn(new ByteSequenceDisassemblyTableColumn());
		descriptor.addVisibleColumn(new ByteSequenceNumOccurrencesTableColumn(), 0, false);// default sorted column
		descriptor.addVisibleColumn(new ByteSequencePercentageTableColumn());
		return descriptor;
	}

	private class ByteSequenceDisassemblyTableColumn
			extends AbstractDynamicTableColumn<ByteSequenceRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Disassembly";
		}

		@Override
		public String getValue(ByteSequenceRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getDisassembly();
		}

		@Override
		public GColumnRenderer<String> getColumnRenderer() {
			return monospacedRenderer;
		}
	}

}
