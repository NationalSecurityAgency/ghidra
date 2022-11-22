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

import java.util.List;

import javax.swing.JTable;
import javax.swing.table.TableModel;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.task.TaskMonitor;

/**
 * Table model for a table displaying the closest function starts from the training set
 * to a given potential start.
 */
public class SimilarStartsTableModel extends AddressBasedTableModel<SimilarStartRowObject> {

	private List<SimilarStartRowObject> rows;
	private RandomForestRowObject randomForestRow;

	/**
	 * Construct a table model for a table to display the closest function starts to
	 * a potential function start
	 * @param plugin owning program
	 * @param program program 
	 * @param rows similar function starts
	 * @param randomForestRow model and params
	 */
	public SimilarStartsTableModel(PluginTool plugin, Program program,
			List<SimilarStartRowObject> rows, RandomForestRowObject randomForestRow) {
		super("Similar Starts", plugin, program, null, false);
		this.rows = rows;
		this.randomForestRow = randomForestRow;
	}

	@Override
	public Address getAddress(int row) {
		return getRowObject(row).funcStart();
	}

	@Override
	protected void doLoad(Accumulator<SimilarStartRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {
		accumulator.addAll(rows);

	}

	@Override
	protected TableColumnDescriptor<SimilarStartRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<SimilarStartRowObject> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new AddressTableColumn());
		descriptor.addVisibleColumn(new SimilarityTableColumn(), 1, false);
		descriptor.addVisibleColumn(new ByteStringTableColumn());
		return descriptor;
	}

	private class AddressTableColumn
			extends AbstractDynamicTableColumn<SimilarStartRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Address";
		}

		@Override
		public String getValue(SimilarStartRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			String addrString = rowObject.funcStart().toString();
			return addrString;
		}
	}

	private class SimilarityTableColumn
			extends AbstractDynamicTableColumn<SimilarStartRowObject, Double, Object> {

		@Override
		public String getColumnName() {
			return "Similarity";
		}

		@Override
		public Double getValue(SimilarStartRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.numAgreements() * 1.0 /
				randomForestRow.getRandomForest().getNumModels();
		}
	}

	private class ByteStringTableColumn
			extends AbstractDynamicTableColumn<SimilarStartRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Byte String";
		}

		@Override
		public GColumnRenderer<String> getColumnRenderer() {
			final GColumnRenderer<String> monospacedRenderer = new AbstractGColumnRenderer<>() {
				@Override
				protected void configureFont(JTable table, TableModel model, int column) {
					setFont(getFixedWidthFont());
				}

				@Override
				public String getFilterString(String t, Settings settings) {
					return t;
				}
			};
			return monospacedRenderer;

		}

		@Override
		public String getValue(SimilarStartRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			Address funcStart = rowObject.funcStart();
			byte[] bytes =
				new byte[randomForestRow.getNumPreBytes() + randomForestRow.getNumInitialBytes()];
			try {
				program.getMemory()
						.getBytes(funcStart.subtract(randomForestRow.getNumPreBytes()), bytes);
			}
			catch (MemoryAccessException e) {
				return "??";
			}
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < randomForestRow.getNumPreBytes(); ++i) {
				sb.append(String.format("%02x ", bytes[i] & 0xff));
			}
			sb.append("* ");
			for (int i = randomForestRow.getNumPreBytes(); i < randomForestRow.getNumPreBytes() +
				randomForestRow.getNumInitialBytes(); ++i) {
				sb.append(String.format("%02x ", bytes[i] & 0xff));
			}
			return sb.toString();
		}
	}
}
