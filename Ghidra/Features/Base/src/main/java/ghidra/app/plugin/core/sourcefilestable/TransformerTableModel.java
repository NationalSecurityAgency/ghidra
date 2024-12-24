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
package ghidra.app.plugin.core.sourcefilestable;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModelStub;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.database.sourcemap.UserDataPathTransformer;
import ghidra.program.model.listing.Program;
import ghidra.program.model.sourcemap.SourcePathTransformRecord;
import ghidra.program.model.sourcemap.SourcePathTransformer;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A table model for source path transform information
 */
public class TransformerTableModel extends ThreadedTableModelStub<SourcePathTransformRecord> {

	private SourceFilesTablePlugin plugin;
	private Program program;
	private SourcePathTransformer pathTransformer;

	/**
	 * Constructor
	 * @param plugin plugin
	 */
	public TransformerTableModel(SourceFilesTablePlugin plugin) {
		super("Transformer Table Model", plugin.getTool());
		this.plugin = plugin;
		program = plugin.getCurrentProgram();
		if (program != null) {
			pathTransformer = UserDataPathTransformer.getPathTransformer(program);
		}
	}

	/**
	 * Returns the program used to populate the table 
	 * @return program
	 */
	protected Program getProgram() {
		return program;
	}

	@Override
	protected void doLoad(Accumulator<SourcePathTransformRecord> accumulator, TaskMonitor monitor)
			throws CancelledException {
		if (pathTransformer == null) {
			return;
		}
		for (SourcePathTransformRecord transformRecord : pathTransformer.getTransformRecords()) {
			accumulator.add(transformRecord);
		}
		return;
	}

	@Override
	protected TableColumnDescriptor<SourcePathTransformRecord> createTableColumnDescriptor() {
		TableColumnDescriptor<SourcePathTransformRecord> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new SourceColumn());
		descriptor.addVisibleColumn(new TargetColumn());
		descriptor.addVisibleColumn(new IsDirectoryTransformColumn());
		return descriptor;
	}

	/**
	 * Reloads the table using the path transformer for {@code newProgram}.
	 * @param newProgram program
	 */
	protected void reloadProgram(Program newProgram) {
		program = newProgram;
		pathTransformer =
			program == null ? null
					: UserDataPathTransformer.getPathTransformer(plugin.getCurrentProgram());
		reload();
	}

	private class SourceColumn
			extends AbstractDynamicTableColumn<SourcePathTransformRecord, String, Object> {

		@Override
		public String getColumnName() {
			return "Source";
		}

		@Override
		public String getValue(SourcePathTransformRecord rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			if (rowObject.isDirectoryTransform()) {
				return rowObject.source();
			}
			return rowObject.sourceFile().toString();
		}
	}

	private class TargetColumn
			extends AbstractDynamicTableColumn<SourcePathTransformRecord, String, Object> {

		@Override
		public String getColumnName() {
			return "Target";
		}

		@Override
		public String getValue(SourcePathTransformRecord rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.target();
		}
	}

	private class IsDirectoryTransformColumn
			extends AbstractDynamicTableColumn<SourcePathTransformRecord, Boolean, Object> {

		@Override
		public String getColumnName() {
			return "Directory Transform";
		}

		@Override
		public Boolean getValue(SourcePathTransformRecord rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.isDirectoryTransform();
		}
	}

}
