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
import ghidra.program.database.sourcemap.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.sourcemap.*;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A table model for displaying all of the {@link SourceFile}s which have been added
 * to a program's {@link SourceFileManager}.
 */
public class SourceFilesTableModel extends ThreadedTableModelStub<SourceFileRowObject> {

	private Program program;
	private SourceFileManager sourceManager;
	private SourcePathTransformer pathTransformer;
	private boolean useExistingAsDefault;

	/**
	 * Constructor
	 * @param sourceFilesTablePlugin plugin
	 */
	protected SourceFilesTableModel(SourceFilesTablePlugin sourceFilesTablePlugin) {
		super("Source File Table Model", sourceFilesTablePlugin.getTool());
		this.program = sourceFilesTablePlugin.getCurrentProgram();
		if (program != null) {
			sourceManager = program.getSourceFileManager();
		}
	}

	@Override
	protected TableColumnDescriptor<SourceFileRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<SourceFileRowObject> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new FileNameColumn());
		descriptor.addVisibleColumn(new PathColumn());
		descriptor.addHiddenColumn(new IdTypeColumn());
		descriptor.addHiddenColumn(new IdentifierColumn());
		descriptor.addVisibleColumn(new TransformedPathColumn());
		descriptor.addVisibleColumn(new NumMappedEntriesColumn());
		return descriptor;
	}

	@Override
	protected void doLoad(Accumulator<SourceFileRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {
		if (sourceManager == null) {
			return;
		}
		for (SourceFile sourceFile : sourceManager.getAllSourceFiles()) {
			accumulator.add(new SourceFileRowObject(sourceFile, sourceManager));
		}
	}

	/**
	 * Reloads the table using data from {@code newProgram}
	 * @param newProgram program
	 */
	protected void reloadProgram(Program newProgram) {
		program = newProgram;
		sourceManager = program == null ? null : program.getSourceFileManager();
		pathTransformer =
			program == null ? null : UserDataPathTransformer.getPathTransformer(program);
		reload();
	}

	/**
	 * Returns the program used to populate the table.
	 * @return program
	 */
	protected Program getProgram() {
		return program;
	}

	private class PathColumn
			extends AbstractDynamicTableColumn<SourceFileRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Path";
		}

		@Override
		public String getValue(SourceFileRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getPath();
		}
	}

	private class IdTypeColumn
			extends AbstractDynamicTableColumn<SourceFileRowObject, SourceFileIdType, Object> {

		@Override
		public String getColumnName() {
			return "ID Type";
		}

		@Override
		public SourceFileIdType getValue(SourceFileRowObject rowObject, Settings settings,
				Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getSourceFileIdType();
		}
	}

	private class FileNameColumn
			extends AbstractDynamicTableColumn<SourceFileRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "File Name";
		}

		@Override
		public String getValue(SourceFileRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getFileName();
		}
	}

	private class TransformedPathColumn
			extends AbstractDynamicTableColumn<SourceFileRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Transformed Path";
		}

		@Override
		public String getValue(SourceFileRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return pathTransformer.getTransformedPath(rowObject.getSourceFile(),
				useExistingAsDefault);
		}

	}

	private class IdentifierColumn
			extends AbstractDynamicTableColumn<SourceFileRowObject, String, Object> {

		@Override
		public String getColumnName() {
			return "Identifier";
		}

		@Override
		public String getValue(SourceFileRowObject rowObject, Settings settings, Object data,
				ServiceProvider sProvider) throws IllegalArgumentException {
			return rowObject.getSourceFile().getIdAsString();
		}

	}

	private class NumMappedEntriesColumn
			extends AbstractDynamicTableColumn<SourceFileRowObject, Integer, Object> {

		@Override
		public String getColumnName() {
			return "Entry Count";
		}

		@Override
		public Integer getValue(SourceFileRowObject rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.getNumSourceMapEntries();
		}
	}

}
