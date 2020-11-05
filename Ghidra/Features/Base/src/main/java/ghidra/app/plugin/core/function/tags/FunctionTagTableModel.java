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
package ghidra.app.plugin.core.function.tags;

import java.util.Set;

import docking.widgets.table.AbstractDynamicTableColumnStub;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.*;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Model that backs a {@link FunctionTagTable}
 */
public class FunctionTagTableModel extends ThreadedTableModel<FunctionTagRowObject, Program> {

	private Program program;
	private TagListPanel tagListPanel;

	protected FunctionTagTableModel(String modelName, ServiceProvider serviceProvider,
			TagListPanel tagLoader) {
		super(modelName, serviceProvider);
		this.tagListPanel = tagLoader;
	}

	public void setProgram(Program program) {
		this.program = program;
	}

	@Override
	protected void doLoad(Accumulator<FunctionTagRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {

		if (program == null) {
			return;
		}

		FunctionManager functionManager = program.getFunctionManager();
		FunctionTagManager tagManager = functionManager.getFunctionTagManager();
		Set<FunctionTag> tags = tagListPanel.backgroundLoadTags();
		monitor.initialize(tags.size());
		for (FunctionTag tag : tags) {
			monitor.checkCanceled();
			accumulator.add(new FunctionTagRowObject(tag, tagManager.getUseCount(tag)));
			monitor.incrementProgress(1);
		}
	}

	@Override
	protected TableColumnDescriptor<FunctionTagRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<FunctionTagRowObject> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new FunctionTagNameColumn());
		descriptor.addVisibleColumn(new FunctionTagCountColumn());

		return descriptor;
	}

	@Override
	public Program getDataSource() {
		return program;
	}

	/**
	 * Removes all function tags from the model
	 */
	public void clear() {
		super.clearData();
	}

	/**
	 * Returns true if a function tag with a given name is in the model
	 * 
	 * @param name the tag name
	 * @return true if the tag exists in the model
	 */
	public boolean containsTag(String name) {
		return getRowObject(name) != null;
	}

	/**
	 * Returns the row object that matches the given tag name
	 * @param name the tag name
	 * @return the row object
	 */
	public FunctionTagRowObject getRowObject(String name) {
		return getAllData().stream()
				.filter(row -> row.getName().equals(name))
				.findFirst()
				.orElseGet(() -> null);
	}

	/**
	 * Table column that displays a count of the number of times a function tag has been
	 * applied to a function (in the selected program)
	 */
	private class FunctionTagCountColumn
			extends AbstractDynamicTableColumnStub<FunctionTagRowObject, Integer> {

		@Override
		public String getColumnDisplayName(Settings settings) {
			// don't display any name, but need it to be at least one space wide so the correct 
			// space is allocated to the header
			return " ";
		}

		@Override
		public String getColumnName() {
			return "Count";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 30;
		}

		@Override
		public Integer getValue(FunctionTagRowObject rowObject, Settings settings,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getCount();
		}
	}

	/**
	 * Table column that displays the name of a function tag
	 */
	private class FunctionTagNameColumn
			extends AbstractDynamicTableColumnStub<FunctionTagRowObject, String> {

		@Override
		public String getColumnName() {
			return "Name";
		}

		@Override
		public String getValue(FunctionTagRowObject rowObject, Settings settings,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getName();
		}
	}
}
