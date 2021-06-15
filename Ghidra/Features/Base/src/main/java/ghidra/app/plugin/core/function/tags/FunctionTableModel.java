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

import java.util.List;
import java.util.Set;

import docking.widgets.table.DiscoverableTableUtils;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.*;
import ghidra.util.task.TaskMonitor;

/**
 * The data model that backs the {@link AllFunctionsPanel}. This displays a list
 * of functions that have function tags matching a provided set. Note that
 * a function will be displayed as long as it has AT LEAST ONE of the tags
 * in the set.
 */
class FunctionTableModel extends AddressBasedTableModel<Function> {

	// The function tags to display functions for
	private Set<FunctionTag> tags;

	/**
	 * Constructor
	 * 
	 * @param title the title of the model
	 * @param serviceProvider the service provider
	 * @param program the current program
	 * @param monitor the task monitor
	 */
	public FunctionTableModel(String title, ServiceProvider serviceProvider, Program program,
			TaskMonitor monitor) {
		super(title, serviceProvider, program, monitor);
	}

	@Override
	public Address getAddress(int row) {
		Function rowObject = getRowObject(row);
		return rowObject.getEntryPoint();
	}

	@Override
	protected TableColumnDescriptor<Function> createTableColumnDescriptor() {
		TableColumnDescriptor<Function> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new LabelTableColumn()));
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new AddressTableColumn()), 1, true);
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new FunctionTagTableColumn()));

		return descriptor;
	}

	@Override
	protected void doLoad(Accumulator<Function> accumulator, TaskMonitor monitor)
			throws CancelledException {

		if (program == null) {
			return;
		}
		if (tags == null) {
			return;
		}

		// Loop over all functions in the program, filtering out those that do not
		// do not contain at least one of the tags in the provided set.
		FunctionIterator iter = program.getFunctionManager().getFunctions(true);
		int realFunctionCount = program.getFunctionManager().getFunctionCount();
		monitor.initialize(realFunctionCount);
		while (iter.hasNext()) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			Function f = iter.next();
			boolean hasTag = f.getTags().stream().anyMatch(t -> tags.contains(t));
			if (hasTag) {
				accumulator.add(f);
			}
		}

		FunctionIterator externals = program.getFunctionManager().getExternalFunctions();
		for (Function f : externals) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			boolean hasTag = f.getTags().stream().anyMatch(t -> tags.contains(t));
			if (hasTag) {
				accumulator.add(f);
			}
		}
	}

	/**
	 * Sets the tags associated with this model. This causes a reload of
	 * the function table
	 * 
	 * @param tags the selected tags
	 */
	public void setTags(Set<FunctionTag> tags) {
		this.tags = tags;
		reload();
	}

	/**
	 * Returns the tags being used by this model
	 * @return the tags
	 */
	public Set<FunctionTag> getTags() {
		return tags;
	}

	/**
	 * Returns the list of functions in the table
	 * 
	 * @return the contents of the table
	 */
	public List<Function> getFunctions() {
		return getAllData();
	}
}
