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
package ghidra.app.util.query;

import docking.widgets.table.DiscoverableTableUtils;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.*;
import ghidra.util.task.TaskMonitor;

/**
 * Table model that shows a location, label, and a preview column to
 * show a preview of the code unit.
 */
public abstract class ProgramLocationPreviewTableModel
		extends AddressBasedTableModel<ProgramLocation> {

	protected ProgramLocationPreviewTableModel(String modelName, ServiceProvider sp, Program prog,
			TaskMonitor monitor) {
		this(modelName, sp, prog, monitor, false);
	}

	protected ProgramLocationPreviewTableModel(String modelName, ServiceProvider sp, Program prog,
			TaskMonitor monitor, boolean loadIncrementally) {
		super(modelName, sp, prog, monitor, loadIncrementally);
	}

	@Override
	protected TableColumnDescriptor<ProgramLocation> createTableColumnDescriptor() {
		TableColumnDescriptor<ProgramLocation> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new AddressTableColumn()), 1, true);
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new LabelTableColumn()));
		descriptor.addVisibleColumn(new NamespaceTableColumn());
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new PreviewTableColumn()));

		return descriptor;
	}

	@Override
	public Address getAddress(int row) {
		ProgramLocation loc = getRowObject(row);
		return loc.getAddress();
	}

}
