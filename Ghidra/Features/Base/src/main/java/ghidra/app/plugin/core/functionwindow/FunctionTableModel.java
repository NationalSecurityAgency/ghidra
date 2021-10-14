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
package ghidra.app.plugin.core.functionwindow;

import docking.widgets.table.DiscoverableTableUtils;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.LongIterator;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.*;
import ghidra.util.task.TaskMonitor;

public class FunctionTableModel extends AddressBasedTableModel<FunctionRowObject> {

	static final int LOCATION_COL_WIDTH = 50;

	static final int NAME_COL = 0;
	static final int LOCATION_COL = 1;
	static final int PROTOTYPE_COL = 2;

	private FunctionManager functionMgr;

	public FunctionTableModel(PluginTool tool, Program program) {
		super("Functions", tool, program, null);
	}

	@Override
	protected TableColumnDescriptor<FunctionRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<FunctionRowObject> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new NameTableColumn());
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new AddressTableColumn()), 1, true);
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new FunctionSignatureTableColumn()));

		// Make function size a default column so that a user who wants to know the function size
		// won't add the "Byte Count" column (which only display the number of bytes in the code
		// unit at the function's entry point).
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new FunctionBodySizeTableColumn()));

		// Function tag column is not something widely used, so make hidden by default
		descriptor.addHiddenColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new FunctionTagTableColumn()));
		
		descriptor.addHiddenColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new IsFunctionInlineTableColumn()));
		
		descriptor.addHiddenColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new IsFunctionNonReturningTableColumn()));
		
		descriptor.addHiddenColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new IsFunctionVarargsTableColumn()));
		
		descriptor.addHiddenColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new IsFunctionCustomStorageTableColumn()));

		return descriptor;
	}

	public void reload(Program newProgram) {
		this.setProgram(newProgram);
		if (newProgram != null) {
			functionMgr = newProgram.getFunctionManager();
		}
		else {
			functionMgr = null;
		}
		reload();
	}

	public int getKeyCount() {
		if (functionMgr == null) {
			return 0;
		}
		return functionMgr.getFunctionCount();
	}

	@Override
	protected void doLoad(Accumulator<FunctionRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {

		LongIterator it = LongIterator.EMPTY;
		if (functionMgr != null) {
			it = new FunctionKeyIterator(functionMgr);
		}

		monitor.initialize(getKeyCount());
		int progress = 0;
		while (it.hasNext()) {
			monitor.setProgress(progress++);
			monitor.checkCanceled();
			long key = it.next();
			Function f = functionMgr.getFunction(key);
			accumulator.add(new FunctionRowObject(f));
		}
	}

	private class FunctionKeyIterator implements LongIterator {
		private FunctionIterator itr;

		FunctionKeyIterator(FunctionManager functionMgr) {
			itr = functionMgr.getFunctions(true);
		}

		@Override
		public boolean hasNext() {
			if (itr == null) {
				return false;
			}
			return itr.hasNext();
		}

		@Override
		public long next() {
			Function function = itr.next();
			return function.getID();
		}

		@Override
		public boolean hasPrevious() {
			throw new UnsupportedOperationException();
		}

		@Override
		public long previous() {
			throw new UnsupportedOperationException();
		}
	}

	void functionAdded(Function f) {
		addObject(new FunctionRowObject(f));
	}

	void functionRemoved(Function f) {
		removeObject(new FunctionRowObject(f));
	}

	void update(Function f) {
		updateObject(new FunctionRowObject(f));
	}

	@Override
	public Address getAddress(int row) {
		FunctionRowObject rowObject = getRowObject(row);
		FunctionManager functionManager = program.getFunctionManager();
		Function function = functionManager.getFunction(rowObject.getKey());
		return function != null ? function.getEntryPoint() : null;
	}

	private class NameTableColumn
			extends AbstractProgramBasedDynamicTableColumn<FunctionRowObject, String> {

		@Override
		public String getColumnName() {
			return "Name";
		}

		@Override
		public String getValue(FunctionRowObject rowObject, Settings settings, Program data,
				ServiceProvider sp) throws IllegalArgumentException {

			Function function = rowObject.getFunction();
			if (function == null) {
				return null;
			}
			return function.getName();
		}

	}
}
