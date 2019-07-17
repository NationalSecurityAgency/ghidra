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
package ghidra.app.plugin.core.datawindow;

import docking.widgets.table.DiscoverableTableUtils;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramSelection;
import ghidra.util.LongIterator;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.table.field.AddressTableColumn;
import ghidra.util.task.TaskMonitor;

class DataTableModel extends AddressBasedTableModel<DataRowObject> {

	static final int ADDRESS_COL_WIDTH = 50;
	static final int SIZE_COL_WIDTH = 30;

	static final int DATA_COL = 0;
	static final int LOCATION_COL = 1;
	static final int TYPE_COL = 2;
	static final int SIZE_COL = 3;

	private DataWindowPlugin plugin;
	private AddressMapImpl addressMap;
	private Listing listing;
	private AddressSet addresses;

	DataTableModel(DataWindowPlugin plugin) {
		super("Data", plugin.getTool(), null, null);
		this.plugin = plugin;
	}

	@Override
	protected TableColumnDescriptor<DataRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<DataRowObject> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new DataValueTableColumn());
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new AddressTableColumn()), 1, true);
		descriptor.addVisibleColumn(new TypeTableColumn());
		descriptor.addVisibleColumn(new SizeTableColumn());

		return descriptor;
	}

	void reload(Program newProgram) {
		this.setProgram(newProgram);
		addresses = plugin.getLimitedAddresses();
		if (newProgram != null) {
			addressMap = new AddressMapImpl();
			listing = newProgram.getListing();
		}
		else {
			addressMap = null;
			listing = null;
		}
		reload();
	}

	private int getKeyCount() {
		if (listing == null) {
			return 0;
		}
		return (int) listing.getNumDefinedData();
	}

	@Override
	protected void doLoad(Accumulator<DataRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {
		LongIterator it = LongIterator.EMPTY;
		if (listing != null) {
			it = new DataKeyIterator();
		}
		monitor.initialize(getKeyCount());
		int progress = 0;
		while (it.hasNext()) {
			monitor.setProgress(progress++);
			monitor.checkCanceled();
			long key = it.next();
			if (filterAccepts(key)) {
				accumulator.add(new DataRowObject(key, addressMap));
			}
		}
	}

	public boolean filterAccepts(long key) {
		if (listing == null || addressMap == null) {
			return false;
		}

		Data curData = listing.getDataAt(addressMap.decodeAddress(key));
		String displayName = curData.getDataType().getDisplayName();
		if (addresses != null) {
			return plugin.typeEnabled(displayName) && addresses.contains(curData.getMinAddress());
		}
		return plugin.typeEnabled(displayName);
	}

	private class DataKeyIterator implements LongIterator {
		private DataIterator itr;

		DataKeyIterator() {
			itr = listing.getDefinedData(getProgram().getMemory(), true);
		}

		@Override
		public boolean hasNext() {
			if (itr == null || getProgram() == null)
				return false;
			return itr.hasNext();
		}

		@Override
		public long next() {
			Data data = itr.next();
			if (addressMap != null) {
				return addressMap.getKey(data.getMinAddress());
			}
			return 0;
		}

		@Override
		public boolean hasPrevious() {
			return false;
		}

		@Override
		public long previous() {
			return -1;
		}
	}

	void dataAdded(Address addr) {
		Data data = listing.getDataAt(addr);
		if (data != null) {
			long key = addressMap.getKey(addr);
			if (filterAccepts(key)) {
				addObject(new DataRowObject(key, addressMap));
			}
		}
	}

	void dataRemoved(Address addr) {
		removeObject(new DataRowObject(addressMap.getKey(addr), addressMap));
	}

	@Override
	public ProgramSelection getProgramSelection(int[] rows) {
		AddressSet set = new AddressSet();
		for (int element : rows) {
			DataRowObject rowObject = getRowObject(element);
			Data data = listing.getDataAt(rowObject.getAddress());
			if (data != null) {
				set.addRange(data.getMinAddress(), data.getMaxAddress());
			}
		}
		return new ProgramSelection(set);
	}

	@Override
	public Address getAddress(int row) {
		return getRowObject(row).getAddress();
	}

	private Data getDataForRowObject(DataRowObject t) {
		return listing.getDataAt(t.getAddress());
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class DataValueTableColumn
			extends AbstractProgramBasedDynamicTableColumn<DataRowObject, String> {

		@Override
		public String getColumnName() {
			return "Data";
		}

		@Override
		public String getValue(DataRowObject rowObject, Settings settings, Program program,
				ServiceProvider provider) throws IllegalArgumentException {
			Data data = getDataForRowObject(rowObject);
			if (data == null) {
				return null;
			}
			DataType dt = data.getDataType();
			// NOTE: settings definitions are not currently provided by column since every 
			// data type could have a unique set of supported settings
			return dt.getRepresentation(data, settings, data.getLength());
		}
	}

	private class TypeTableColumn
			extends AbstractProgramBasedDynamicTableColumn<DataRowObject, String> {

		@Override
		public String getColumnName() {
			return "Type";
		}

		@Override
		public String getValue(DataRowObject rowObject, Settings settings, Program program,
				ServiceProvider provider) throws IllegalArgumentException {
			Data data = getDataForRowObject(rowObject);
			if (data == null) {
				return null;
			}

			return data.getDataType().getDisplayName();
		}

	}

	private class SizeTableColumn
			extends AbstractProgramBasedDynamicTableColumn<DataRowObject, Integer> {

		@Override
		public String getColumnName() {
			return "Size";
		}

		@Override
		public Integer getValue(DataRowObject rowObject, Settings settings, Program program,
				ServiceProvider provider) throws IllegalArgumentException {
			Data data = getDataForRowObject(rowObject);
			if (data == null) {
				return null;
			}

			return new Integer(data.getLength());
		}

	}
}
