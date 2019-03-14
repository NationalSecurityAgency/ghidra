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
package ghidra.app.plugin.core.disassembler;

import java.util.HashMap;

import docking.widgets.table.DiscoverableTableUtils;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.*;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.*;
import ghidra.util.task.TaskMonitor;

class AutoTableDisassemblerModel extends AddressBasedTableModel<AddressTable> {

	final static String MODEL_NAME = "Auto-table Disassembler";

	private AddressSetView addresses;
	private int minimumTableSize;
	private int alignment;
	private int skipAmount;
	private boolean shiftedAddresses;
	private HashMap<Address, AddressTable> map;

	private AutoTableDisassemblerPlugin plugin;

	AutoTableDisassemblerModel(ServiceProvider sp, AutoTableDisassemblerPlugin plugin) {

		super(MODEL_NAME, sp, null, TaskMonitor.DUMMY, true);
		this.plugin = plugin;
	}

	@Override
	protected TableColumnDescriptor<AddressTable> createTableColumnDescriptor() {
		TableColumnDescriptor<AddressTable> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new AddressTableColumn()), 1, true);
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new LabelTableColumn()));
		descriptor.addVisibleColumn(new AddressTableDataTableColumn());
		descriptor.addVisibleColumn(new AddressTableLengthTableColumn());

		return descriptor;
	}

	boolean containsKey(Address addr) {
		if (map == null) {
			return (get(addr) != null);
		}
		return map.containsKey(addr);
	}

	AddressTable get(Address addr) {
		// if map null, then map not initialized, just get it with non-cancelable task monitor
		if (map == null) {
			return get(addr, TaskMonitor.DUMMY);
		}
		return map.get(addr);
	}

	private AddressTable get(Address addr, TaskMonitor monitor) {
		AddressTable entry;

		entry = AddressTable.getEntry(getProgram(), addr, monitor, false, minimumTableSize,
			alignment, skipAmount, 0, shiftedAddresses, true, false);
		if (map != null) {
			map.put(addr, entry);
		}
		return entry;
	}

	@Override
	protected void doLoad(Accumulator<AddressTable> accumulator, TaskMonitor monitor)
			throws CancelledException {

		loadSettings();

		monitor.initialize(addresses.getNumAddresses());
		monitor.setMessage("Finding Tables...");

		int addrCount = 0;

		// iterate over addresses in the selected module
		AddressIterator addrIter = addresses.getAddresses(true);
		map = new HashMap<>();
		while (addrIter.hasNext()) {
			++addrCount;
			monitor.checkCanceled();
			monitor.setProgress(addrCount);
			Address start = addrIter.next();

			AddressTable tableEntry = get(start, monitor);
			if (tableEntry != null) {
				accumulator.add(tableEntry);

				// jump the address iterator by the size of the table entry
				int tableByteLen = tableEntry.getByteLength();
				addrCount += tableByteLen;
				start = start.add(tableByteLen);
				addrIter = addresses.getAddresses(start, true);
			}
		}
	}

	private void loadSettings() {

		setProgram(plugin.getProgram());
		this.addresses = plugin.getSelection();
		this.minimumTableSize = plugin.getMinimumTableSize();
		this.alignment = plugin.getAlignment();
		this.skipAmount = plugin.getSkipLength();
		this.shiftedAddresses = plugin.isShiftAddresses();
	}

	@Override
	public Address getAddress(int row) {
		return getRowObject(row).getTopAddress();
	}

	public int getTableLength(int row) {
		AddressTable table = getRowObject(row);
		if (table == null) {
			return 0;
		}
		return table.getNumberAddressEntries();
	}

}
