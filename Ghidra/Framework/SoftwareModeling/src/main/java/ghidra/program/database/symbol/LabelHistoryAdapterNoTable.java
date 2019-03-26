/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.database.symbol;

import ghidra.program.database.map.AddressMap;
import ghidra.program.database.util.EmptyRecordIterator;
import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.Set;

import db.DBHandle;
import db.RecordIterator;

/**
 * Adapter needed when a Program is being opened read only and the label
 * history table does not exist in the Program.
 */
class LabelHistoryAdapterNoTable extends LabelHistoryAdapter {

	/**
	 * Constructs a new LabelHistoryAdapterNoTable
	 * @param handle the databse handle.
	 */
	LabelHistoryAdapterNoTable(DBHandle handle) {
	}

	/**
	 * @see ghidra.program.database.symbol.LabelHistoryAdapter#createRecord(long, byte, java.lang.String)
	 */
	@Override
	public void createRecord(long addr, byte actionID, String labelStr) throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.symbol.LabelHistoryAdapter#getRecordsByAddress(long)
	 */
	@Override
	public RecordIterator getRecordsByAddress(long addr) throws IOException {
		return new EmptyRecordIterator();
	}

	/**
	 * @see ghidra.program.database.symbol.LabelHistoryAdapter#getAllRecords()
	 */
	@Override
	public RecordIterator getAllRecords() throws IOException {
		return new EmptyRecordIterator();
	}

	/**
	 * @see ghidra.program.database.symbol.LabelHistoryAdapter#getRecordCount()
	 */
	@Override
	int getRecordCount() {
		return 0;
	}

	/**
	 * @see ghidra.program.database.symbol.LabelHistoryAdapter#moveAddress(long, long)
	 */
	@Override
	void moveAddress(long oldAddr, long newAddr) throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.symbol.LabelHistoryAdapter#moveAddressRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address, long, ghidra.program.model.address.AddressMap, ghidra.util.task.TaskMonitor)
	 */
	@Override
	void moveAddressRange(Address fromAddr, Address toAddr, long length, AddressMap addrMap,
			TaskMonitor monitor) throws CancelledException, IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.symbol.LabelHistoryAdapter#deleteAddressRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address, ghidra.program.model.address.AddressMap, ghidra.util.task.TaskMonitor)
	 */
	@Override
	void deleteAddressRange(Address startAddr, Address endAddr, AddressMap addrMap,
			Set<Address> set, TaskMonitor monitor) throws CancelledException, IOException {
		throw new UnsupportedOperationException();
	}

}
