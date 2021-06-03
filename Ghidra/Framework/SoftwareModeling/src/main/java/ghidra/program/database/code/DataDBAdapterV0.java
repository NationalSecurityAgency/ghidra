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
package ghidra.program.database.code;

import ghidra.program.database.map.*;
import ghidra.program.database.util.DatabaseTableUtils;
import ghidra.program.model.address.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

import db.*;

/**
 * Version 0 implementation for the Data table.
 * 
 * 
 */
class DataDBAdapterV0 extends DataDBAdapter {

	private Table dataTable;
	private AddressMap addrMap;

	/**
	 * Constructor
	 * 
	 */
	public DataDBAdapterV0(DBHandle handle, AddressMap addrMap, boolean create) throws IOException,
			VersionException {
		this.addrMap = addrMap;
		if (create) {
			dataTable = handle.createTable(DATA_TABLE_NAME, DATA_SCHEMA);
		}
		else {
			dataTable = handle.getTable(DATA_TABLE_NAME);
			if (dataTable == null) {
				throw new VersionException("Missing Table: " + DATA_TABLE_NAME);
			}
			if (dataTable.getSchema().getVersion() != 0) {
				throw new VersionException(VersionException.NEWER_VERSION, false);
			}
		}
	}

	/**
	 * @see ghidra.program.database.code.DataDBAdapter#getRecordAtOrAfter(ghidra.program.model.address.Address)
	 */
	@Override
	DBRecord getRecordAtOrAfter(Address addr) throws IOException {
		AddressKeyRecordIterator it = new AddressKeyRecordIterator(dataTable, addrMap, addr, true);
		return it.next();
	}

	/**
	 * @see ghidra.program.database.code.DataDBAdapter#getRecordAtOrBefore(long)
	 */
	@Override
	DBRecord getRecordAtOrBefore(Address addr) throws IOException {
		AddressKeyRecordIterator it = new AddressKeyRecordIterator(dataTable, addrMap, addr, false);
		return it.previous();
	}

	/**
	 * @see ghidra.program.database.code.DataDBAdapter#getRecordAfter(long)
	 */
	@Override
	DBRecord getRecordAfter(Address addr) throws IOException {
		AddressKeyRecordIterator it = new AddressKeyRecordIterator(dataTable, addrMap, addr, false);
		return it.next();
	}

	/**
	 * @see ghidra.program.database.code.DataDBAdapter#getRecord(long)
	 */
	@Override
	DBRecord getRecord(Address addr) throws IOException {
		return dataTable.getRecord(addrMap.getKey(addr, false));
	}

	/**
	 * @see ghidra.program.database.code.DataDBAdapter#getRecord(long)
	 */
	@Override
	DBRecord getRecord(long key) throws IOException {
		return dataTable.getRecord(key);
	}

	/**
	 * @see ghidra.program.database.code.DataDBAdapter#getRecordBefore(long)
	 */
	@Override
	DBRecord getRecordBefore(Address addr) throws IOException {
		AddressKeyRecordIterator it = new AddressKeyRecordIterator(dataTable, addrMap, addr, true);
		return it.previous();
	}

	/**
	 * @see ghidra.program.database.code.DataDBAdapter#getRecords(long)
	 */
	@Override
	RecordIterator getRecords(Address addr, boolean forward) throws IOException {
		return new AddressKeyRecordIterator(dataTable, addrMap, addr, forward);
	}

	/**
	 * @see ghidra.program.database.code.MoveRangeAdapter#getRecords(long, long, boolean)
	 */
	@Override
	RecordIterator getRecords(Address start, Address end, boolean atStart) throws IOException {

		if (atStart) {
			return new AddressKeyRecordIterator(dataTable, addrMap, start, end, start, true);
		}
		return new AddressKeyRecordIterator(dataTable, addrMap, start, end, end, false);
	}

	/**
	 * @see ghidra.program.database.code.DataDBAdapter#getRecords(ghidra.program.model.address.AddressSetView, boolean)
	 */
	@Override
	RecordIterator getRecords(AddressSetView set, boolean forward) throws IOException {
		return new AddressKeyRecordIterator(dataTable, addrMap, set, forward ? set.getMinAddress()
				: set.getMaxAddress(), forward);
	}

	/**
	 * @see ghidra.program.database.code.DataDBAdapter#removeData(long)
	 */
	@Override
	void deleteRecord(long key) throws IOException {
		dataTable.deleteRecord(key);
	}

	/**
	 * @see ghidra.program.database.code.DataDBAdapter#createData(long, long)
	 */
	@Override
	DBRecord createData(Address newAddr, long dataTypeID) throws IOException {
		long key = addrMap.getKey(newAddr, true);
		DBRecord record = DATA_SCHEMA.createRecord(key);
		record.setLongValue(DATA_TYPE_ID_COL, dataTypeID);
		dataTable.putRecord(record);
		return record;
	}

	/**
	 * @see ghidra.program.database.code.DataDBAdapter#removeData(long, long)
	 */
	@Override
	boolean deleteRecords(Address start, Address end) throws IOException {
		return AddressRecordDeleter.deleteRecords(dataTable, addrMap, start, end);
	}

	/**
	 * @see ghidra.program.database.code.DataDBAdapter#getRecordCount()
	 */
	@Override
	int getRecordCount() throws IOException {
		return dataTable.getRecordCount();
	}

	/**
	 * @see ghidra.program.database.code.DataDBAdapter#getKeys(long, long)
	 */
	@Override
	AddressKeyIterator getKeys(Address start, Address end, boolean atStart) throws IOException {
		if (atStart) {
			return new AddressKeyIterator(dataTable, addrMap, start, end, start, true);
		}
		return new AddressKeyIterator(dataTable, addrMap, start, end, end, false);
	}

	/**
	 * @see ghidra.program.database.code.DataDBAdapter#getKeys(ghidra.program.model.address.AddressSetView, boolean)
	 */
	@Override
	AddressKeyIterator getKeys(AddressSetView set, boolean forward) throws IOException {
		if (forward) {
			return new AddressKeyIterator(dataTable, addrMap, set, set.getMinAddress(), true);
		}
		return new AddressKeyIterator(dataTable, addrMap, set, set.getMaxAddress(), false);
	}

	/**
	 * @see ghidra.program.database.code.MoveRangeAdapter#putRecord(ghidra.framework.store.db.DBRecord)
	 */
	@Override
	void putRecord(DBRecord record) throws IOException {
		dataTable.putRecord(record);
	}

	/**
	 * @see ghidra.program.database.code.DataDBAdapter#getRecords()
	 */
	@Override
	RecordIterator getRecords() throws IOException {
		return new AddressKeyRecordIterator(dataTable, addrMap);
	}

	/**
	 * @see ghidra.program.database.code.DataDBAdapter#moveAddressRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address, long, ghidra.util.task.TaskMonitor)
	 */
	@Override
	void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException, IOException {
		DatabaseTableUtils.updateAddressKey(dataTable, addrMap, fromAddr, toAddr, length, monitor);
	}

}
