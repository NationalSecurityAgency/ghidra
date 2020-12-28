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
/*
 *
 */
package ghidra.program.database.code;

import java.io.IOException;

import db.*;
import ghidra.program.database.map.AddressKeyIterator;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Adapter to access the Data table.
 */
abstract class DataDBAdapter {

	static final String DATA_TABLE_NAME = "Data";

	static final Schema DATA_SCHEMA = new Schema(0, "Address", new Field[] { LongField.INSTANCE },
		new String[] { "Data Type ID" });

	static final int DATA_TYPE_ID_COL = 0;

	static DataDBAdapter getAdapter(DBHandle dbHandle, int openMode, AddressMap addrMap,
			TaskMonitor monitor) throws VersionException, CancelledException, IOException {

		if (openMode == DBConstants.CREATE) {
			return new DataDBAdapterV0(dbHandle, addrMap, true);
		}

		try {
			DataDBAdapter adapter = new DataDBAdapterV0(dbHandle, addrMap, false);
			if (addrMap.isUpgraded()) {
				throw new VersionException(true);
			}
			return adapter;
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			DataDBAdapter adapter = findReadOnlyAdapter(dbHandle, addrMap);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(dbHandle, addrMap, adapter, monitor);
			}
			return adapter;
		}
	}

	private static DataDBAdapter findReadOnlyAdapter(DBHandle handle, AddressMap addrMap)
			throws VersionException, IOException {
		return new DataDBAdapterV0(handle, addrMap.getOldAddressMap(), false);
	}

	private static DataDBAdapter upgrade(DBHandle dbHandle, AddressMap addrMap,
			DataDBAdapter oldAdapter, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {

		AddressMap oldAddrMap = addrMap.getOldAddressMap();

		DBHandle tmpHandle = new DBHandle();
		try {
			tmpHandle.startTransaction();

			monitor.setMessage("Upgrading Data...");
			monitor.initialize(oldAdapter.getRecordCount() * 2);
			int count = 0;

			DataDBAdapter tmpAdapter = new DataDBAdapterV0(tmpHandle, addrMap, true);
			RecordIterator iter = oldAdapter.getRecords();
			while (iter.hasNext()) {
				monitor.checkCanceled();
				DBRecord rec = iter.next();
				Address addr = oldAddrMap.decodeAddress(rec.getKey());
				rec.setKey(addrMap.getKey(addr, true));
				tmpAdapter.putRecord(rec);
				monitor.setProgress(++count);
			}

			dbHandle.deleteTable(DATA_TABLE_NAME);
			DataDBAdapter newAdapter = new DataDBAdapterV0(dbHandle, addrMap, true);

			iter = tmpAdapter.getRecords();
			while (iter.hasNext()) {
				monitor.checkCanceled();
				DBRecord rec = iter.next();
				newAdapter.putRecord(rec);
				monitor.setProgress(++count);
			}
			return newAdapter;
		}
		finally {
			tmpHandle.close();
		}
	}

	/**
	 * Get the record at or after the given start address.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord getRecordAtOrAfter(Address start) throws IOException;

	/**
	 * Get the Record afer the given start address.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord getRecordAfter(Address start) throws IOException;

	/**
	 * Get the record at the given start address.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord getRecord(Address start) throws IOException;

	/**
	 * Get the record at the give key;
	 * @param key the key of the record to retrieve.
	 */
	abstract DBRecord getRecord(long key) throws IOException;

	/**
	 * Get the record before the given address address.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord getRecordBefore(Address addr) throws IOException;

	/**
	 * Get a record iterator starting at the given address address.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getRecords(Address addr, boolean forward) throws IOException;

	/**
	 * Get a record iterator over the given range.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getRecords(Address start, Address end, boolean atStart)
			throws IOException;

	/**
	 * Delete the record for addr.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void deleteRecord(long key) throws IOException;

	/**
	 * Create a data record.
	 * @param addr address of data
	 * @param dataTypeID ID of data type
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord createData(Address addr, long dataTypeID) throws IOException;

	/**
	 * Get the number of records in the data table.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract int getRecordCount() throws IOException;

	/**
	 * Get the record at or before the given address address.
	 * @param addr
	 * @throws IOException if there was a problem accessing the database
	 * @return
	 */
	abstract DBRecord getRecordAtOrBefore(Address addr) throws IOException;

	/**
	 * Get a iterator over the keys in the data table.
	 * @param start start of range
	 * @param end end of range, inclusive
	 * @param atStart true means position at start of the range
	 * @throws IOException if there was a problem accessing the database
	 * @return
	 */
	abstract AddressKeyIterator getKeys(Address start, Address end, boolean atStart)
			throws IOException;

	/**
	 * Get a record iterator over all records in the data table.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getRecords() throws IOException;

	/**
	 * Deletes all records in the given range.
	 * @param start the first address in the range.
	 * @param end the last address in the range.
	 * @return true if at least on record was deleted.
	 * @throws IOException if a database io error occurs.
	 */
	abstract boolean deleteRecords(Address start, Address end) throws IOException;

	/**
	 * Puts the given record into the database.
	 * @param record the record to add or update.
	 * @throws IOException if a database io error occurs.
	 */
	abstract void putRecord(DBRecord record) throws IOException;

	/**
	 * Returns an iterator over the keys that fall within the address set provided.
	 * @param addrSetView the address set to restrict to.
	 * @param forward the direction of the iteration.
	 * @throws IOException if a database io error occurs.
	 */
	abstract AddressKeyIterator getKeys(AddressSetView addrSetView, boolean forward)
			throws IOException;

	/**
	 * Returns a record iterator over all records that fall within the given address set.
	 * @param addrSet the set to restrict to.
	 * @param forward the direction of the iterator.
	 * @throws IOException if a database io error occurs.
	 */
	abstract RecordIterator getRecords(AddressSetView set, boolean forward) throws IOException;

	/**
	 * Update the addresses in all records to reflect the movement of a memory block.
	 * @param fromAddr minimum address of the original block to be moved
	 * @param toAddr the new minimum address after the block move
	 * @param length the number of bytes in the memory block being moved
	 * @param monitor progress monitor
	 * @throws CancelledException if the user cancels the operation.
	 * @throws IOException if a database io error occurs.
	 */
	abstract void moveAddressRange(Address fromAddr, Address toAddr, long length,
			TaskMonitor monitor) throws CancelledException, IOException;

}
