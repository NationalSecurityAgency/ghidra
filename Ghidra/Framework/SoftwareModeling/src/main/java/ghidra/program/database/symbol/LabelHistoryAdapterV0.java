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
package ghidra.program.database.symbol;

import java.io.IOException;
import java.util.Date;
import java.util.Set;

import db.*;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.map.AddressRecordDeleter;
import ghidra.program.database.util.DatabaseTableUtils;
import ghidra.program.database.util.RecordFilter;
import ghidra.program.model.address.Address;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Version 0 of the Label History adapter.
 */
class LabelHistoryAdapterV0 extends LabelHistoryAdapter {

	private Table table;
	private String userName;

	/**
	 * Constructs a new LabelHistoryAdapterV0
	 * @param handle the database handle.
	 * @param create if true, create the tables.
	 * @throws VersionException if the database table version does not match this adapter's version.
	 * @throws IOException if a database io error occurs.
	 */
	LabelHistoryAdapterV0(DBHandle handle, boolean create) throws VersionException, IOException {

		if (create) {
			table = handle.createTable(LABEL_HISTORY_TABLE_NAME, LABEL_HISTORY_SCHEMA,
				new int[] { HISTORY_ADDR_COL });
		}
		else {
			table = handle.getTable(LABEL_HISTORY_TABLE_NAME);
			if (table == null) {
				throw new VersionException(true);
			}
			else if (table.getSchema().getVersion() != 0) {
				throw new VersionException(VersionException.NEWER_VERSION, false);
			}
		}
		userName = SystemUtilities.getUserName();
	}

	static LabelHistoryAdapter upgrade(DBHandle dbHandle, AddressMap addrMap,
			LabelHistoryAdapter oldAdapter, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {

		AddressMap oldAddrMap = addrMap.getOldAddressMap();

		DBHandle tmpHandle = new DBHandle();
		try {
			tmpHandle.startTransaction();

			monitor.setMessage("Upgrading Label History...");
			monitor.initialize(oldAdapter.getRecordCount() * 2);
			int count = 0;

			LabelHistoryAdapterV0 tmpAdapter = new LabelHistoryAdapterV0(tmpHandle, true);
			RecordIterator iter = oldAdapter.getAllRecords();
			while (iter.hasNext()) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				DBRecord rec = iter.next();
				Address addr = oldAddrMap.decodeAddress(rec.getLongValue(HISTORY_ADDR_COL));
				rec.setLongValue(HISTORY_ADDR_COL, addrMap.getKey(addr, true));
				tmpAdapter.table.putRecord(rec);
				monitor.setProgress(++count);
			}

			dbHandle.deleteTable(LABEL_HISTORY_TABLE_NAME);
			LabelHistoryAdapterV0 newAdapter = new LabelHistoryAdapterV0(dbHandle, true);

			iter = tmpAdapter.getAllRecords();
			while (iter.hasNext()) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				DBRecord rec = iter.next();
				newAdapter.table.putRecord(rec);
				monitor.setProgress(++count);
			}
			return newAdapter;
		}
		finally {
			tmpHandle.close();
		}
	}

	/**
	 * @see ghidra.program.database.symbol.LabelHistoryAdapter#createRecord(long, java.lang.String)
	 */
	@Override
	public void createRecord(long addr, byte actionID, String labelStr) throws IOException {

		DBRecord rec = table.getSchema().createRecord(table.getKey());

		rec.setLongValue(HISTORY_ADDR_COL, addr);
		rec.setByteValue(HISTORY_ACTION_COL, actionID);
		rec.setString(HISTORY_LABEL_COL, labelStr);
		rec.setString(HISTORY_USER_COL, userName);
		rec.setLongValue(HISTORY_DATE_COL, new Date().getTime());

		table.putRecord(rec);
	}

	/**
	 * @see ghidra.program.database.symbol.LabelHistoryAdapter#getAllRecords()
	 */
	@Override
	public RecordIterator getAllRecords() throws IOException {
		return table.iterator();
	}

	/**
	 * @see ghidra.program.database.symbol.LabelHistoryAdapter#getRecordsByAddress(long)
	 */
	@Override
	public RecordIterator getRecordsByAddress(long addr) throws IOException {
		LongField field = new LongField(addr);
		return table.indexIterator(HISTORY_ADDR_COL, field, field, true);
	}

	/**
	 * @see ghidra.program.database.symbol.LabelHistoryAdapter#getRecordCount()
	 */
	@Override
	int getRecordCount() {
		return table.getRecordCount();
	}

	/**
	 * @see ghidra.program.database.symbol.LabelHistoryAdapter#moveAddress(long, long)
	 */
	@Override
	void moveAddress(long oldAddr, long newAddr) throws IOException {
		Field[] keys = table.findRecords(new LongField(oldAddr), HISTORY_ADDR_COL);
		for (Field key : keys) {
			DBRecord rec = table.getRecord(key);
			rec.setLongValue(HISTORY_ADDR_COL, newAddr);
			table.putRecord(rec);
		}
	}

	/**
	 * @see ghidra.program.database.symbol.LabelHistoryAdapter#moveAddressRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address, long, ghidra.program.model.address.AddressMap, ghidra.util.task.TaskMonitor)
	 */
	@Override
	void moveAddressRange(Address fromAddr, Address toAddr, long length, final AddressMap addrMap,
			TaskMonitor monitor) throws CancelledException, IOException {

		DatabaseTableUtils.updateIndexedAddressField(table, HISTORY_ADDR_COL, addrMap, fromAddr,
			toAddr, length, null, monitor);
	}

	/**
	 * @see ghidra.program.database.symbol.LabelHistoryAdapter#deleteAddressRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address, ghidra.program.model.address.AddressMap, ghidra.util.task.TaskMonitor)
	 */
	@Override
	void deleteAddressRange(Address startAddr, Address endAddr, final AddressMap addrMap,
			final Set<Address> set, TaskMonitor monitor) throws CancelledException, IOException {
		RecordFilter filter = new RecordFilter() {
			@Override
			public boolean matches(DBRecord record) {
				Address addr = addrMap.decodeAddress(record.getLongValue(HISTORY_ADDR_COL));
				return set == null || !set.contains(addr);
			}
		};
		AddressRecordDeleter.deleteRecords(table, HISTORY_ADDR_COL, addrMap, startAddr, endAddr,
			filter);
	}

}
