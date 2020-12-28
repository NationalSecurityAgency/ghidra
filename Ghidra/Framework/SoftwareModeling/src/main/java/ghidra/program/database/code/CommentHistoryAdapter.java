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

import java.io.IOException;

import db.*;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Adapter for accessing records in the CommentHistory table.
 */
abstract class CommentHistoryAdapter {

	static final String COMMENT_HISTORY_TABLE_NAME = "Comment History";

	static final Schema COMMENT_HISTORY_SCHEMA = new Schema(0, "Key",
		new Field[] { LongField.INSTANCE, ByteField.INSTANCE, IntField.INSTANCE, IntField.INSTANCE,
			StringField.INSTANCE, StringField.INSTANCE, LongField.INSTANCE },
		new String[] { "Address", "Comment Type", "Pos1", "Pos2", "String Data", "User", "Date" });

	static final int HISTORY_ADDRESS_COL = 0;
	static final int HISTORY_TYPE_COL = 1;
	static final int HISTORY_POS1_COL = 2;
	static final int HISTORY_POS2_COL = 3;
	static final int HISTORY_STRING_COL = 4;
	static final int HISTORY_USER_COL = 5;
	static final int HISTORY_DATE_COL = 6;

	static CommentHistoryAdapter getAdapter(DBHandle dbHandle, int openMode, AddressMap addrMap,
			TaskMonitor monitor) throws VersionException, CancelledException, IOException {

		if (openMode == DBConstants.CREATE) {
			return new CommentHistoryAdapterV0(dbHandle, addrMap, true);
		}

		try {
			CommentHistoryAdapter adapter = new CommentHistoryAdapterV0(dbHandle, addrMap, false);
			if (addrMap.isUpgraded()) {
				throw new VersionException(true);
			}
			return adapter;
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			CommentHistoryAdapter adapter = findReadOnlyAdapter(dbHandle, addrMap);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(dbHandle, addrMap, adapter, monitor);
			}
			return adapter;
		}
	}

	@SuppressWarnings("unused")
	private static CommentHistoryAdapter findReadOnlyAdapter(DBHandle handle, AddressMap addrMap)
			throws VersionException, IOException {
		try {
			return new CommentHistoryAdapterV0(handle, addrMap.getOldAddressMap(), false);
		}
		catch (VersionException e) {
			// use the 'no table' below
		}

		return new CommentHistoryAdapterNoTable();
	}

	private static CommentHistoryAdapter upgrade(DBHandle dbHandle, AddressMap addrMap,
			CommentHistoryAdapter oldAdapter, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {

		AddressMap oldAddrMap = addrMap.getOldAddressMap();

		DBHandle tmpHandle = new DBHandle();
		try {
			tmpHandle.startTransaction();

			monitor.setMessage("Upgrading Comment History...");
			monitor.initialize(oldAdapter.getRecordCount() * 2);
			int count = 0;

			CommentHistoryAdapter tmpAdapter =
				new CommentHistoryAdapterV0(tmpHandle, addrMap, true);
			RecordIterator iter = oldAdapter.getAllRecords();
			while (iter.hasNext()) {
				monitor.checkCanceled();
				DBRecord rec = iter.next();
				Address addr = oldAddrMap.decodeAddress(rec.getLongValue(HISTORY_ADDRESS_COL));
				rec.setLongValue(HISTORY_ADDRESS_COL, addrMap.getKey(addr, true));
				tmpAdapter.updateRecord(rec);
				monitor.setProgress(++count);
			}

			dbHandle.deleteTable(COMMENT_HISTORY_TABLE_NAME);
			CommentHistoryAdapter newAdapter = new CommentHistoryAdapterV0(dbHandle, addrMap, true);

			iter = tmpAdapter.getAllRecords();
			while (iter.hasNext()) {
				monitor.checkCanceled();
				DBRecord rec = iter.next();
				newAdapter.updateRecord(rec);
				monitor.setProgress(++count);
			}
			return newAdapter;
		}
		finally {
			tmpHandle.close();
		}
	}

	/**
	 * Returns the record count
	 * @return the record count
	 */
	abstract int getRecordCount();

	/**
	 * Create a comment history record.
	 * @param addr address of the changed record
	 * @param commentType see CodeManager constants for comment type
	 * @param pos1 position 1 of change
	 * @param pos2 position 2 of change
	 * @param data string from the comment change
	 * @param date the date of the history entry
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void createRecord(long addr, byte commentType, int pos1, int pos2, String data,
			long date) throws IOException;

	/**
	 * Update record
	 * @param rec the record to update
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void updateRecord(DBRecord rec) throws IOException;

	/**
	 * Delete the records in the given range.
	 * @param start start address (key)
	 * @param end address (key)
	 * @return true if at least one record was removed in the range
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract boolean deleteRecords(Address start, Address end) throws IOException;

	/**
	 * Get an iterator over records with the given address.
	 * @param addr the address for which to get records
	 * @return the iterator
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getRecordsByAddress(Address addr) throws IOException;

	/**
	 * Get an iterator over all records
	 * @return the iterator
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getAllRecords() throws IOException;
}
