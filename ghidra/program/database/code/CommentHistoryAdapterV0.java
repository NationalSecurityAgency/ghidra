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
import ghidra.program.database.map.*;
import ghidra.program.database.util.DatabaseVersionException;
import ghidra.program.model.address.Address;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.VersionException;

/**
 * Adapter for Version 0 of the Comment History table.
 */
class CommentHistoryAdapterV0 extends CommentHistoryAdapter {

	private Table table;
	private String userName;
	private AddressMap addrMap;

	/**
	 * Construct a new Version 0 comment history adapter.
	 * @param handle database handle
	 * @throws DatabaseVersionException if the table was not found
	 * @throws IOException if an error occurred while accessing the database
	 */
	CommentHistoryAdapterV0(DBHandle handle, AddressMap addrMap, boolean create)
			throws VersionException, IOException {
		this.addrMap = addrMap;
		if (create) {
			table =
				handle.createTable(COMMENT_HISTORY_TABLE_NAME, COMMENT_HISTORY_SCHEMA,
					new int[] { HISTORY_ADDRESS_COL });
		}
		else {
			table = handle.getTable(COMMENT_HISTORY_TABLE_NAME);
			if (table == null) {
				throw new VersionException(true);
			}
			if (table.getSchema().getVersion() != 0) {
				throw new VersionException(VersionException.NEWER_VERSION, false);
			}
		}
		userName = SystemUtilities.getUserName();
	}

	/**
	 * @see ghidra.program.database.code.CommentHistoryAdapter#createRecord(long, byte, int, int, java.lang.String)
	 */
	@Override
	void createRecord(long addr, byte commentType, int pos1, int pos2, String data)
			throws IOException {

		Record rec = table.getSchema().createRecord(table.getKey());
		rec.setLongValue(HISTORY_ADDRESS_COL, addr);
		rec.setByteValue(HISTORY_TYPE_COL, commentType);
		rec.setIntValue(HISTORY_POS1_COL, pos1);
		rec.setIntValue(HISTORY_POS2_COL, pos2);
		rec.setString(HISTORY_STRING_COL, data);
		rec.setString(HISTORY_USER_COL, userName);
		rec.setLongValue(HISTORY_DATE_COL, System.currentTimeMillis() ); //new Date().getTime());

		table.putRecord(rec);
	}

	/**
	 * @see ghidra.program.database.code.CommentHistoryAdapter#getRecordsByAddress(long)
	 */
	@Override
	RecordIterator getRecordsByAddress(Address address) throws IOException {
		LongField field = new LongField(addrMap.getKey(address, false));
		return table.indexIterator(HISTORY_ADDRESS_COL, field, field, true);
	}

	/**
	 * @see ghidra.program.database.code.CommentHistoryAdapter#getAllRecords()
	 */
	@Override
	RecordIterator getAllRecords() throws IOException {
		return new AddressKeyRecordIterator(table, addrMap);
	}

	/**
	 * @see ghidra.program.database.code.CommentHistoryAdapter#updateRecord(db.Record)
	 */
	@Override
	void updateRecord(Record rec) throws IOException {
		table.putRecord(rec);
	}

	/**
	 * @see ghidra.program.database.code.CommentHistoryAdapter#deleteRecords(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	boolean deleteRecords(Address start, Address end) throws IOException {
		return AddressRecordDeleter.deleteRecords(table, addrMap, start, end);
	}

	/**
	 * @see ghidra.program.database.code.CommentHistoryAdapter#getRecordCount()
	 */
	@Override
	int getRecordCount() {
		return table.getRecordCount();
	}
}
