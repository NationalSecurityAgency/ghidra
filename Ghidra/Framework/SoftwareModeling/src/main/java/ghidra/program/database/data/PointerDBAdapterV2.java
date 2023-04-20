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
package ghidra.program.database.data;

import java.io.IOException;

import db.*;
import ghidra.util.exception.VersionException;

/**
 * Version 2 implementation for accessing the PointerDB database table. 
 * 
 * NOTE: Use of tablePrefix introduced with this adapter version.
 */
class PointerDBAdapterV2 extends PointerDBAdapter {
	final static int VERSION = 2;

	private Table table;

	/**
	 * Gets a version 2 adapter for the PointerDB database table.
	 * @param handle handle to the database containing the table.
	 * @param tablePrefix prefix to be used with default table name
	 * @param create true if this constructor should create the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if IO error occurs
	 */
	PointerDBAdapterV2(DBHandle handle, String tablePrefix, boolean create)
			throws VersionException, IOException {
		String tableName = tablePrefix + POINTER_TABLE_NAME;
		if (create) {
			table = handle.createTable(tableName, SCHEMA, new int[] { PTR_CATEGORY_COL });
		}
		else {
			table = handle.getTable(tableName);
			if (table == null) {
				throw new VersionException("Missing Table: " + tableName);
			}
			int version = table.getSchema().getVersion();
			if (version != VERSION) {
				throw new VersionException(version < VERSION);
			}
		}
	}

	@Override
	DBRecord createRecord(long dataTypeID, long categoryID, int length) throws IOException {
		long key = DataTypeManagerDB.createKey(DataTypeManagerDB.POINTER, table.getKey());
		DBRecord record = SCHEMA.createRecord(key);
		record.setLongValue(PTR_DT_ID_COL, dataTypeID);
		record.setLongValue(PTR_CATEGORY_COL, categoryID);
		record.setByteValue(PTR_LENGTH_COL, (byte) length);
		table.putRecord(record);
		return record;
	}

	@Override
	DBRecord getRecord(long pointerID) throws IOException {
		return table.getRecord(pointerID);
	}

	@Override
	RecordIterator getRecords() throws IOException {
		return table.iterator();
	}

	@Override
	boolean removeRecord(long pointerID) throws IOException {
		return table.deleteRecord(pointerID);
	}

	@Override
	void updateRecord(DBRecord record) throws IOException {
		table.putRecord(record);
	}

	@Override
	Field[] getRecordIdsInCategory(long categoryID) throws IOException {
		return table.findRecords(new LongField(categoryID), PTR_CATEGORY_COL);
	}

	@Override
	void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(table.getName());
	}

	@Override
	public DBRecord translateRecord(DBRecord rec) {
		return rec;
	}
}
