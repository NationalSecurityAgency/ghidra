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
package ghidra.program.database.data;

import ghidra.util.exception.VersionException;

import java.io.IOException;

import db.*;

class PointerDBAdapterV2 extends PointerDBAdapter {
	final static int VERSION = 2;

	private Table table;

	PointerDBAdapterV2(DBHandle handle, boolean create) throws VersionException, IOException {

		if (create) {
			table = handle.createTable(POINTER_TABLE_NAME, SCHEMA, new int[] { PTR_CATEGORY_COL });
		}
		else {
			table = handle.getTable(POINTER_TABLE_NAME);
			if (table == null) {
				throw new VersionException("Missing Table: " + POINTER_TABLE_NAME);
			}
			else if (table.getSchema().getVersion() != VERSION) {
				int version = table.getSchema().getVersion();
				if (version < VERSION) {
					throw new VersionException(true);
				}
				throw new VersionException(VersionException.NEWER_VERSION, false);
			}
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.data.PointerDBAdapter#createRecord(long, int)
	 */
	@Override
	Record createRecord(long dataTypeID, long categoryID, int length) throws IOException {
		long tableKey = table.getKey();
		long key = DataTypeManagerDB.createKey(DataTypeManagerDB.POINTER, tableKey);

		Record record = SCHEMA.createRecord(key);
		record.setLongValue(PTR_DT_ID_COL, dataTypeID);
		record.setLongValue(PTR_CATEGORY_COL, categoryID);
		record.setByteValue(PTR_LENGTH_COL, (byte) length);
		table.putRecord(record);
		return record;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.data.PointerDBAdapter#getRecord(long)
	 */
	@Override
	Record getRecord(long pointerID) throws IOException {
		return table.getRecord(pointerID);
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.data.PointerDBAdapter#getRecords()
	 */
	@Override
	RecordIterator getRecords() throws IOException {
		return table.iterator();
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.data.PointerDBAdapter#removeRecord(long)
	 */
	@Override
	boolean removeRecord(long pointerID) throws IOException {
		return table.deleteRecord(pointerID);
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.data.PointerDBAdapter#updateRecord(ghidra.framework.store.db.Record)
	 */
	@Override
	void updateRecord(Record record) throws IOException {
		table.putRecord(record);
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.data.PointerDBAdapter#getRecordIdsInCategory(long)
	 */
	@Override
	long[] getRecordIdsInCategory(long categoryID) throws IOException {
		return table.findRecords(new LongField(categoryID), PTR_CATEGORY_COL);
	}

	/**
	 * @see ghidra.program.database.data.PointerDBAdapter#deleteTable()
	 */
	@Override
	void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(POINTER_TABLE_NAME);

	}

}
