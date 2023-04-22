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
import java.util.Date;

import db.*;
import ghidra.util.UniversalID;
import ghidra.util.exception.VersionException;

/**
 * Version 2 implementation for accessing the Typedef database table. 
 * 
 * NOTE: Use of tablePrefix introduced with this adapter version.
 */
class TypedefDBAdapterV2 extends TypedefDBAdapter {

	static final int VERSION = 2;

	static final int V2_TYPEDEF_DT_ID_COL = 0;
	static final int V2_TYPEDEF_FLAGS_COL = 1;
	static final int V2_TYPEDEF_NAME_COL = 2;
	static final int V2_TYPEDEF_CAT_COL = 3;
	static final int V2_TYPEDEF_SOURCE_ARCHIVE_ID_COL = 4;
	static final int V2_TYPEDEF_UNIVERSAL_DT_ID_COL = 5;
	static final int V2_TYPEDEF_SOURCE_SYNC_TIME_COL = 6;
	static final int V2_TYPEDEF_LAST_CHANGE_TIME_COL = 7;

	static final Schema V2_SCHEMA = new Schema(VERSION, "Typedef ID",
		new Field[] { LongField.INSTANCE, ShortField.INSTANCE, StringField.INSTANCE,
			LongField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE,
			LongField.INSTANCE },
		new String[] { "Data Type ID", "Flags", "Name", "Category ID", "Source Archive ID",
			"Universal Data Type ID", "Source Sync Time", "Last Change Time" });

	private Table table;

	/**
	 * Gets a version 1 adapter for the Typedef database table.
	 * @param handle handle to the database containing the table.
	 * @param tablePrefix prefix to be used with default table name
	 * @param create true if this constructor should create the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if IO error occurs
	 */
	public TypedefDBAdapterV2(DBHandle handle, String tablePrefix, boolean create)
			throws VersionException, IOException {
		String tableName = tablePrefix + TYPEDEF_TABLE_NAME;
		if (create) {
			table = handle.createTable(tableName, V2_SCHEMA,
				new int[] { V2_TYPEDEF_CAT_COL, V2_TYPEDEF_UNIVERSAL_DT_ID_COL });
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
	void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(table.getName());
	}

	@Override
	public DBRecord createRecord(long dataTypeID, String name, short flags, long categoryID,
			long sourceArchiveID, long sourceDataTypeID, long lastChangeTime) throws IOException {
		long key = DataTypeManagerDB.createKey(DataTypeManagerDB.TYPEDEF, table.getKey());
		DBRecord record = V2_SCHEMA.createRecord(key);
		record.setLongValue(V2_TYPEDEF_DT_ID_COL, dataTypeID);
		record.setShortValue(V2_TYPEDEF_FLAGS_COL, flags);
		record.setString(V2_TYPEDEF_NAME_COL, name);
		record.setLongValue(V2_TYPEDEF_CAT_COL, categoryID);
		record.setLongValue(V2_TYPEDEF_SOURCE_ARCHIVE_ID_COL, sourceArchiveID);
		record.setLongValue(V2_TYPEDEF_UNIVERSAL_DT_ID_COL, sourceDataTypeID);
		record.setLongValue(V2_TYPEDEF_SOURCE_SYNC_TIME_COL, lastChangeTime);
		record.setLongValue(V2_TYPEDEF_LAST_CHANGE_TIME_COL, lastChangeTime);
		table.putRecord(record);
		return record;
	}

	@Override
	public DBRecord getRecord(long typedefID) throws IOException {
		return table.getRecord(typedefID);
	}

	@Override
	public RecordIterator getRecords() throws IOException {
		return table.iterator();
	}

	@Override
	public void updateRecord(DBRecord record, boolean setLastChangeTime) throws IOException {
		if (setLastChangeTime) {
			record.setLongValue(TypedefDBAdapter.TYPEDEF_LAST_CHANGE_TIME_COL,
				(new Date()).getTime());
		}
		table.putRecord(record);
	}

	@Override
	public boolean removeRecord(long dataID) throws IOException {
		return table.deleteRecord(dataID);
	}

	@Override
	public Field[] getRecordIdsInCategory(long categoryID) throws IOException {
		return table.findRecords(new LongField(categoryID), V2_TYPEDEF_CAT_COL);
	}

	@Override
	Field[] getRecordIdsForSourceArchive(long archiveID) throws IOException {
		return table.findRecords(new LongField(archiveID), V2_TYPEDEF_SOURCE_ARCHIVE_ID_COL);
	}

	@Override
	DBRecord getRecordWithIDs(UniversalID sourceID, UniversalID datatypeID) throws IOException {
		Field[] keys =
			table.findRecords(new LongField(datatypeID.getValue()), V2_TYPEDEF_UNIVERSAL_DT_ID_COL);

		for (int i = 0; i < keys.length; i++) {
			DBRecord record = table.getRecord(keys[i]);
			if (record.getLongValue(V2_TYPEDEF_SOURCE_ARCHIVE_ID_COL) == sourceID.getValue()) {
				return record;
			}
		}
		return null;
	}

}
