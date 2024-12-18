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
 * Version 1 implementation for accessing the Enumeration database table. 
 * 
 * NOTE: Use of tablePrefix introduced with this adapter version.
 */
class EnumDBAdapterV1 extends EnumDBAdapter {
	static final int VERSION = 1;

	// Enum Columns
	static final int V1_ENUM_NAME_COL = 0;
	static final int V1_ENUM_COMMENT_COL = 1;
	static final int V1_ENUM_CAT_COL = 2;
	static final int V1_ENUM_SIZE_COL = 3;
	static final int V1_ENUM_SOURCE_ARCHIVE_ID_COL = 4;
	static final int V1_ENUM_UNIVERSAL_DT_ID_COL = 5;
	static final int V1_ENUM_SOURCE_SYNC_TIME_COL = 6;
	static final int V1_ENUM_LAST_CHANGE_TIME_COL = 7;

	static final Schema V1_ENUM_SCHEMA = new Schema(VERSION, "Enum ID",
		new Field[] { StringField.INSTANCE, StringField.INSTANCE, LongField.INSTANCE,
			ByteField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE,
			LongField.INSTANCE },
		new String[] { "Name", "Comment", "Category ID", "Size", "Source Archive ID",
			"Source Data Type ID", "Source Sync Time", "Last Change Time" });

	private Table enumTable;

	/**
	 * Gets a version 1 adapter for the Enumeration database table.
	 * @param handle handle to the database containing the table.
	 * @param tablePrefix prefix to be used with default table name
	 * @param create true if this constructor should create the table.
	 * @throws VersionException if the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException an IO error occured during table creation
	 */
	public EnumDBAdapterV1(DBHandle handle, String tablePrefix, boolean create)
			throws VersionException, IOException {
		String tableName = tablePrefix + ENUM_TABLE_NAME;
		if (create) {
			enumTable = handle.createTable(tableName, V1_ENUM_SCHEMA,
				new int[] { V1_ENUM_CAT_COL, V1_ENUM_UNIVERSAL_DT_ID_COL });
		}
		else {
			enumTable = handle.getTable(tableName);
			if (enumTable == null) {
				throw new VersionException(true);
			}
			int version = enumTable.getSchema().getVersion();
			if (version != VERSION) {
				throw new VersionException(version < VERSION);
			}
		}
	}

	@Override
	public DBRecord createRecord(String name, String comments, long categoryID, byte size,
			long sourceArchiveID, long sourceDataTypeID, long lastChangeTime) throws IOException {
		long tableKey = enumTable.getKey();
		long key = DataTypeManagerDB.createKey(DataTypeManagerDB.ENUM, tableKey);
		DBRecord record = V1_ENUM_SCHEMA.createRecord(key);
		record.setString(V1_ENUM_NAME_COL, name);
		record.setString(V1_ENUM_COMMENT_COL, comments);
		record.setLongValue(V1_ENUM_CAT_COL, categoryID);
		record.setByteValue(V1_ENUM_SIZE_COL, size);
		record.setLongValue(V1_ENUM_SOURCE_ARCHIVE_ID_COL, sourceArchiveID);
		record.setLongValue(V1_ENUM_UNIVERSAL_DT_ID_COL, sourceDataTypeID);
		record.setLongValue(V1_ENUM_SOURCE_SYNC_TIME_COL, lastChangeTime);
		record.setLongValue(V1_ENUM_LAST_CHANGE_TIME_COL, lastChangeTime);
		enumTable.putRecord(record);
		return record;
	}

	@Override
	public DBRecord getRecord(long enumID) throws IOException {
		return enumTable.getRecord(enumID);
	}

	@Override
	public RecordIterator getRecords() throws IOException {
		return enumTable.iterator();
	}

	@Override
	public void updateRecord(DBRecord record, boolean setLastChangeTime) throws IOException {
		if (setLastChangeTime) {
			record.setLongValue(EnumDBAdapter.ENUM_LAST_CHANGE_TIME_COL, (new Date()).getTime());
		}
		enumTable.putRecord(record);
	}

	@Override
	public boolean removeRecord(long enumID) throws IOException {
		// TODO Fix up DataType Manager to remove associated value records.
		return enumTable.deleteRecord(enumID);
	}

	@Override
	protected void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(enumTable.getName());
	}

	@Override
	public Field[] getRecordIdsInCategory(long categoryID) throws IOException {
		return enumTable.findRecords(new LongField(categoryID), V1_ENUM_CAT_COL);
	}

	@Override
	Field[] getRecordIdsForSourceArchive(long archiveID) throws IOException {
		return enumTable.findRecords(new LongField(archiveID), V1_ENUM_SOURCE_ARCHIVE_ID_COL);
	}

	@Override
	DBRecord getRecordWithIDs(UniversalID sourceID, UniversalID datatypeID) throws IOException {
		Field[] keys = enumTable.findRecords(new LongField(datatypeID.getValue()),
			V1_ENUM_UNIVERSAL_DT_ID_COL);

		for (Field key : keys) {
			DBRecord record = enumTable.getRecord(key);
			if (record.getLongValue(V1_ENUM_SOURCE_ARCHIVE_ID_COL) == sourceID.getValue()) {
				return record;
			}
		}
		return null;
	}

	@Override
	public int getRecordCount() {
		return enumTable.getRecordCount();
	}

}
