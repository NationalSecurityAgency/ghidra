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
import ghidra.util.UniversalID;
import ghidra.util.exception.VersionException;

/**
 * Version 1 implementation for accessing the Typedef database table. 
 */
class TypedefDBAdapterV1 extends TypedefDBAdapter implements RecordTranslator {

	static final int VERSION = 1;

	static final int V1_TYPEDEF_DT_ID_COL = 0;
	static final int V1_TYPEDEF_NAME_COL = 1;
	static final int V1_TYPEDEF_CAT_COL = 2;
	static final int V1_TYPEDEF_SOURCE_ARCHIVE_ID_COL = 3;
	static final int V1_TYPEDEF_UNIVERSAL_DT_ID_COL = 4;
	static final int V1_TYPEDEF_SOURCE_SYNC_TIME_COL = 5;
	static final int V1_TYPEDEF_LAST_CHANGE_TIME_COL = 6;

//  DO NOT REMOVE WHAT'S BELOW - this documents the schema used in version 0.
//	static final Schema V1_SCHEMA = new Schema(VERSION, "Typedef ID",
//		new Field[] { LongField.INSTANCE, StringField.INSTANCE, LongField.INSTANCE,
//			LongField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE },
//		new String[] { "Data Type ID", "Name", "Category ID", "Source Archive ID",
//			"Universal Data Type ID", "Source Sync Time", "Last Change Time" });

	private Table table;

	/**
	 * Gets a version 1 adapter for the Typedef database table.
	 * @param handle handle to the database containing the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 */
	public TypedefDBAdapterV1(DBHandle handle) throws VersionException {

		table = handle.getTable(TYPEDEF_TABLE_NAME);
		if (table == null) {
			throw new VersionException("Missing Table: " + TYPEDEF_TABLE_NAME);
		}
		int version = table.getSchema().getVersion();
		if (version != VERSION) {
			throw new VersionException(version < VERSION);
		}
	}

	@Override
	void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(TYPEDEF_TABLE_NAME);
	}

	@Override
	public DBRecord createRecord(long dataTypeID, String name, short flags, long categoryID,
			long sourceArchiveID, long sourceDataTypeID, long lastChangeTime) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public DBRecord getRecord(long typedefID) throws IOException {
		return translateRecord(table.getRecord(typedefID));
	}

	@Override
	RecordIterator getRecords() throws IOException {
		return new TranslatedRecordIterator(table.iterator(), this);
	}

	@Override
	public void updateRecord(DBRecord record, boolean setLastChangeTime) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean removeRecord(long dataID) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Field[] getRecordIdsInCategory(long categoryID) throws IOException {
		return table.findRecords(new LongField(categoryID), V1_TYPEDEF_CAT_COL);
	}

	@Override
	Field[] getRecordIdsForSourceArchive(long archiveID) throws IOException {
		return table.findRecords(new LongField(archiveID), V1_TYPEDEF_SOURCE_ARCHIVE_ID_COL);
	}

	@Override
	DBRecord getRecordWithIDs(UniversalID sourceID, UniversalID datatypeID) throws IOException {
		Field[] keys =
			table.findRecords(new LongField(datatypeID.getValue()), V1_TYPEDEF_UNIVERSAL_DT_ID_COL);
		for (int i = 0; i < keys.length; i++) {
			DBRecord record = table.getRecord(keys[i]);
			if (record.getLongValue(V1_TYPEDEF_SOURCE_ARCHIVE_ID_COL) == sourceID.getValue()) {
				return translateRecord(record);
			}
		}
		return null;
	}

	@Override
	public DBRecord translateRecord(DBRecord oldRec) {
		if (oldRec == null) {
			return null;
		}
		DBRecord rec = TypedefDBAdapter.SCHEMA.createRecord(oldRec.getKey());
		rec.setLongValue(TYPEDEF_DT_ID_COL, oldRec.getLongValue(V1_TYPEDEF_DT_ID_COL));
		// default TYPEDEF_FLAGS_COL to 0 
		rec.setString(TYPEDEF_NAME_COL, oldRec.getString(V1_TYPEDEF_NAME_COL));
		rec.setLongValue(TYPEDEF_CAT_COL, oldRec.getLongValue(V1_TYPEDEF_CAT_COL));
		rec.setLongValue(TYPEDEF_SOURCE_ARCHIVE_ID_COL,
			oldRec.getLongValue(V1_TYPEDEF_SOURCE_ARCHIVE_ID_COL));
		rec.setLongValue(TYPEDEF_UNIVERSAL_DT_ID_COL,
			oldRec.getLongValue(V1_TYPEDEF_UNIVERSAL_DT_ID_COL));
		rec.setLongValue(TYPEDEF_SOURCE_SYNC_TIME_COL,
			oldRec.getLongValue(V1_TYPEDEF_SOURCE_SYNC_TIME_COL));
		rec.setLongValue(TYPEDEF_LAST_CHANGE_TIME_COL,
			oldRec.getLongValue(V1_TYPEDEF_LAST_CHANGE_TIME_COL));
		return rec;
	}
}
