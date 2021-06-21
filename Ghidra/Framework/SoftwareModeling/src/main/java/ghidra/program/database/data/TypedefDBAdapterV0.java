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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.UniversalID;
import ghidra.util.UniversalIdGenerator;
import ghidra.util.exception.VersionException;

/**
 * Version 0 implementation for accessing the Typedef database table. 
 */
class TypedefDBAdapterV0 extends TypedefDBAdapter implements RecordTranslator {
	static final int VERSION = 0;
	private static final int V0_TYPEDEF_DT_ID_COL = 0;
	private static final int V0_TYPEDEF_NAME_COL = 1;
	private static final int V0_TYPEDEF_CAT_COL = 2;
//  DO NOT REMOVE WHAT'S BELOW - this documents the schema used in version 0.
//	static final Schema V0_SCHEMA = new Schema(VERSION, "Typedef ID",
//								new Class[] {LongField.class, StringField.class,
//											 LongField.class},
//								new String[] {"Data Type ID", "Name", "Category ID"});
	private Table table;

	/**
	 * Gets a version 0 adapter for the Typedef database table.
	 * @param handle handle to the database containing the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 */
	public TypedefDBAdapterV0(DBHandle handle) throws VersionException {

		table = handle.getTable(TYPEDEF_TABLE_NAME);
		if (table == null) {
			throw new VersionException("Missing Table: " + TYPEDEF_TABLE_NAME);
		}
		int version = table.getSchema().getVersion();
		if (version != VERSION) {
			String msg = "Expected version " + VERSION + " for table " + TYPEDEF_TABLE_NAME +
				" but got " + table.getSchema().getVersion();
			if (version < VERSION) {
				throw new VersionException(msg, VersionException.OLDER_VERSION, true);
			}
			throw new VersionException(msg, VersionException.NEWER_VERSION, false);
		}
	}

	@Override
	void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(TYPEDEF_TABLE_NAME);
	}

	@Override
	public DBRecord createRecord(long dataTypeID, String name, long categoryID, long sourceArchiveID,
			long sourceDataTypeID, long lastChangeTime) throws IOException {
		throw new UnsupportedOperationException("Not allowed to update prior version #" + VERSION +
			" of " + TYPEDEF_TABLE_NAME + " table.");
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
		return table.deleteRecord(dataID);
	}

	@Override
	public Field[] getRecordIdsInCategory(long categoryID) throws IOException {
		return table.findRecords(new LongField(categoryID), V0_TYPEDEF_CAT_COL);
	}

	@Override
	Field[] getRecordIdsForSourceArchive(long archiveID) throws IOException {
		return Field.EMPTY_ARRAY;
	}

	@Override
	public DBRecord translateRecord(DBRecord oldRec) {
		if (oldRec == null) {
			return null;
		}
		DBRecord rec = TypedefDBAdapter.SCHEMA.createRecord(oldRec.getKey());
		rec.setLongValue(TYPEDEF_DT_ID_COL, oldRec.getLongValue(V0_TYPEDEF_DT_ID_COL));
		rec.setString(TYPEDEF_NAME_COL, oldRec.getString(V0_TYPEDEF_NAME_COL));
		rec.setLongValue(TYPEDEF_CAT_COL, oldRec.getLongValue(V0_TYPEDEF_CAT_COL));
		rec.setLongValue(TYPEDEF_SOURCE_ARCHIVE_ID_COL, DataTypeManager.LOCAL_ARCHIVE_KEY);
		rec.setLongValue(TYPEDEF_UNIVERSAL_DT_ID_COL, UniversalIdGenerator.nextID().getValue());
		rec.setLongValue(TYPEDEF_SOURCE_SYNC_TIME_COL, DataType.NO_SOURCE_SYNC_TIME);
		rec.setLongValue(TYPEDEF_LAST_CHANGE_TIME_COL, DataType.NO_LAST_CHANGE_TIME);
		return rec;
	}

	@Override
	DBRecord getRecordWithIDs(UniversalID sourceID, UniversalID datatypeID) throws IOException {
		return null;
	}

}
