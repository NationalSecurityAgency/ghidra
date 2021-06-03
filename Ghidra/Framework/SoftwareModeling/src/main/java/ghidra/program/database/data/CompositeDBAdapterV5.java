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
import ghidra.program.model.data.CompositeInternal;
import ghidra.util.UniversalID;
import ghidra.util.exception.VersionException;

/**
 * Version 5 implementation for accessing the Composite database table. 
 * This version introduces the retained computed alignment to reduce
 * need for recalculation and to allow for improved change detection.
 */
class CompositeDBAdapterV5 extends CompositeDBAdapter {

	static final int VERSION = 5;

	static final int V5_COMPOSITE_NAME_COL = 0;
	static final int V5_COMPOSITE_COMMENT_COL = 1;
	static final int V5_COMPOSITE_IS_UNION_COL = 2;
	static final int V5_COMPOSITE_CAT_COL = 3;
	static final int V5_COMPOSITE_LENGTH_COL = 4;
	static final int V5_COMPOSITE_ALIGNMENT_COL = 5;
	static final int V5_COMPOSITE_NUM_COMPONENTS_COL = 6;
	static final int V5_COMPOSITE_SOURCE_ARCHIVE_ID_COL = 7;
	static final int V5_COMPOSITE_UNIVERSAL_DT_ID_COL = 8;
	static final int V5_COMPOSITE_SOURCE_SYNC_TIME_COL = 9;
	static final int V5_COMPOSITE_LAST_CHANGE_TIME_COL = 10;
	static final int V5_COMPOSITE_PACK_COL = 11;
	static final int V5_COMPOSITE_MIN_ALIGN_COL = 12;

	static final Schema V5_COMPOSITE_SCHEMA = new Schema(VERSION, "Data Type ID",
		new Field[] { StringField.INSTANCE, StringField.INSTANCE, BooleanField.INSTANCE,
			LongField.INSTANCE, IntField.INSTANCE, IntField.INSTANCE, IntField.INSTANCE,
			LongField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE,
			IntField.INSTANCE, IntField.INSTANCE },
		new String[] { "Name", "Comment", "Is Union", "Category ID", "Length", "Alignment",
			"Number Of Components", "Source Archive ID", "Source Data Type ID", "Source Sync Time",
			"Last Change Time", "Pack", "MinAlign" });

	private Table compositeTable;

	/**
	 * Gets an adapter for the Composite database table.
	 * @param handle handle to the database containing the table.
	 * @param create true if this constructor should create the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if IO error occurs
	 */
	public CompositeDBAdapterV5(DBHandle handle, boolean create)
			throws VersionException, IOException {
		if (create) {
			compositeTable = handle.createTable(COMPOSITE_TABLE_NAME, V5_COMPOSITE_SCHEMA,
				new int[] { V5_COMPOSITE_CAT_COL, V5_COMPOSITE_UNIVERSAL_DT_ID_COL });
		}
		else {
			compositeTable = handle.getTable(COMPOSITE_TABLE_NAME);
			if (compositeTable == null) {
				throw new VersionException("Missing Table: " + COMPOSITE_TABLE_NAME);
			}
			int version = compositeTable.getSchema().getVersion();
			if (version != VERSION) {
				String msg = "Expected version " + VERSION + " for table " + COMPOSITE_TABLE_NAME +
					" but got " + version;
				if (version < VERSION) {
					throw new VersionException(msg, VersionException.OLDER_VERSION, true);
				}
				throw new VersionException(msg, VersionException.NEWER_VERSION, false);
			}
		}
	}

	@Override
	public DBRecord createRecord(String name, String comments, boolean isUnion, long categoryID,
			int length, int computedAlignment, long sourceArchiveID, long sourceDataTypeID,
			long lastChangeTime, int packValue, int minAlignment) throws IOException {
		if (packValue < CompositeInternal.DEFAULT_ALIGNMENT) {
			packValue = CompositeInternal.NO_PACKING;
		}
		else {
			length = 0; // aligned structures always start empty
		}
		long key =
			DataTypeManagerDB.createKey(DataTypeManagerDB.COMPOSITE, compositeTable.getKey());
		DBRecord record = CompositeDBAdapter.COMPOSITE_SCHEMA.createRecord(key);

		record.setString(V5_COMPOSITE_NAME_COL, name);
		record.setString(V5_COMPOSITE_COMMENT_COL, comments);
		record.setBooleanValue(V5_COMPOSITE_IS_UNION_COL, isUnion);
		record.setLongValue(V5_COMPOSITE_CAT_COL, categoryID);
		record.setIntValue(V5_COMPOSITE_LENGTH_COL, length);
		record.setIntValue(V5_COMPOSITE_ALIGNMENT_COL, computedAlignment);
		record.setIntValue(V5_COMPOSITE_NUM_COMPONENTS_COL, length);
		record.setLongValue(V5_COMPOSITE_SOURCE_ARCHIVE_ID_COL, sourceArchiveID);
		record.setLongValue(V5_COMPOSITE_UNIVERSAL_DT_ID_COL, sourceDataTypeID);
		record.setLongValue(V5_COMPOSITE_SOURCE_SYNC_TIME_COL, lastChangeTime);
		record.setLongValue(V5_COMPOSITE_LAST_CHANGE_TIME_COL, lastChangeTime);
		record.setIntValue(V5_COMPOSITE_PACK_COL, packValue);
		record.setIntValue(V5_COMPOSITE_MIN_ALIGN_COL, minAlignment);
		compositeTable.putRecord(record);
		return record;
	}

	@Override
	public DBRecord getRecord(long dataTypeID) throws IOException {
		return compositeTable.getRecord(dataTypeID);
	}

	@Override
	public RecordIterator getRecords() throws IOException {
		return compositeTable.iterator();
	}

	@Override
	public void updateRecord(DBRecord record, boolean setLastChangeTime) throws IOException {
		if (setLastChangeTime) {
			record.setLongValue(CompositeDBAdapter.COMPOSITE_LAST_CHANGE_TIME_COL,
				(new Date()).getTime());
		}
		compositeTable.putRecord(record);
	}

	@Override
	public boolean removeRecord(long compositeID) throws IOException {
		return compositeTable.deleteRecord(compositeID);
	}

	@Override
	void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(COMPOSITE_TABLE_NAME);
	}

	@Override
	public Field[] getRecordIdsInCategory(long categoryID) throws IOException {
		return compositeTable.findRecords(new LongField(categoryID),
			CompositeDBAdapter.COMPOSITE_CAT_COL);
	}

	@Override
	Field[] getRecordIdsForSourceArchive(long archiveID) throws IOException {
		return compositeTable.findRecords(new LongField(archiveID),
			V5_COMPOSITE_SOURCE_ARCHIVE_ID_COL);
	}

	@Override
	DBRecord getRecordWithIDs(UniversalID sourceID, UniversalID datatypeID) throws IOException {
		Field[] keys = compositeTable.findRecords(new LongField(datatypeID.getValue()),
			V5_COMPOSITE_UNIVERSAL_DT_ID_COL);

		for (Field key : keys) {
			DBRecord record = compositeTable.getRecord(key);
			if (record.getLongValue(V5_COMPOSITE_SOURCE_ARCHIVE_ID_COL) == sourceID.getValue()) {
				return record;
			}
		}
		return null;
	}
}
