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

import javax.help.UnsupportedOperationException;

import db.*;
import ghidra.framework.data.OpenMode;
import ghidra.program.model.data.CompositeInternal;
import ghidra.util.UniversalID;
import ghidra.util.exception.VersionException;

/**
 * Version 5 and 6 implementation for accessing the Composite database table. 
 * Version 5 introduced the retained computed alignment to reduce the
 * need for recalculation and to allow for improved change detection.
 * Version 6 did not change the schema but corresponds to the elimination
 * of Structure flex-arrays which are supported in read-only mode under
 * the older version 5 adapter version.
 * 
 * NOTE: Use of tablePrefix introduced with adapter V6.
 */
class CompositeDBAdapterV5V6 extends CompositeDBAdapter {

	static final int V5_VERSION = 5;
	static final int VERSION = 6;

	static final int V5V6_COMPOSITE_NAME_COL = 0;
	static final int V5V6_COMPOSITE_COMMENT_COL = 1;
	static final int V5V6_COMPOSITE_IS_UNION_COL = 2;
	static final int V5V6_COMPOSITE_CAT_COL = 3;
	static final int V5V6_COMPOSITE_LENGTH_COL = 4;
	static final int V5V6_COMPOSITE_ALIGNMENT_COL = 5;
	static final int V5V6_COMPOSITE_NUM_COMPONENTS_COL = 6;
	static final int V5V6_COMPOSITE_SOURCE_ARCHIVE_ID_COL = 7;
	static final int V5V6_COMPOSITE_UNIVERSAL_DT_ID_COL = 8;
	static final int V5V6_COMPOSITE_SOURCE_SYNC_TIME_COL = 9;
	static final int V5V6_COMPOSITE_LAST_CHANGE_TIME_COL = 10;
	static final int V5V6_COMPOSITE_PACK_COL = 11;
	static final int V5V6_COMPOSITE_MIN_ALIGN_COL = 12;

	static final Schema V5V6_COMPOSITE_SCHEMA = new Schema(VERSION, "Data Type ID",
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
	 * @param openMode the mode this adapter is to be opened for (CREATE, UPDATE, READ_ONLY, UPGRADE).
	 * @param tablePrefix prefix to be used with default table name
	 * @throws VersionException if the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if IO error occurs
	 */
	CompositeDBAdapterV5V6(DBHandle handle, OpenMode openMode, String tablePrefix)
			throws VersionException, IOException {
		String tableName = tablePrefix + COMPOSITE_TABLE_NAME;
		if (openMode == OpenMode.CREATE) {
			compositeTable = handle.createTable(tableName, V5V6_COMPOSITE_SCHEMA,
				new int[] { V5V6_COMPOSITE_CAT_COL, V5V6_COMPOSITE_UNIVERSAL_DT_ID_COL });
		}
		else {
			compositeTable = handle.getTable(tableName);
			if (compositeTable == null) {
				throw new VersionException("Missing Table: " + tableName);
			}
			int version = compositeTable.getSchema().getVersion();
			if (version != VERSION) {
				if (version == V5_VERSION && openMode == OpenMode.IMMUTABLE) {
					return; // StructureDB handles read-only flex-array migration
				}
				throw new VersionException(version < VERSION);
			}
		}
	}

	@Override
	int getVersion() {
		return compositeTable.getSchema().getVersion();
	}

	@Override
	public int getRecordCount() {
		return compositeTable.getRecordCount();
	}

	@Override
	DBRecord createRecord(String name, String comments, boolean isUnion, long categoryID,
			int length, int computedAlignment, long sourceArchiveID, long sourceDataTypeID,
			long lastChangeTime, int packValue, int minAlignment) throws IOException {
		if (compositeTable.getSchema().getVersion() == V5_VERSION) {
			throw new UnsupportedOperationException();
		}
		if (packValue < CompositeInternal.DEFAULT_PACKING) {
			packValue = CompositeInternal.NO_PACKING;
		}
		else {
			length = 0; // aligned structures always start empty
		}
		long key =
			DataTypeManagerDB.createKey(DataTypeManagerDB.COMPOSITE, compositeTable.getKey());
		DBRecord record = CompositeDBAdapter.COMPOSITE_SCHEMA.createRecord(key);

		record.setString(V5V6_COMPOSITE_NAME_COL, name);
		record.setString(V5V6_COMPOSITE_COMMENT_COL, comments);
		record.setBooleanValue(V5V6_COMPOSITE_IS_UNION_COL, isUnion);
		record.setLongValue(V5V6_COMPOSITE_CAT_COL, categoryID);
		record.setIntValue(V5V6_COMPOSITE_LENGTH_COL, length);
		record.setIntValue(V5V6_COMPOSITE_ALIGNMENT_COL, computedAlignment);
		record.setIntValue(V5V6_COMPOSITE_NUM_COMPONENTS_COL, length);
		record.setLongValue(V5V6_COMPOSITE_SOURCE_ARCHIVE_ID_COL, sourceArchiveID);
		record.setLongValue(V5V6_COMPOSITE_UNIVERSAL_DT_ID_COL, sourceDataTypeID);
		record.setLongValue(V5V6_COMPOSITE_SOURCE_SYNC_TIME_COL, lastChangeTime);
		record.setLongValue(V5V6_COMPOSITE_LAST_CHANGE_TIME_COL, lastChangeTime);
		record.setIntValue(V5V6_COMPOSITE_PACK_COL, packValue);
		record.setIntValue(V5V6_COMPOSITE_MIN_ALIGN_COL, minAlignment);
		compositeTable.putRecord(record);
		return record;
	}

	@Override
	DBRecord getRecord(long dataTypeID) throws IOException {
		return compositeTable.getRecord(dataTypeID);
	}

	@Override
	public RecordIterator getRecords() throws IOException {
		return compositeTable.iterator();
	}

	@Override
	void updateRecord(DBRecord record, boolean setLastChangeTime) throws IOException {
		if (compositeTable.getSchema().getVersion() == V5_VERSION) {
			throw new UnsupportedOperationException();
		}
		if (setLastChangeTime) {
			record.setLongValue(CompositeDBAdapter.COMPOSITE_LAST_CHANGE_TIME_COL,
				(new Date()).getTime());
		}
		compositeTable.putRecord(record);
	}

	@Override
	boolean removeRecord(long compositeID) throws IOException {
		if (compositeTable.getSchema().getVersion() == V5_VERSION) {
			throw new UnsupportedOperationException();
		}
		return compositeTable.deleteRecord(compositeID);
	}

	@Override
	void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(compositeTable.getName());
	}

	@Override
	Field[] getRecordIdsInCategory(long categoryID) throws IOException {
		return compositeTable.findRecords(new LongField(categoryID),
			CompositeDBAdapter.COMPOSITE_CAT_COL);
	}

	@Override
	Field[] getRecordIdsForSourceArchive(long archiveID) throws IOException {
		return compositeTable.findRecords(new LongField(archiveID),
			V5V6_COMPOSITE_SOURCE_ARCHIVE_ID_COL);
	}

	@Override
	DBRecord getRecordWithIDs(UniversalID sourceID, UniversalID datatypeID) throws IOException {
		Field[] keys = compositeTable.findRecords(new LongField(datatypeID.getValue()),
			V5V6_COMPOSITE_UNIVERSAL_DT_ID_COL);

		for (Field key : keys) {
			DBRecord record = compositeTable.getRecord(key);
			if (record.getLongValue(V5V6_COMPOSITE_SOURCE_ARCHIVE_ID_COL) == sourceID.getValue()) {
				return record;
			}
		}
		return null;
	}
}
