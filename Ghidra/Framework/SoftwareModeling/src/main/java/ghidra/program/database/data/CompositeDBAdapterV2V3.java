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
import ghidra.util.ReadOnlyException;
import ghidra.util.UniversalID;
import ghidra.util.exception.VersionException;

/**
 * Version 2-3 implementation for accessing the Composite database table. 
 */
class CompositeDBAdapterV2V3 extends CompositeDBAdapter {

	// While the addition of flex-array and bitfields does not impact the 
	// actual schema the presence of such components can not be supported
	// by earlier versions of Ghidra.  A version change to the existing
	// schema permits us to prevent archives containing such components 
	// where not supported.

	// Version bumped to 3 when flex-arrays support added to structures
	// Version bumped to 4 when bitfields support added to composites

	static final int VERSION = 4;
	static final int MIN_READ_ONLY_VERSION = 2;

	static final int V2_COMPOSITE_NAME_COL = 0;
	static final int V2_COMPOSITE_COMMENT_COL = 1;
	static final int V2_COMPOSITE_IS_UNION_COL = 2;
	static final int V2_COMPOSITE_CAT_COL = 3;
	static final int V2_COMPOSITE_LENGTH_COL = 4;
	static final int V2_COMPOSITE_NUM_COMPONENTS_COL = 5;
	static final int V2_COMPOSITE_SOURCE_ARCHIVE_ID_COL = 6;
	static final int V2_COMPOSITE_UNIVERSAL_DT_ID_COL = 7;
	static final int V2_COMPOSITE_SOURCE_SYNC_TIME_COL = 8;
	static final int V2_COMPOSITE_LAST_CHANGE_TIME_COL = 9;
	static final int V2_COMPOSITE_INTERNAL_ALIGNMENT_COL = 10;
	static final int V2_COMPOSITE_EXTERNAL_ALIGNMENT_COL = 11;

	static final Schema V2_COMPOSITE_SCHEMA = new Schema(VERSION, "Data Type ID",
		new Field[] { StringField.INSTANCE, StringField.INSTANCE, BooleanField.INSTANCE,
			LongField.INSTANCE, IntField.INSTANCE, IntField.INSTANCE, LongField.INSTANCE,
			LongField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE, IntField.INSTANCE,
			IntField.INSTANCE },
		new String[] { "Name", "Comment", "Is Union", "Category ID", "Length",
			"Number Of Components", "Source Archive ID", "Source Data Type ID", "Source Sync Time",
			"Last Change Time", "Internal Alignment", "External Alignment" });

	private Table compositeTable;
	private boolean readOnly;

	/**
	 * Gets an adapter for the Composite database table.
	 * @param handle handle to the database containing the table.
	 * @param openMode the open mode 
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 */
	public CompositeDBAdapterV2V3(DBHandle handle, int openMode)
			throws VersionException, IOException {
		readOnly = (openMode == DBConstants.READ_ONLY);
		if (openMode == DBConstants.CREATE) {
			compositeTable = handle.createTable(COMPOSITE_TABLE_NAME, V2_COMPOSITE_SCHEMA,
				new int[] { V2_COMPOSITE_CAT_COL, V2_COMPOSITE_UNIVERSAL_DT_ID_COL });
		}
		else {
			compositeTable = handle.getTable(COMPOSITE_TABLE_NAME);
			if (compositeTable == null) {
				throw new VersionException("Missing Table: " + COMPOSITE_TABLE_NAME);
			}
			int version = compositeTable.getSchema().getVersion();
			if (version != VERSION) {
				if (version < VERSION && version >= MIN_READ_ONLY_VERSION) {
					if (openMode == DBConstants.READ_ONLY) {
						return; // allow read-only immutable use
					}
					throw new VersionException(VersionException.OLDER_VERSION, true);
				}
				String msg = "Expected version 2-" + VERSION + " for table " +
					COMPOSITE_TABLE_NAME + " but got " + version;
				throw new VersionException(msg, VersionException.NEWER_VERSION, false);
			}
		}
	}

	/**
	 * Gets a read-only adapter for the Composite database table.
	 * @param handle handle to the database containing the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 */
	public CompositeDBAdapterV2V3(DBHandle handle) throws VersionException {
		readOnly = true;
		compositeTable = handle.getTable(COMPOSITE_TABLE_NAME);
		if (compositeTable == null) {
			throw new VersionException("Missing Table: " + COMPOSITE_TABLE_NAME);
		}
		int version = compositeTable.getSchema().getVersion();
		if (version < MIN_READ_ONLY_VERSION) {
			throw new VersionException(VersionException.OLDER_VERSION, true);
		}
		else if (version > VERSION) {
			String msg = "Expected version " + VERSION + " for table " + COMPOSITE_TABLE_NAME +
				" but got " + version;
			throw new VersionException(msg, VersionException.NEWER_VERSION, false);
		}
	}

	@Override
	public DBRecord createRecord(String name, String comments, boolean isUnion, long categoryID,
			int length, long sourceArchiveID, long sourceDataTypeID, long lastChangeTime,
			int internalAlignment, int externalAlignment) throws IOException {
		if (readOnly) {
			throw new ReadOnlyException();
		}
		if (internalAlignment == UNALIGNED) {
			length = 0; // aligned structures always start empty
		}
		long tableKey = compositeTable.getKey();
//		if (tableKey <= DataManager.VOID_DATATYPE_ID) {
//			tableKey = DataManager.VOID_DATATYPE_ID +1;
//		}
		long key = DataTypeManagerDB.createKey(DataTypeManagerDB.COMPOSITE, tableKey);
		DBRecord record = CompositeDBAdapter.COMPOSITE_SCHEMA.createRecord(key);

		record.setString(V2_COMPOSITE_NAME_COL, name);
		record.setString(V2_COMPOSITE_COMMENT_COL, comments);
		record.setBooleanValue(V2_COMPOSITE_IS_UNION_COL, isUnion);
		record.setLongValue(V2_COMPOSITE_CAT_COL, categoryID);
		record.setIntValue(V2_COMPOSITE_LENGTH_COL, length);
		record.setIntValue(V2_COMPOSITE_NUM_COMPONENTS_COL, length);
		record.setLongValue(V2_COMPOSITE_SOURCE_ARCHIVE_ID_COL, sourceArchiveID);
		record.setLongValue(V2_COMPOSITE_UNIVERSAL_DT_ID_COL, sourceDataTypeID);
		record.setLongValue(V2_COMPOSITE_SOURCE_SYNC_TIME_COL, lastChangeTime);
		record.setLongValue(V2_COMPOSITE_LAST_CHANGE_TIME_COL, lastChangeTime);
		record.setIntValue(V2_COMPOSITE_INTERNAL_ALIGNMENT_COL, internalAlignment);
		record.setIntValue(V2_COMPOSITE_EXTERNAL_ALIGNMENT_COL, externalAlignment);
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
		if (readOnly) {
			throw new ReadOnlyException();
		}
		if (setLastChangeTime) {
			record.setLongValue(CompositeDBAdapter.COMPOSITE_LAST_CHANGE_TIME_COL,
				(new Date()).getTime());
		}
		compositeTable.putRecord(record);
	}

	@Override
	public boolean removeRecord(long compositeID) throws IOException {
		if (readOnly) {
			throw new ReadOnlyException();
		}
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
			V2_COMPOSITE_SOURCE_ARCHIVE_ID_COL);
	}

	@Override
	DBRecord getRecordWithIDs(UniversalID sourceID, UniversalID datatypeID) throws IOException {
		Field[] keys = compositeTable.findRecords(new LongField(datatypeID.getValue()),
			V2_COMPOSITE_UNIVERSAL_DT_ID_COL);

		for (int i = 0; i < keys.length; i++) {
			DBRecord record = compositeTable.getRecord(keys[i]);
			if (record.getLongValue(V2_COMPOSITE_SOURCE_ARCHIVE_ID_COL) == sourceID.getValue()) {
				return record;
			}
		}
		return null;
	}
}
