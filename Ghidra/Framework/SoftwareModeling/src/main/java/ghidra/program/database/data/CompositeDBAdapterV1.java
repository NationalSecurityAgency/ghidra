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
import ghidra.program.model.data.CompositeInternal;
import ghidra.util.UniversalID;
import ghidra.util.exception.VersionException;

/**
 * Version 1 implementation for accessing the Composite database table. 
 */
class CompositeDBAdapterV1 extends CompositeDBAdapter implements RecordTranslator {
	static final int VERSION = 1;
	static final int V1_COMPOSITE_NAME_COL = 0;
	static final int V1_COMPOSITE_COMMENT_COL = 1;
	static final int V1_COMPOSITE_IS_UNION_COL = 2;
	static final int V1_COMPOSITE_CAT_COL = 3;
	static final int V1_COMPOSITE_LENGTH_COL = 4;
	static final int V1_COMPOSITE_NUM_COMPONENTS_COL = 5;
	static final int V1_COMPOSITE_SOURCE_ARCHIVE_ID_COL = 6;
	static final int V1_COMPOSITE_UNIVERSAL_DT_ID_COL = 7;
	static final int V1_COMPOSITE_SOURCE_SYNC_TIME_COL = 8;
	static final int V1_COMPOSITE_LAST_CHANGE_TIME_COL = 9;

//	static final Schema V1_COMPOSITE_SCHEMA = new Schema(VERSION, "Data Type ID",
//		new Field[] { StringField.INSTANCE, StringField.INSTANCE, BooleanField.INSTANCE,
//			LongField.INSTANCE, IntField.INSTANCE, IntField.INSTANCE, LongField.INSTANCE,
//			LongField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE },
//		new String[] { "Name", "Comment", "Is Union", "Category ID", "Length",
//			"Number Of Components", "Source Archive ID", "Source Data Type ID", "Source Sync Time",
//			"Last Change Time" });

	private Table compositeTable;

	/**
	 * Gets a version 1 adapter for the Composite database table.
	 * @param handle handle to the database containing the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 */
	public CompositeDBAdapterV1(DBHandle handle) throws VersionException {

		compositeTable = handle.getTable(COMPOSITE_TABLE_NAME);
		if (compositeTable == null) {
			throw new VersionException("Missing Table: " + COMPOSITE_TABLE_NAME);
		}
		int version = compositeTable.getSchema().getVersion();
		if (version != VERSION) {
			String msg = "Expected version " + VERSION + " for table " + COMPOSITE_TABLE_NAME +
				" but got " + compositeTable.getSchema().getVersion();
			if (version < VERSION) {
				throw new VersionException(msg, VersionException.OLDER_VERSION, true);
			}
			throw new VersionException(msg, VersionException.NEWER_VERSION, false);
		}
	}

	@Override
	public DBRecord createRecord(String name, String comments, boolean isUnion, long categoryID,
			int length, int computedAlignment, long sourceArchiveID, long sourceDataTypeID,
			long lastChangeTime, int packValue, int minAlignment) throws IOException {
		throw new UnsupportedOperationException("Not allowed to update prior version #" + VERSION +
			" of " + COMPOSITE_TABLE_NAME + " table.");
	}

	@Override
	public DBRecord getRecord(long dataTypeID) throws IOException {
		return translateRecord(compositeTable.getRecord(dataTypeID));
	}

	@Override
	public RecordIterator getRecords() throws IOException {
		return new TranslatedRecordIterator(compositeTable.iterator(), this);
	}

	@Override
	public void updateRecord(DBRecord record, boolean setLastChangeTime) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean removeRecord(long compositeID) throws IOException {
		throw new UnsupportedOperationException("Not allowed to update prior version #" + VERSION +
			" of " + COMPOSITE_TABLE_NAME + " table.");
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
			V1_COMPOSITE_SOURCE_ARCHIVE_ID_COL);
	}

	/* (non-Javadoc)
	 * @see db.RecordTranslator#translateRecord(db.Record)
	 */
	@Override
	public DBRecord translateRecord(DBRecord oldRec) {
		if (oldRec == null) {
			return null;
		}
		DBRecord rec = CompositeDBAdapter.COMPOSITE_SCHEMA.createRecord(oldRec.getKey());
		rec.setString(COMPOSITE_NAME_COL, oldRec.getString(V1_COMPOSITE_NAME_COL));
		rec.setString(COMPOSITE_COMMENT_COL, oldRec.getString(V1_COMPOSITE_COMMENT_COL));
		rec.setBooleanValue(COMPOSITE_IS_UNION_COL,
			oldRec.getBooleanValue(V1_COMPOSITE_IS_UNION_COL));
		rec.setLongValue(COMPOSITE_CAT_COL, oldRec.getLongValue(V1_COMPOSITE_CAT_COL));
		rec.setIntValue(COMPOSITE_LENGTH_COL, oldRec.getIntValue(V1_COMPOSITE_LENGTH_COL));
		rec.setIntValue(COMPOSITE_ALIGNMENT_COL, oldRec.getIntValue(-1));
		rec.setIntValue(COMPOSITE_NUM_COMPONENTS_COL,
			oldRec.getIntValue(V1_COMPOSITE_NUM_COMPONENTS_COL));
		rec.setLongValue(COMPOSITE_SOURCE_ARCHIVE_ID_COL,
			oldRec.getLongValue(V1_COMPOSITE_SOURCE_ARCHIVE_ID_COL));
		rec.setLongValue(COMPOSITE_UNIVERSAL_DT_ID,
			oldRec.getLongValue(V1_COMPOSITE_UNIVERSAL_DT_ID_COL));
		rec.setLongValue(COMPOSITE_SOURCE_SYNC_TIME_COL,
			oldRec.getLongValue(V1_COMPOSITE_SOURCE_SYNC_TIME_COL));
		rec.setLongValue(COMPOSITE_LAST_CHANGE_TIME_COL,
			oldRec.getLongValue(V1_COMPOSITE_LAST_CHANGE_TIME_COL));
		rec.setIntValue(COMPOSITE_PACKING_COL, CompositeInternal.NO_PACKING);
		rec.setIntValue(COMPOSITE_MIN_ALIGN_COL, CompositeInternal.DEFAULT_ALIGNMENT);
		return rec;
	}

	@Override
	DBRecord getRecordWithIDs(UniversalID sourceID, UniversalID datatypeID) throws IOException {
		Field[] keys = compositeTable.findRecords(new LongField(datatypeID.getValue()),
			V1_COMPOSITE_UNIVERSAL_DT_ID_COL);

		for (Field key : keys) {
			DBRecord record = compositeTable.getRecord(key);
			if (record.getLongValue(V1_COMPOSITE_SOURCE_ARCHIVE_ID_COL) == sourceID.getValue()) {
				return translateRecord(record);
			}
		}
		return null;
	}
}
