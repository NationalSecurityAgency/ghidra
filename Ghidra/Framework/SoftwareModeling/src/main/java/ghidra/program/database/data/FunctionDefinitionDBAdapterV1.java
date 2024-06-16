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
 * Version 1 implementation for accessing the Function Signature Definition database table. 
 * 
 * NOTE: Use of tablePrefix introduced with this adapter version.
 */
class FunctionDefinitionDBAdapterV1 extends FunctionDefinitionDBAdapter
		implements RecordTranslator {

	static final int VERSION = 1;

	static final int V1_FUNCTION_DEF_NAME_COL = 0;
	static final int V1_FUNCTION_DEF_COMMENT_COL = 1;
	static final int V1_FUNCTION_DEF_CAT_ID_COL = 2;
	static final int V1_FUNCTION_DEF_RETURN_ID_COL = 3;
	static final int V1_FUNCTION_DEF_FLAGS_COL = 4;
	static final int V1_FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL = 5;
	static final int V1_FUNCTION_DEF_UNIVERSAL_DT_ID_COL = 6;
	static final int V1_FUNCTION_DEF_SOURCE_SYNC_TIME_COL = 7;
	static final int V1_FUNCTION_DEF_LAST_CHANGE_TIME_COL = 8;

//  DO NOT REMOVE WHAT'S BELOW - this documents the schema used in version 0.
//	static final Schema V1_FUN_DEF_SCHEMA = new Schema(VERSION, "Data Type ID",
//		new Field[] { StringField.INSTANCE, StringField.INSTANCE, LongField.INSTANCE,
//			LongField.INSTANCE, ByteField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE,
//			LongField.INSTANCE, LongField.INSTANCE },
//		new String[] { "Name", "Comment", "Category ID", "Return Type ID", "Flags",
//			"Source Archive ID", "Source Data Type ID", "Source Sync Time", "Last Change Time" });

	// Flags Bits 1..4 used for generic calling convention ID
	private static final int GENERIC_CALLING_CONVENTION_FLAG_MASK = 0xf;
	private static final int GENERIC_CALLING_CONVENTION_FLAG_SHIFT = 1;

	private Table table;
	private CallingConventionDBAdapter callConvAdapter; // must be null if not performing upgrade

	/**
	 * Gets a version 1 read-only adapter for the Function Definition database table.
	 * @param handle handle to the database containing the table.
	 * @param tablePrefix prefix to be used with default table name
	 * @param callConvAdapter calling convention table adapter suitable to add new conventions
	 * (e.g., this adapter being used during upgrade operation).  Should be null if not performing
	 * an upgrade in which case calling convention IDs will reflect generic convention ordinals.
	 * 
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 */
	public FunctionDefinitionDBAdapterV1(DBHandle handle, String tablePrefix,
			CallingConventionDBAdapter callConvAdapter) throws VersionException {
		this.callConvAdapter = callConvAdapter;
		String tableName = tablePrefix + FUNCTION_DEF_TABLE_NAME;
		table = handle.getTable(tableName);
		if (table == null) {
			throw new VersionException(true);
		}
		int version = table.getSchema().getVersion();
		if (version != VERSION) {
			throw new VersionException(version < VERSION);
		}
	}

	@Override
	boolean usesGenericCallingConventionId() {
		return callConvAdapter == null;
	}

	@Override
	public int getRecordCount() {
		return table.getRecordCount();
	}

	@Override
	DBRecord createRecord(String name, String comments, long categoryID, long returnDtID,
			boolean hasNoReturn, boolean hasVarArgs, byte callingConventionID, long sourceArchiveID,
			long sourceDataTypeID, long lastChangeTime) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	DBRecord getRecord(long functionDefID) throws IOException {
		return translateRecord(table.getRecord(functionDefID));
	}

	@Override
	void updateRecord(DBRecord record, boolean setLastChangeTime) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public RecordIterator getRecords() throws IOException {
		return new TranslatedRecordIterator(table.iterator(), this);
	}

	@Override
	boolean removeRecord(long functionDefID) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(table.getName());
	}

	@Override
	Field[] getRecordIdsInCategory(long categoryID) throws IOException {
		return table.findRecords(new LongField(categoryID), V1_FUNCTION_DEF_CAT_ID_COL);
	}

	@Override
	Field[] getRecordIdsForSourceArchive(long archiveID) throws IOException {
		return table.findRecords(new LongField(archiveID), V1_FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL);
	}

	@Override
	DBRecord getRecordWithIDs(UniversalID sourceID, UniversalID datatypeID) throws IOException {
		Field[] keys = table.findRecords(new LongField(datatypeID.getValue()),
			V1_FUNCTION_DEF_UNIVERSAL_DT_ID_COL);

		for (int i = 0; i < keys.length; i++) {
			DBRecord record = table.getRecord(keys[i]);
			if (record.getLongValue(V1_FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL) == sourceID.getValue()) {
				return record;
			}
		}
		return null;
	}

	@Override
	public DBRecord translateRecord(DBRecord oldRec) {
		if (oldRec == null) {
			return null;
		}
		DBRecord rec = FunctionDefinitionDBAdapter.FUN_DEF_SCHEMA.createRecord(oldRec.getKey());
		rec.setString(FUNCTION_DEF_NAME_COL, oldRec.getString(V1_FUNCTION_DEF_NAME_COL));
		rec.setString(FUNCTION_DEF_COMMENT_COL, oldRec.getString(V1_FUNCTION_DEF_COMMENT_COL));
		rec.setLongValue(FUNCTION_DEF_CAT_ID_COL, oldRec.getLongValue(V1_FUNCTION_DEF_CAT_ID_COL));
		rec.setLongValue(FUNCTION_DEF_RETURN_ID_COL, oldRec.getLongValue(V1_FUNCTION_DEF_RETURN_ID_COL));
		
		byte flags = oldRec.getByteValue(V1_FUNCTION_DEF_FLAGS_COL);
		int mask = GENERIC_CALLING_CONVENTION_FLAG_MASK << GENERIC_CALLING_CONVENTION_FLAG_SHIFT;
		int genericCallConvId = (flags & mask) >> GENERIC_CALLING_CONVENTION_FLAG_SHIFT;
		flags &= (byte) (~mask); // clear old flag bits used for calling convention

		byte callingConventionId = DataTypeManagerDB.UNKNOWN_CALLING_CONVENTION_ID;
		try {
			if (callConvAdapter == null) {
				// Must use old generic calling convention ordinal as ID
				callingConventionId = (byte) genericCallConvId;
			}
			else {
				// It is expected that an open transaction exists during upgrade use
				// and that all records are upgraded prior to general use
				String callingConvention = getGenericCallingConventionName(genericCallConvId);
				callingConventionId = callConvAdapter.getCallingConventionId(callingConvention,
					cc -> {
						/* ignore */ });
			}
		}
		catch (IOException e) {
			// ignore - use unknown convention ID
		}

		rec.setByteValue(FUNCTION_DEF_FLAGS_COL, flags);
		rec.setByteValue(FUNCTION_DEF_CALLCONV_COL, callingConventionId);
		rec.setLongValue(FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL, DataTypeManager.LOCAL_ARCHIVE_KEY);
		rec.setLongValue(FUNCTION_DEF_SOURCE_DT_ID_COL, UniversalIdGenerator.nextID().getValue());
		rec.setLongValue(FUNCTION_DEF_SOURCE_SYNC_TIME_COL, DataType.NO_SOURCE_SYNC_TIME);
		rec.setLongValue(FUNCTION_DEF_LAST_CHANGE_TIME_COL, DataType.NO_LAST_CHANGE_TIME);
		return rec;
	}
}
