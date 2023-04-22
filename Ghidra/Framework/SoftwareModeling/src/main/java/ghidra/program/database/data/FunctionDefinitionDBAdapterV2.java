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
 * Version 2 implementation for accessing the Function Signature Definition database table. 
 */
class FunctionDefinitionDBAdapterV2 extends FunctionDefinitionDBAdapter {

	static final int VERSION = 2;
	static final int V2_FUNCTION_DEF_NAME_COL = 0;
	static final int V2_FUNCTION_DEF_COMMENT_COL = 1;
	static final int V2_FUNCTION_DEF_CAT_ID_COL = 2;
	static final int V2_FUNCTION_DEF_RETURN_ID_COL = 3;
	static final int V2_FUNCTION_DEF_FLAGS_COL = 4;
	static final int V2_FUNCTION_DEF_CALLCONV_COL = 5;
	static final int V2_FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL = 6;
	static final int V2_FUNCTION_DEF_UNIVERSAL_DT_ID_COL = 7;
	static final int V2_FUNCTION_DEF_SOURCE_SYNC_TIME_COL = 8;
	static final int V2_FUNCTION_DEF_LAST_CHANGE_TIME_COL = 9;
	static final Schema V2_FUN_DEF_SCHEMA = new Schema(VERSION, "Data Type ID",
		new Field[] { StringField.INSTANCE, StringField.INSTANCE, LongField.INSTANCE,
			LongField.INSTANCE, ByteField.INSTANCE, ByteField.INSTANCE, LongField.INSTANCE,
			LongField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE },
		new String[] { "Name", "Comment", "Category ID", "Return Type ID", "Flags", "Call Conv ID",
			"Source Archive ID", "Source Data Type ID", "Source Sync Time", "Last Change Time" });

	private Table table;

	/**
	 * Gets a version 2 adapter for the Function Definition database table.
	 * @param handle handle to the database containing the table.
	 * @param tablePrefix prefix to be used with default table name
	 * @param create true if this constructor should create the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if an IO error occurs
	 */
	public FunctionDefinitionDBAdapterV2(DBHandle handle, String tablePrefix, boolean create)
			throws VersionException, IOException {
		String tableName = tablePrefix + FUNCTION_DEF_TABLE_NAME;
		if (create) {
			table = handle.createTable(tableName, V2_FUN_DEF_SCHEMA,
				new int[] { V2_FUNCTION_DEF_CAT_ID_COL, V2_FUNCTION_DEF_UNIVERSAL_DT_ID_COL });
		}
		else {
			table = handle.getTable(tableName);
			if (table == null) {
				throw new VersionException(true);
			}
			int version = table.getSchema().getVersion();
			if (version != VERSION) {
				throw new VersionException(version < VERSION);
			}
		}
	}

	@Override
	public int getRecordCount() {
		return table.getRecordCount();
	}

	@Override
	DBRecord createRecord(String name, String comments, long categoryID, long returnDtID,
			boolean hasNoReturn, boolean hasVarArgs, byte callingConventionID, long sourceArchiveID,
			long sourceDataTypeID, long lastChangeTime) throws IOException {
		byte flags = (byte) 0;
		if (hasVarArgs) {
			flags |= FUNCTION_DEF_VARARG_FLAG;
		}
		if (hasNoReturn) {
			flags |= FUNCTION_DEF_NORETURN_FLAG;
		}
		long tableKey = table.getKey();
		long key = DataTypeManagerDB.createKey(DataTypeManagerDB.FUNCTION_DEF, tableKey);
		DBRecord record = V2_FUN_DEF_SCHEMA.createRecord(key);

		record.setString(V2_FUNCTION_DEF_NAME_COL, name);
		record.setString(V2_FUNCTION_DEF_COMMENT_COL, comments);
		record.setLongValue(V2_FUNCTION_DEF_CAT_ID_COL, categoryID);
		record.setLongValue(V2_FUNCTION_DEF_RETURN_ID_COL, returnDtID);
		record.setByteValue(V2_FUNCTION_DEF_FLAGS_COL, flags);
		record.setByteValue(V2_FUNCTION_DEF_CALLCONV_COL, callingConventionID);
		record.setLongValue(V2_FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL, sourceArchiveID);
		record.setLongValue(V2_FUNCTION_DEF_UNIVERSAL_DT_ID_COL, sourceDataTypeID);
		record.setLongValue(V2_FUNCTION_DEF_SOURCE_SYNC_TIME_COL, lastChangeTime);
		record.setLongValue(V2_FUNCTION_DEF_LAST_CHANGE_TIME_COL, lastChangeTime);
		table.putRecord(record);
		return record;
	}

	@Override
	DBRecord getRecord(long functionDefID) throws IOException {
		return table.getRecord(functionDefID);
	}

	@Override
	void updateRecord(DBRecord record, boolean setLastChangeTime) throws IOException {
		if (setLastChangeTime) {
			record.setLongValue(FunctionDefinitionDBAdapter.FUNCTION_DEF_LAST_CHANGE_TIME_COL,
				(new Date()).getTime());
		}
		table.putRecord(record);
	}

	@Override
	public RecordIterator getRecords() throws IOException {
		return table.iterator();
	}

	@Override
	boolean removeRecord(long functionDefID) throws IOException {
		return table.deleteRecord(functionDefID);
	}

	@Override
	void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(table.getName());
	}

	@Override
	Field[] getRecordIdsInCategory(long categoryID) throws IOException {
		return table.findRecords(new LongField(categoryID), V2_FUNCTION_DEF_CAT_ID_COL);
	}

	@Override
	Field[] getRecordIdsForSourceArchive(long archiveID) throws IOException {
		return table.findRecords(new LongField(archiveID), V2_FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL);
	}

	@Override
	DBRecord getRecordWithIDs(UniversalID sourceID, UniversalID datatypeID) throws IOException {
		Field[] keys = table.findRecords(new LongField(datatypeID.getValue()),
			V2_FUNCTION_DEF_UNIVERSAL_DT_ID_COL);

		for (int i = 0; i < keys.length; i++) {
			DBRecord record = table.getRecord(keys[i]);
			if (record.getLongValue(V2_FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL) == sourceID.getValue()) {
				return record;
			}
		}
		return null;
	}
}
