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
import ghidra.program.model.data.*;
import ghidra.util.UniversalID;
import ghidra.util.UniversalIdGenerator;
import ghidra.util.exception.VersionException;

/**
 * Version 0 implementation for accessing the Function Signature Definition database table. 
 */
class FunctionDefinitionDBAdapterV0 extends FunctionDefinitionDBAdapter
		implements RecordTranslator {
	static final int VERSION = 0;
	static final int V0_FUNCTION_DEF_NAME_COL = 0;
	static final int V0_FUNCTION_DEF_COMMENT_COL = 1;
	static final int V0_FUNCTION_DEF_CAT_ID_COL = 2;
	static final int V0_FUNCTION_DEF_RETURN_ID_COL = 3;
	static final int V0_FUNCTION_DEF_FLAGS_COL = 4;
//  DO NOT REMOVE WHAT'S BELOW - this documents the schema used in version 0.
//	static final Schema V0_FUN_DEF_SCHEMA = new Schema(VERSION, "Data Type ID",
//								new Class[] {StringField.class, StringField.class,
//											LongField.class, LongField.class,
//											ByteField.class},
//								new String[] {"Name", "Comment",
//											"Category ID", "Return Type ID", 
//											"Flags"});

	private Table table;

	/**
	 * Gets a version 0 adapter for the Function Definition database table.
	 * @param handle handle to the database containing the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 */
	public FunctionDefinitionDBAdapterV0(DBHandle handle) throws VersionException {

		table = handle.getTable(FUNCTION_DEF_TABLE_NAME);
		if (table == null) {
			throw new VersionException("Missing Table: " + FUNCTION_DEF_TABLE_NAME);
		}
		int version = table.getSchema().getVersion();
		if (version != VERSION) {
			String msg = "Expected version " + VERSION + " for table " + FUNCTION_DEF_TABLE_NAME +
				" but got " + table.getSchema().getVersion();
			if (version < VERSION) {
				throw new VersionException(msg, VersionException.OLDER_VERSION, true);
			}
			throw new VersionException(msg, VersionException.NEWER_VERSION, false);
		}
	}

	@Override
	public DBRecord createRecord(String name, String comments, long categoryID, long returnDtID,
			boolean hasVarArgs, GenericCallingConvention genericCallingConvention,
			long sourceArchiveID, long sourceDataTypeID, long lastChangeTime) throws IOException {
		throw new UnsupportedOperationException("Not allowed to update prior version #" + VERSION +
			" of " + FUNCTION_DEF_TABLE_NAME + " table.");
	}

	@Override
	public DBRecord getRecord(long functionDefID) throws IOException {
		return translateRecord(table.getRecord(functionDefID));
	}

	@Override
	public RecordIterator getRecords() throws IOException {
		return new TranslatedRecordIterator(table.iterator(), this);
	}

	@Override
	public void updateRecord(DBRecord record, boolean setLastChangeTime) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean removeRecord(long functionDefID) throws IOException {
		return table.deleteRecord(functionDefID);
	}

	@Override
	protected void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(FUNCTION_DEF_TABLE_NAME);
	}

	@Override
	public Field[] getRecordIdsInCategory(long categoryID) throws IOException {
		return table.findRecords(new LongField(categoryID), V0_FUNCTION_DEF_CAT_ID_COL);
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
		DBRecord rec = FunctionDefinitionDBAdapter.FUN_DEF_SCHEMA.createRecord(oldRec.getKey());
		rec.setString(FUNCTION_DEF_NAME_COL, oldRec.getString(V0_FUNCTION_DEF_NAME_COL));
		rec.setString(FUNCTION_DEF_COMMENT_COL, oldRec.getString(V0_FUNCTION_DEF_COMMENT_COL));
		rec.setLongValue(FUNCTION_DEF_CAT_ID_COL, oldRec.getLongValue(V0_FUNCTION_DEF_CAT_ID_COL));
		rec.setLongValue(FUNCTION_DEF_RETURN_ID_COL,
			oldRec.getLongValue(V0_FUNCTION_DEF_RETURN_ID_COL));
		rec.setByteValue(FUNCTION_DEF_FLAGS_COL, oldRec.getByteValue(V0_FUNCTION_DEF_FLAGS_COL));
		rec.setLongValue(FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL, DataTypeManager.LOCAL_ARCHIVE_KEY);
		rec.setLongValue(FUNCTION_DEF_SOURCE_DT_ID_COL, UniversalIdGenerator.nextID().getValue());
		rec.setLongValue(FUNCTION_DEF_SOURCE_SYNC_TIME_COL, DataType.NO_SOURCE_SYNC_TIME);
		rec.setLongValue(FUNCTION_DEF_LAST_CHANGE_TIME_COL, DataType.NO_LAST_CHANGE_TIME);
		return rec;
	}

	@Override
	DBRecord getRecordWithIDs(UniversalID sourceID, UniversalID datatypeID) throws IOException {
		return null;
	}

}
