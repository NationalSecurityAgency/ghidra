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
import ghidra.util.exception.VersionException;

/**
 * Version 0 implementation for accessing the Function Definition Parameters database table. 
 */
class FunctionParameterAdapterV0 extends FunctionParameterAdapter implements RecordTranslator {

	static final int VERSION = 0;
	// Parameter Table Columns
	static final int V0_PARAMETER_PARENT_ID_COL = 0;
	static final int V0_PARAMETER_DT_ID_COL = 1;
	static final int V0_PARAMETER_NAME_COL = 2;
	static final int V0_PARAMETER_COMMENT_COL = 3;
	static final int V0_PARAMETER_ORDINAL_COL = 4;

	static final Schema V0_PARAMETER_SCHEMA = new Schema(VERSION, "Parameter ID",
		new Field[] { LongField.INSTANCE, LongField.INSTANCE, StringField.INSTANCE,
			StringField.INSTANCE, IntField.INSTANCE },
		new String[] { "Parent ID", "Data Type ID", "Name", "Comment", "Ordinal" });

	private Table parameterTable;

	/**
	 * Gets a version 0 adapter for the Function Definition Parameter database table.
	 * @param handle handle to the database containing the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 */
	public FunctionParameterAdapterV0(DBHandle handle) throws VersionException {

		parameterTable = handle.getTable(PARAMETER_TABLE_NAME);
		if (parameterTable == null) {
			throw new VersionException(true);
		}
		int version = parameterTable.getSchema().getVersion();
		if (version != VERSION) {
			String msg = "Expected version " + VERSION + " for table " + PARAMETER_TABLE_NAME +
				" but got " + parameterTable.getSchema().getVersion();
			if (version < VERSION) {
				throw new VersionException(msg, VersionException.OLDER_VERSION, true);
			}
			throw new VersionException(msg, VersionException.NEWER_VERSION, false);
		}
	}

	@Override
	public DBRecord createRecord(long dataTypeID, long parentID, int ordinal, String name,
			String comment, int dtLength) throws IOException {

		long tableKey = parameterTable.getKey();
//		if (tableKey <= DataManager.VOID_DATATYPE_ID) {
//			tableKey = DataManager.VOID_DATATYPE_ID +1;
//		}
		long key = DataTypeManagerDB.createKey(DataTypeManagerDB.PARAMETER, tableKey);
		DBRecord record = V0_PARAMETER_SCHEMA.createRecord(key);
		record.setLongValue(V0_PARAMETER_PARENT_ID_COL, parentID);
		record.setLongValue(V0_PARAMETER_DT_ID_COL, dataTypeID);
		record.setString(V0_PARAMETER_NAME_COL, name);
		record.setString(V0_PARAMETER_COMMENT_COL, comment);
		record.setIntValue(V0_PARAMETER_ORDINAL_COL, ordinal);
		parameterTable.putRecord(record);
		return record;
	}

	@Override
	public DBRecord getRecord(long parameterID) throws IOException {
		return translateRecord(parameterTable.getRecord(parameterID));
	}

	@Override
	protected RecordIterator getRecords() throws IOException {
		return new TranslatedRecordIterator(parameterTable.iterator(), this);
	}

	@Override
	public void updateRecord(DBRecord record) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean removeRecord(long parameterID) throws IOException {
		return false;
	}

	@Override
	protected void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(PARAMETER_TABLE_NAME);
	}

	@Override
	public Field[] getParameterIdsInFunctionDef(long functionDefID) throws IOException {
		return parameterTable.findRecords(new LongField(functionDefID), V0_PARAMETER_PARENT_ID_COL);
	}

	/* (non-Javadoc)
	 * @see db.RecordTranslator#translateRecord(db.Record)
	 */
	@Override
	public DBRecord translateRecord(DBRecord oldRec) {
		if (oldRec == null) {
			return null;
		}
		DBRecord rec = FunctionParameterAdapter.PARAMETER_SCHEMA.createRecord(oldRec.getKey());
		rec.setLongValue(FunctionParameterAdapter.PARAMETER_PARENT_ID_COL,
			oldRec.getLongValue(V0_PARAMETER_PARENT_ID_COL));
		rec.setLongValue(FunctionParameterAdapter.PARAMETER_DT_ID_COL,
			oldRec.getLongValue(V0_PARAMETER_DT_ID_COL));
		rec.setString(FunctionParameterAdapter.PARAMETER_NAME_COL,
			oldRec.getString(V0_PARAMETER_NAME_COL));
		rec.setString(FunctionParameterAdapter.PARAMETER_COMMENT_COL,
			oldRec.getString(V0_PARAMETER_COMMENT_COL));
		rec.setIntValue(FunctionParameterAdapter.PARAMETER_ORDINAL_COL,
			oldRec.getIntValue(V0_PARAMETER_ORDINAL_COL));
		rec.setIntValue(FunctionParameterAdapter.PARAMETER_DT_LENGTH_COL, 1);

		return rec;
	}

}
