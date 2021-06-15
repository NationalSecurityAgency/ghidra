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
 * Version 1 implementation for accessing the Function Definition Parameters database table. 
 */
class FunctionParameterAdapterV1 extends FunctionParameterAdapter {
	static final int VERSION = 1;

	// Parameter Table Columns
	static final int V1_PARAMETER_PARENT_ID_COL = 0;
	static final int V1_PARAMETER_DT_ID_COL = 1;
	static final int V1_PARAMETER_NAME_COL = 2;
	static final int V1_PARAMETER_COMMENT_COL = 3;
	static final int V1_PARAMETER_ORDINAL_COL = 4;
	static final int V1_PARAMETER_DT_LENGTH_COL = 5;

	static final Schema V1_PARAMETER_SCHEMA = new Schema(VERSION, "Parameter ID",
		new Field[] { LongField.INSTANCE, LongField.INSTANCE, StringField.INSTANCE,
			StringField.INSTANCE, IntField.INSTANCE, IntField.INSTANCE },
		new String[] { "Parent ID", "Data Type ID", "Name", "Comment", "Ordinal",
			"Data Type Length" });

	private Table table;

	/**
	 * Gets a version 1 adapter for the Function Definition Parameter database table.
	 * @param handle handle to the database containing the table.
	 * @param create true if this constructor should create the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 */
	public FunctionParameterAdapterV1(DBHandle handle, boolean create)
			throws VersionException, IOException {

		if (create) {
			table = handle.createTable(PARAMETER_TABLE_NAME, V1_PARAMETER_SCHEMA,
				new int[] { V1_PARAMETER_PARENT_ID_COL });
		}
		else {
			table = handle.getTable(PARAMETER_TABLE_NAME);
			if (table == null) {
				throw new VersionException(true);
			}
			int version = table.getSchema().getVersion();
			if (version != VERSION) {
				String msg = "Expected version " + VERSION + " for table " + PARAMETER_TABLE_NAME +
					" but got " + table.getSchema().getVersion();
				if (version < VERSION) {
					throw new VersionException(msg, VersionException.OLDER_VERSION, true);
				}
				throw new VersionException(msg, VersionException.NEWER_VERSION, false);
			}
		}
	}

	@Override
	public DBRecord createRecord(long dataTypeID, long parentID, int ordinal, String name,
			String comment, int dtLength) throws IOException {

		long tableKey = table.getKey();
//		if (tableKey <= DataManager.VOID_DATATYPE_ID) {
//			tableKey = DataManager.VOID_DATATYPE_ID +1;
//		}
		long key = DataTypeManagerDB.createKey(DataTypeManagerDB.PARAMETER, tableKey);
		DBRecord record = V1_PARAMETER_SCHEMA.createRecord(key);
		record.setLongValue(V1_PARAMETER_PARENT_ID_COL, parentID);
		record.setLongValue(V1_PARAMETER_DT_ID_COL, dataTypeID);
		record.setString(V1_PARAMETER_NAME_COL, name);
		record.setString(V1_PARAMETER_COMMENT_COL, comment);
		record.setIntValue(V1_PARAMETER_ORDINAL_COL, ordinal);
		record.setIntValue(V1_PARAMETER_DT_LENGTH_COL, dtLength);
		table.putRecord(record);
		return record;
	}

	@Override
	public DBRecord getRecord(long parameterID) throws IOException {
		return table.getRecord(parameterID);
	}

	@Override
	protected RecordIterator getRecords() throws IOException {
		return table.iterator();
	}

	@Override
	public void updateRecord(DBRecord record) throws IOException {
		table.putRecord(record);
	}

	@Override
	public boolean removeRecord(long parameterID) throws IOException {
		return table.deleteRecord(parameterID);
	}

	@Override
	protected void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(PARAMETER_TABLE_NAME);
	}

	@Override
	public Field[] getParameterIdsInFunctionDef(long functionDefID) throws IOException {
		return table.findRecords(new LongField(functionDefID), V1_PARAMETER_PARENT_ID_COL);
	}

}
