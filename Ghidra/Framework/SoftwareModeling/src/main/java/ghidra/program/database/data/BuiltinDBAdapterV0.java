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
 * Version 0 implementation of the adapter for accessing the built-ins table.
 */
class BuiltinDBAdapterV0 extends BuiltinDBAdapter {
	static final String BUILT_IN_TABLE_NAME = "Built-in datatypes";
	static final int V0_BUILT_IN_NAME_COL = 0;
	static final int V0_BUILT_IN_CLASSNAME_COL = 1;
	static final int V0_BUILT_IN_CAT_COL = 2;
	static final Schema V0_SCHEMA = new Schema(0, "Data Type ID",
		new Field[] { StringField.INSTANCE, StringField.INSTANCE, LongField.INSTANCE },
		new String[] { "Name", "Class Name", "Category ID" });
	private Table table;

	/**
	 * Gets a version 0 adapter for the Built-Ins database table.
	 * @param handle handle to the database containing the table.
	 * @param create true if this constructor should create the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if there is trouble accessing the database.
	 */
	public BuiltinDBAdapterV0(DBHandle handle, boolean create)
			throws VersionException, IOException {

		if (create) {
			table = handle.createTable(BUILT_IN_TABLE_NAME, V0_SCHEMA,
				new int[] { V0_BUILT_IN_CAT_COL });
		}
		else {
			table = handle.getTable(BUILT_IN_TABLE_NAME);
			if (table == null) {
				throw new VersionException("Missing Table: " + BUILT_IN_TABLE_NAME);
			}
			else if (table.getSchema().getVersion() != 0) {
				throw new VersionException("Expected version 0 for table " + BUILT_IN_TABLE_NAME +
					" but got " + table.getSchema().getVersion());
			}
		}
	}

	@Override
	public DBRecord getRecord(long dataTypeID) throws IOException {
		return table.getRecord(dataTypeID);
	}

	@Override
	public Field[] getRecordIdsInCategory(long categoryID) throws IOException {
		return table.findRecords(new LongField(categoryID), V0_BUILT_IN_CAT_COL);
	}

	@Override
	public void updateRecord(DBRecord record) throws IOException {
		table.putRecord(record);
	}

	@Override
	public boolean removeRecord(long dataID) throws IOException {
		return table.deleteRecord(dataID);
	}

	@Override
	public DBRecord createRecord(String name, String className, long categoryID) throws IOException {

		long tableKey = table.getKey();
		if (tableKey <= 100) {
			tableKey = 100;
		}
		long key = DataTypeManagerDB.createKey(DataTypeManagerDB.BUILT_IN, tableKey);

		DBRecord record = V0_SCHEMA.createRecord(key);
		record.setString(V0_BUILT_IN_NAME_COL, name);
		record.setString(V0_BUILT_IN_CLASSNAME_COL, className);
		record.setLongValue(V0_BUILT_IN_CAT_COL, categoryID);
		table.putRecord(record);
		return record;
	}

	@Override
	public RecordIterator getRecords() throws IOException {
		return table.iterator();
	}

}
