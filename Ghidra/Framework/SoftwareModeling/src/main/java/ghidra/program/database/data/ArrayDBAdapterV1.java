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
 *
 * To change the template for this generated type comment go to
 * {@literal Window>Preferences>Java>Code Generation>Code and Comments}
 * 
 * 
 */
class ArrayDBAdapterV1 extends ArrayDBAdapter {
	static final int VERSION = 1;
	static final String ARRAY_TABLE_NAME = "Arrays";
	static final int V1_ARRAY_DT_ID_COL = 0;
	static final int V1_ARRAY_DIM_COL = 1;
	static final int V1_ARRAY_LENGTH_COL = 2;
	static final int V1_ARRAY_CAT_COL = 3;

	private Table table;

	public static final Schema V1_SCHEMA =
		new Schema(VERSION, "Array ID",
			new Field[] { LongField.INSTANCE, IntField.INSTANCE, IntField.INSTANCE,
				LongField.INSTANCE },
			new String[] { "Data Type ID", "Dimension", "Length", "Cat ID" });

	/**
	 * Constructor
	 * 
	 */
	public ArrayDBAdapterV1(DBHandle handle, boolean create) throws VersionException, IOException {

		if (create) {
			table = handle.createTable(ARRAY_TABLE_NAME, V1_SCHEMA, new int[] { V1_ARRAY_CAT_COL });
		}
		else {
			table = handle.getTable(ARRAY_TABLE_NAME);
			if (table == null) {
				throw new VersionException("Missing Table: " + ARRAY_TABLE_NAME);
			}
			else if (table.getSchema().getVersion() != VERSION) {
				throw new VersionException(VersionException.NEWER_VERSION, false);
			}
		}
	}

	@Override
	public DBRecord createRecord(long dataTypeID, int numberOfElements, int length, long catID)
			throws IOException {

		long tableKey = table.getKey();
//		if (tableKey <= DataManager.VOID_DATATYPE_ID) {
//			tableKey = DataManager.VOID_DATATYPE_ID +1;
//		}
		long key = DataTypeManagerDB.createKey(DataTypeManagerDB.ARRAY, tableKey);

		DBRecord record = V1_SCHEMA.createRecord(key);
		record.setLongValue(V1_ARRAY_DT_ID_COL, dataTypeID);
		record.setIntValue(V1_ARRAY_DIM_COL, numberOfElements);
		record.setIntValue(V1_ARRAY_LENGTH_COL, length);
		record.setLongValue(V1_ARRAY_CAT_COL, catID);
		table.putRecord(record);
		return record;
	}

	@Override
	public DBRecord getRecord(long arrayID) throws IOException {
		return table.getRecord(arrayID);
	}

	@Override
	public RecordIterator getRecords() throws IOException {
		return table.iterator();
	}

	@Override
	public boolean removeRecord(long dataID) throws IOException {
		return table.deleteRecord(dataID);
	}

	@Override
	public void updateRecord(DBRecord record) throws IOException {
		table.putRecord(record);

	}

	@Override
	void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(ARRAY_TABLE_NAME);
	}

	@Override
	Field[] getRecordIdsInCategory(long categoryID) throws IOException {
		return table.findRecords(new LongField(categoryID), V1_ARRAY_CAT_COL);
	}

}
