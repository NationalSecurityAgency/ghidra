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

class CategoryDBAdapterV0 extends CategoryDBAdapter {

	private static final int VERSION = 0;

	static final String CATEGORY_TABLE_NAME = "Categories";
	static final int V0_CATEGORY_NAME_COL = 0;
	static final int V0_CATEGORY_PARENT_COL = 1;

	static final Schema V0_SCHEMA =
		new Schema(0, "Category ID", new Field[] { StringField.INSTANCE, LongField.INSTANCE },
			new String[] { "Name", "Parent ID" });

	private Table table;

	/**
	 * Gets a version 0 adapter for the Category database table.
	 * @param handle handle to the database containing the table.
	 * @param tablePrefix prefix to be used with default table name
	 * @param create true if this constructor should create the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if an IO error occurs
	 */
	CategoryDBAdapterV0(DBHandle handle, String tablePrefix, boolean create)
			throws VersionException, IOException {
		String tableName = tablePrefix + CATEGORY_TABLE_NAME;
		if (create) {
			table = handle.createTable(tableName, V0_SCHEMA, new int[] { V0_CATEGORY_PARENT_COL });
		}
		else {
			table = handle.getTable(tableName);
			if (table == null) {
				throw new VersionException("Missing Table: " + tableName);
			}
			if (table.getSchema().getVersion() != VERSION) {
				throw new VersionException(false);
			}
		}
	}

	@Override
	DBRecord getRecord(long categoryID) throws IOException {
		return table.getRecord(categoryID);
	}

	@Override
	Field[] getRecordIdsWithParent(long categoryID) throws IOException {
		return table.findRecords(new LongField(categoryID), V0_CATEGORY_PARENT_COL);
	}

	@Override
	void updateRecord(long categoryID, long parentID, String name) throws IOException {
		DBRecord rec = table.getSchema().createRecord(categoryID);
		rec.setString(V0_CATEGORY_NAME_COL, name);
		rec.setLongValue(V0_CATEGORY_PARENT_COL, parentID);
		table.putRecord(rec);
	}

	@Override
	void putRecord(DBRecord record) throws IOException {
		table.putRecord(record);
	}

	@Override
	DBRecord createCategory(String name, long parentID) throws IOException {
		long key = table.getKey();
		if (key == 0) {
			key = 1;
		}
		DBRecord rec = table.getSchema().createRecord(key);
		rec.setString(V0_CATEGORY_NAME_COL, name);
		rec.setLongValue(V0_CATEGORY_PARENT_COL, parentID);
		table.putRecord(rec);
		return rec;

	}

	@Override
	boolean removeCategory(long categoryID) throws IOException {
		return table.deleteRecord(categoryID);
	}

	@Override
	DBRecord getRootRecord() throws IOException {
		Field[] keys = table.findRecords(new LongField(-1), V0_CATEGORY_PARENT_COL);
		if (keys.length != 1) {
			throw new IOException("Found " + keys.length + " entries for root category");
		}
		return getRecord(keys[0].getLongValue());
	}

	@Override
	int getRecordCount() {
		return table.getRecordCount();
	}

}
