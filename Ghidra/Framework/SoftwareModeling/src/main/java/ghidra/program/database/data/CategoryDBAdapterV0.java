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
/*
 *
 */
package ghidra.program.database.data;

import java.io.IOException;

import db.*;
import ghidra.util.exception.VersionException;

class CategoryDBAdapterV0 extends CategoryDBAdapter {
	static final String CATEGORY_TABLE_NAME = "Categories";
	static final int V0_CATEGORY_NAME_COL = 0;
	static final int V0_CATEGORY_PARENT_COL = 1;
	static final Schema V0_SCHEMA =
		new Schema(0, "Category ID", new Field[] { StringField.INSTANCE, LongField.INSTANCE },
			new String[] { "Name", "Parent ID" });

	private Table table;

	/**
	 * Constructor
	 * 
	 */
	public CategoryDBAdapterV0(DBHandle handle, int openMode) throws VersionException, IOException {

		if (openMode == DBConstants.CREATE) {
			table = handle.createTable(CATEGORY_TABLE_NAME, V0_SCHEMA,
				new int[] { V0_CATEGORY_PARENT_COL });
		}
		else {
			table = handle.getTable(CATEGORY_TABLE_NAME);
			if (table == null) {
				throw new VersionException("Missing Table: " + CATEGORY_TABLE_NAME);
			}
			else if (table.getSchema().getVersion() != 0) {
				throw new VersionException("Expected version 0 for table " + CATEGORY_TABLE_NAME +
					" but got " + table.getSchema().getVersion());
			}
		}
	}

	@Override
	public DBRecord getRecord(long categoryID) throws IOException {
		return table.getRecord(categoryID);
	}

	@Override
	public Field[] getRecordIdsWithParent(long categoryID) throws IOException {
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
	public DBRecord createCategory(String name, long parentID) throws IOException {
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
	public boolean removeCategory(long categoryID) throws IOException {
		return table.deleteRecord(categoryID);
	}

	@Override
	public DBRecord getRootRecord() throws IOException {
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
