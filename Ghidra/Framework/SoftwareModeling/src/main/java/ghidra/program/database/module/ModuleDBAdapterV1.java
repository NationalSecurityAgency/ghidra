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
package ghidra.program.database.module;

import java.io.IOException;

import db.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.VersionException;

class ModuleDBAdapterV1 extends ModuleDBAdapter {

	static final int V1_VERSION = 1;

	static final int V1_MODULE_NAME_COL = 0;
	static final int V1_MODULE_COMMENTS_COL = 1;
	static final int V1_MODULE_CHILD_COUNT_COL = 2;

	static final Schema V1_MODULE_SCHEMA =
		new Schema(V1_VERSION, "Key",
			new Field[] { StringField.INSTANCE, StringField.INSTANCE, IntField.INSTANCE },
			new String[] { "Name", "Comments", "ChildCount" });

	private Table moduleTable;

	/**
	 * Gets a version 0 adapter for the program tree module database table.
	 * @param handle handle to the database containing the table.
	 * @param create true if this constructor should create the table.
	 * @param treeID associated program tree ID
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if database IO error occurs
	 */
	public ModuleDBAdapterV1(DBHandle handle, boolean create, long treeID)
			throws VersionException, IOException {

		String tableName = getTableName(treeID);

		if (create) {
			moduleTable = handle.createTable(tableName, V1_MODULE_SCHEMA,
				new int[] { V1_MODULE_NAME_COL });
		}
		else {
			moduleTable = handle.getTable(tableName);
			if (moduleTable == null) {
				throw new VersionException("Missing Table: " + tableName);
			}
			int version = moduleTable.getSchema().getVersion();
			if (version != V1_VERSION) {
				throw new VersionException(version < V1_VERSION);
			}
		}
	}

	@Override
	public DBRecord createModuleRecord(long parentModuleID, String name) throws IOException {
		DBRecord record = V1_MODULE_SCHEMA.createRecord(moduleTable.getKey());
		record.setString(V1_MODULE_NAME_COL, name);
		moduleTable.putRecord(record);
		return record;
	}

	@Override
	DBRecord getModuleRecord(long key) throws IOException {
		return moduleTable.getRecord(key);
	}

	@Override
	DBRecord getModuleRecord(String name) throws IOException {
		Field[] keys = moduleTable.findRecords(new StringField(name), V1_MODULE_NAME_COL);
		if (keys.length == 0) {
			return null;
		}
		if (keys.length > 1) {
			throw new AssertException("Found " + keys.length + " modules named " + name);
		}
		return moduleTable.getRecord(keys[0]);
	}

	@Override
	RecordIterator getRecords() throws IOException {
		return moduleTable.iterator();
	}

	@Override
	void updateModuleRecord(DBRecord record) throws IOException {
		moduleTable.putRecord(record);
	}

	@Override
	boolean removeModuleRecord(long childID) throws IOException {
		return moduleTable.deleteRecord(childID);
	}
}
