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

class FragmentDBAdapterV0 extends FragmentDBAdapter {

	static final int V0_VERSION = 0;

	static final int V0_FRAGMENT_NAME_COL = 0;
	static final int V0_FRAGMENT_COMMENTS_COL = 1;

	static final Schema V0_FRAGMENT_SCHEMA =
		new Schema(V0_VERSION, "Key", new Field[] { StringField.INSTANCE, StringField.INSTANCE },
			new String[] { "Name", "Comments" });

	private Table fragmentTable;

	/**
	 * Gets a version 0 adapter for the program tree fragment database table.
	 * @param handle handle to the database containing the table.
	 * @param create true if this constructor should create the table.
	 * @param treeID associated program tree ID
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if database IO error occurs
	 */
	public FragmentDBAdapterV0(DBHandle handle, boolean create, long treeID)
			throws VersionException, IOException {

		String tableName = getTableName(treeID);

		if (create) {
			fragmentTable = handle.createTable(tableName, V0_FRAGMENT_SCHEMA,
				new int[] { V0_FRAGMENT_NAME_COL });
		}
		else {
			fragmentTable = handle.getTable(tableName);
			if (fragmentTable == null) {
				throw new VersionException("Missing Table: " + tableName);
			}
			int version = fragmentTable.getSchema().getVersion();
			if (version != V0_VERSION) {
				throw new VersionException(VersionException.NEWER_VERSION, false);
			}
		}
	}

	@Override
	public DBRecord createFragmentRecord(long parentFragmentID, String name) throws IOException {
		long key = fragmentTable.getKey();
		if (key == 0) {
			key = 1;
		}
		DBRecord record = V0_FRAGMENT_SCHEMA.createRecord(key);
		record.setString(V0_FRAGMENT_NAME_COL, name);
		fragmentTable.putRecord(record);
		return record;
	}

	@Override
	DBRecord getFragmentRecord(long key) throws IOException {
		return fragmentTable.getRecord(key);
	}

	@Override
	DBRecord getFragmentRecord(String name) throws IOException {
		Field[] keys = fragmentTable.findRecords(new StringField(name), V0_FRAGMENT_NAME_COL);
		if (keys.length == 0) {
			return null;
		}
		if (keys.length > 1) {
			throw new AssertException("Found " + keys.length + " fragments named " + name);
		}
		return fragmentTable.getRecord(keys[0]);
	}

	@Override
	void updateFragmentRecord(DBRecord record) throws IOException {
		fragmentTable.putRecord(record);
	}

	@Override
	boolean removeFragmentRecord(long childID) throws IOException {
		return fragmentTable.deleteRecord(childID);
	}
}
