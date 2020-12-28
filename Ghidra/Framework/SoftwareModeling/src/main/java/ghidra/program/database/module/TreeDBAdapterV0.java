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

/**
 *
 * Version 0 of the adapter to access the tree table.
 * 
 * 
 */
class TreeDBAdapterV0 implements TreeDBAdapter {

	private Table treeTable;
	private DBHandle handle;

	TreeDBAdapterV0(DBHandle handle) throws VersionException {
		this.handle = handle;
		treeTable = handle.getTable(TreeManager.TREE_TABLE_NAME);
		testVersion(0);
	}

	private void testVersion(int expectedVersion) throws VersionException {

		if (treeTable == null) {
			throw new VersionException("Tree table not found");
		}
		int versionNumber = treeTable.getSchema().getVersion();
		if (versionNumber != expectedVersion) {
			throw new VersionException(VersionException.NEWER_VERSION, false);
		}
	}

	@Override
	public DBRecord createRecord(String name) throws IOException {
		DBRecord record = TreeManager.TREE_SCHEMA.createRecord(treeTable.getKey());
		record.setString(TreeManager.TREE_NAME_COL, name);
		record.setLongValue(TreeManager.MODIFICATION_NUM_COL, 0);
		treeTable.putRecord(record);
		return record;
	}

	@Override
	public boolean deleteRecord(long treeID) throws IOException {

		if (treeTable.deleteRecord(treeID)) {
			handle.deleteTable(TreeManager.getFragmentTableName(treeID));
			handle.deleteTable(TreeManager.getModuleTableName(treeID));
			handle.deleteTable(TreeManager.getParentChildTableName(treeID));
			return true;
		}
		return false;
	}

	@Override
	public DBRecord getRecord(long treeID) throws IOException {
		return treeTable.getRecord(treeID);
	}

	@Override
	public DBRecord getRecord(String name) throws IOException {
		Field[] keys = treeTable.findRecords(new StringField(name), TreeManager.TREE_NAME_COL);
		if (keys.length == 0) {
			return null;
		}
		if (keys.length > 1) {
			throw new AssertException("Found " + keys.length + " trees named " + name);
		}
		return treeTable.getRecord(keys[0]);
	}

	@Override
	public RecordIterator getRecords() throws IOException {
		return treeTable.iterator();
	}

	@Override
	public void updateRecord(DBRecord record) throws IOException {
		treeTable.putRecord(record);
	}

}
