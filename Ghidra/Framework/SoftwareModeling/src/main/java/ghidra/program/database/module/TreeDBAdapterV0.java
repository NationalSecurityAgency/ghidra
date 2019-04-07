/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.util.exception.AssertException;
import ghidra.util.exception.VersionException;

import java.io.IOException;

import db.*;

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

	/**
	 * @see ghidra.program.database.module.TreeDBAdapter#createRecord(long, java.lang.String, int)
	 */
	public Record createRecord(String name) throws IOException {
		Record record = TreeManager.TREE_SCHEMA.createRecord(treeTable.getKey());
		record.setString(TreeManager.TREE_NAME_COL, name);
		record.setLongValue(TreeManager.MODIFICATION_NUM_COL, 0);
		treeTable.putRecord(record);
		return record;
	}

	/**
	 * @see ghidra.program.database.module.TreeDBAdapter#deleteRecord(long)
	 */
	public boolean deleteRecord(long treeID) throws IOException {

		if (treeTable.deleteRecord(treeID)) {
			handle.deleteTable(TreeManager.getFragmentTableName(treeID));
			handle.deleteTable(TreeManager.getModuleTableName(treeID));
			handle.deleteTable(TreeManager.getParentChildTableName(treeID));
			return true;
		}
		return false;
	}

	/**
	 * @see ghidra.program.database.module.TreeDBAdapter#getRecord(long)
	 */
	public Record getRecord(long treeID) throws IOException {
		return treeTable.getRecord(treeID);
	}

	/**
	 * @see ghidra.program.database.module.TreeDBAdapter#getRecord(java.lang.String)
	 */
	public Record getRecord(String name) throws IOException {
		long[] keys = treeTable.findRecords(new StringField(name), TreeManager.TREE_NAME_COL);
		if (keys.length == 0) {
			return null;
		}
		if (keys.length > 1) {
			throw new AssertException("Found " + keys.length + " trees named " + name);
		}
		return treeTable.getRecord(keys[0]);
	}

	/**
	 * @see ghidra.program.database.module.TreeDBAdapter#getRecords()
	 */
	public RecordIterator getRecords() throws IOException {
		return treeTable.iterator();
	}

	/**
	 * 
	 * @see ghidra.program.database.module.TreeDBAdapter#updateRecord(ghidra.framework.store.db.Record)
	 */
	public void updateRecord(Record record) throws IOException {
		treeTable.putRecord(record);
	}

}
