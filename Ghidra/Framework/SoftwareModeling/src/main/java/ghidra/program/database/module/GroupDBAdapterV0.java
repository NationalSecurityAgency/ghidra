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

import ghidra.util.exception.*;

import java.io.IOException;

import db.*;

/**
 *
 * Version 0 implementation for the GroupDBAdapter.
 *  
 * 
 */
class GroupDBAdapterV0 implements GroupDBAdapter {

	private Table moduleTable;
	private Table fragmentTable;
	private Table parentChildTable;

	GroupDBAdapterV0(DBHandle handle, String moduleTableName, String fragTableName,
			String parentChildTableName) throws VersionException {

		moduleTable = handle.getTable(moduleTableName);
		fragmentTable = handle.getTable(fragTableName);
		parentChildTable = handle.getTable(parentChildTableName);
		testVersion(moduleTable, 0, moduleTableName);
		testVersion(fragmentTable, 0, fragTableName);
		testVersion(parentChildTable, 0, parentChildTableName);
	}

	/**
	 * @see ghidra.program.database.module.GroupDBAdapter#createModule(java.lang.String)
	 */
	public Record createModule(long parentModuleID, String name) throws IOException,
			DuplicateNameException {

		if (getModuleRecord(name) != null || getFragmentRecord(name) != null) {
			throw new DuplicateNameException(name + " already exists");
		}
		Record record = TreeManager.MODULE_SCHEMA.createRecord(moduleTable.getKey());
		record.setString(TreeManager.MODULE_NAME_COL, name);
		moduleTable.putRecord(record);

		// insert record for parent/child table
		Record pcRec = TreeManager.PARENT_CHILD_SCHEMA.createRecord(parentChildTable.getKey());
		pcRec.setLongValue(TreeManager.PARENT_ID_COL, parentModuleID);
		pcRec.setLongValue(TreeManager.CHILD_ID_COL, record.getKey());
		parentChildTable.putRecord(pcRec);

		return record;
	}

	/**
	 * @see ghidra.program.database.module.GroupDBAdapter#createFragment(java.lang.String)
	 */
	public Record createFragment(long parentModuleID, String name) throws IOException,
			DuplicateNameException {

		if (getFragmentRecord(name) != null || getModuleRecord(name) != null) {
			throw new DuplicateNameException(name + " already exists");
		}
		long key = fragmentTable.getKey();
		if (key == 0) {
			key = 1;
		}
		Record record = TreeManager.FRAGMENT_SCHEMA.createRecord(key);
		record.setString(TreeManager.FRAGMENT_NAME_COL, name);
		fragmentTable.putRecord(record);

		Record pcRec = TreeManager.PARENT_CHILD_SCHEMA.createRecord(parentChildTable.getKey());
		pcRec.setLongValue(TreeManager.PARENT_ID_COL, parentModuleID);
		// negative value to indicate fragment
		pcRec.setLongValue(TreeManager.CHILD_ID_COL, -key);
		parentChildTable.putRecord(pcRec);

		return record;

	}

	/**
	 * @see ghidra.program.database.module.GroupDBAdapter#getFragmentRecord(long)
	 */
	public Record getFragmentRecord(long key) throws IOException {
		return fragmentTable.getRecord(key);
	}

	/**
	 * @see ghidra.program.database.module.GroupDBAdapter#getModuleRecord(long)
	 */
	public Record getModuleRecord(long key) throws IOException {
		return moduleTable.getRecord(key);
	}

	/**
	 * @see ghidra.program.database.module.GroupDBAdapter#getParentChildRecord(long, long)
	 * @param childID negative value if child is a fragment
	 */
	public Record getParentChildRecord(long parentID, long childID) throws IOException {
		long[] keys =
			parentChildTable.findRecords(new LongField(parentID), TreeManager.PARENT_ID_COL);
		for (int i = 0; i < keys.length; i++) {
			Record pcRec = parentChildTable.getRecord(keys[i]);
			if (pcRec.getLongValue(TreeManager.CHILD_ID_COL) == childID) {
				return pcRec;
			}
		}
		return null;
	}

	/**
	 * @see ghidra.program.database.module.GroupDBAdapter#addParentChildRecord(long, long)
	 */
	public Record addParentChildRecord(long moduleID, long childID) throws IOException {

		Record pcRec = TreeManager.PARENT_CHILD_SCHEMA.createRecord(parentChildTable.getKey());
		pcRec.setLongValue(TreeManager.PARENT_ID_COL, moduleID);
		pcRec.setLongValue(TreeManager.CHILD_ID_COL, childID);
		parentChildTable.putRecord(pcRec);
		return pcRec;
	}

	/**
	 * @see ghidra.program.database.module.GroupDBAdapter#removeParentChildRecord(long)
	 */
	public boolean removeParentChildRecord(long key) throws IOException {
		return parentChildTable.deleteRecord(key);
	}

	/**
	 * @see ghidra.program.database.module.GroupDBAdapter#getParentChildRecords(long)
	 */
	public long[] getParentChildKeys(long parentID, int indexedCol) throws IOException {
		return parentChildTable.findRecords(new LongField(parentID), indexedCol);
	}

	/**
	 * @see ghidra.program.database.module.GroupDBAdapter#getFragmentRecord(java.lang.String)
	 */
	public Record getFragmentRecord(String name) throws IOException {
		long[] keys =
			fragmentTable.findRecords(new StringField(name), TreeManager.FRAGMENT_NAME_COL);
		if (keys.length == 0) {
			return null;
		}
		if (keys.length > 1) {
			throw new AssertException("Found " + keys.length + " fragments named " + name);
		}
		return fragmentTable.getRecord(keys[0]);
	}

	/**
	 * @see ghidra.program.database.module.GroupDBAdapter#getModuleRecord(java.lang.String)
	 */
	public Record getModuleRecord(String name) throws IOException {
		long[] keys = moduleTable.findRecords(new StringField(name), TreeManager.MODULE_NAME_COL);
		if (keys.length == 0) {
			return null;
		}
		if (keys.length > 1) {
			throw new AssertException("Found " + keys.length + " modules named " + name);
		}
		return moduleTable.getRecord(keys[0]);
	}

	/**
	 * @see ghidra.program.database.module.GroupDBAdapter#getParentChildRecord(long)
	 */
	public Record getParentChildRecord(long key) throws IOException {
		return parentChildTable.getRecord(key);
	}

	/**
	 * @see ghidra.program.database.module.GroupDBAdapter#updateRecord(ghidra.framework.store.db.Record)
	 */
	public void updateModuleRecord(Record record) throws IOException {
		moduleTable.putRecord(record);
	}

	/**
	 * @see ghidra.program.database.module.GroupDBAdapter#updateFragmentRecord(ghidra.framework.store.db.Record)
	 */
	public void updateFragmentRecord(Record record) throws IOException {
		fragmentTable.putRecord(record);
	}

	/**
	 * @see ghidra.program.database.module.GroupDBAdapter#updateParentChildRecord(ghidra.framework.store.db.Record)
	 */
	public void updateParentChildRecord(Record record) throws IOException {
		parentChildTable.putRecord(record);
	}

	/**
	 * @see ghidra.program.database.module.GroupDBAdapter#createRootModule()
	 */
	public Record createRootModule(String name) throws IOException {
		Record record = TreeManager.MODULE_SCHEMA.createRecord(0);
		record.setString(TreeManager.MODULE_NAME_COL, name);
		moduleTable.putRecord(record);
		return record;
	}

	/**
	 * @see ghidra.program.database.module.GroupDBAdapter#removeFragmentRecord(long)
	 */
	public boolean removeFragmentRecord(long childID) throws IOException {
		return fragmentTable.deleteRecord(childID);
	}

	/**
	 * @see ghidra.program.database.module.GroupDBAdapter#removeModuleRecord(long)
	 */
	public boolean removeModuleRecord(long childID) throws IOException {
		return moduleTable.deleteRecord(childID);
	}

	private void testVersion(Table table, int expectedVersion, String name) throws VersionException {

		if (table == null) {
			throw new VersionException(name + " not found");
		}
		int versionNumber = table.getSchema().getVersion();
		if (versionNumber != expectedVersion) {
			throw new VersionException(name + ": Expected Version " + expectedVersion + ", got " +
				versionNumber);
		}
	}

}
