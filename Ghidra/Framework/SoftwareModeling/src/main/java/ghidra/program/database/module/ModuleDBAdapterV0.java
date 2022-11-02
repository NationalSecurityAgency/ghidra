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

class ModuleDBAdapterV0 extends ModuleDBAdapter implements RecordTranslator {

	static final int V0_VERSION = 0;

	static final int V0_MODULE_NAME_COL = 0;
	static final int V0_MODULE_COMMENTS_COL = 1;

// V0 Schema - retain for documentation
//
//	static final Schema V0_MODULE_SCHEMA =
//		new Schema(V0_VERSION, "Key", new Field[] { StringField.INSTANCE, StringField.INSTANCE },
//			new String[] { "Name", "Comments" });

	private Table moduleTable;
	private ParentChildDBAdapter parentChildAdapter;

	/**
	 * Gets a version 0 adapter for the program tree module database table (read-only).
	 * @param handle handle to the database containing the table.
	 * @param treeID associated program tree ID
	 * @param parentChildAdapter parent/child database adapter
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if database IO error occurs
	 */
	public ModuleDBAdapterV0(DBHandle handle, long treeID, ParentChildDBAdapter parentChildAdapter)
			throws VersionException, IOException {

		this.parentChildAdapter = parentChildAdapter;

		String tableName = getTableName(treeID);
		moduleTable = handle.getTable(tableName);
		if (moduleTable == null) {
			throw new VersionException("Missing Table: " + tableName);
		}
		int version = moduleTable.getSchema().getVersion();
		if (version != V0_VERSION) {
			throw new VersionException(VersionException.NEWER_VERSION, false);
		}
	}

	@Override
	public DBRecord createModuleRecord(long parentModuleID, String name) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	DBRecord getModuleRecord(long key) throws IOException {
		return translateRecord(moduleTable.getRecord(key));
	}

	@Override
	DBRecord getModuleRecord(String name) throws IOException {
		Field[] keys = moduleTable.findRecords(new StringField(name), V0_MODULE_NAME_COL);
		if (keys.length == 0) {
			return null;
		}
		if (keys.length > 1) {
			throw new AssertException("Found " + keys.length + " modules named " + name);
		}
		return translateRecord(moduleTable.getRecord(keys[0]));
	}

	@Override
	RecordIterator getRecords() throws IOException {
		return new TranslatedRecordIterator(moduleTable.iterator(), this);
	}

	@Override
	void updateModuleRecord(DBRecord record) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	boolean removeModuleRecord(long childID) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public DBRecord translateRecord(DBRecord oldRec) throws IOException {
		if (oldRec == null) {
			return null;
		}
		DBRecord rec = ModuleDBAdapterV1.V1_MODULE_SCHEMA.createRecord(oldRec.getKey());

		rec.setString(MODULE_NAME_COL, oldRec.getString(V0_MODULE_NAME_COL));
		rec.setString(MODULE_COMMENTS_COL, oldRec.getString(V0_MODULE_COMMENTS_COL));

		// Count child associations for the module
		Field[] keys =
			parentChildAdapter.getParentChildKeys(rec.getKey(), ParentChildDBAdapter.PARENT_ID_COL);
		rec.setIntValue(MODULE_CHILD_COUNT_COL, keys.length);
		return rec;
	}
}
