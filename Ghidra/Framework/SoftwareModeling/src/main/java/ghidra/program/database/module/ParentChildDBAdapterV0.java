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
import ghidra.util.exception.VersionException;

public class ParentChildDBAdapterV0 extends ParentChildDBAdapter {

	static final int V0_VERSION = 0;

	static final int V0_PARENT_ID_COL = 0;
	static final int V0_CHILD_ID_COL = 1;
	static final int V0_ORDER_COL = 2;

	static final Schema V0_PARENT_CHILD_SCHEMA = new Schema(V0_VERSION, "Key",
		new Field[] { LongField.INSTANCE, LongField.INSTANCE, IntField.INSTANCE },
		new String[] { "Parent ID", "Child ID", "Child Index" });

	private Table parentChildTable;

	/**
	 * Gets a version 0 adapter for the program tree parent/child database table.
	 * @param handle handle to the database containing the table.
	 * @param create true if this constructor should create the table.
	 * @param treeID associated program tree ID
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if database IO error occurs
	 */
	public ParentChildDBAdapterV0(DBHandle handle, boolean create, long treeID)
			throws VersionException, IOException {

		String tableName = getTableName(treeID);

		if (create) {
			parentChildTable = handle.createTable(tableName, V0_PARENT_CHILD_SCHEMA,
				new int[] { V0_PARENT_ID_COL, V0_CHILD_ID_COL });
		}
		else {
			parentChildTable = handle.getTable(tableName);
			if (parentChildTable == null) {
				throw new VersionException("Missing Table: " + tableName);
			}
			int version = parentChildTable.getSchema().getVersion();
			if (version != V0_VERSION) {
				throw new VersionException(VersionException.NEWER_VERSION, false);
			}
		}
	}

	@Override
	public DBRecord addParentChildRecord(long moduleID, long childID) throws IOException {
		DBRecord pcRec = V0_PARENT_CHILD_SCHEMA.createRecord(parentChildTable.getKey());
		pcRec.setLongValue(V0_PARENT_ID_COL, moduleID);
		pcRec.setLongValue(V0_CHILD_ID_COL, childID); // negative value to indicate fragment
		parentChildTable.putRecord(pcRec);
		return pcRec;
	}

	@Override
	DBRecord getParentChildRecord(long parentID, long childID) throws IOException {
		Field[] keys =
			parentChildTable.findRecords(new LongField(childID), V0_CHILD_ID_COL);
		for (int i = 0; i < keys.length; i++) {
			DBRecord pcRec = parentChildTable.getRecord(keys[i]);
			if (pcRec.getLongValue(V0_PARENT_ID_COL) == parentID) {
				return pcRec;
			}
		}
		return null;
	}

	@Override
	boolean removeParentChildRecord(long key) throws IOException {
		return parentChildTable.deleteRecord(key);
	}

	@Override
	DBRecord getParentChildRecord(long key) throws IOException {
		return parentChildTable.getRecord(key);
	}

	@Override
	void updateParentChildRecord(DBRecord record) throws IOException {
		parentChildTable.putRecord(record);
	}

	@Override
	Field[] getParentChildKeys(long parentID, int indexedCol) throws IOException {
		return parentChildTable.findRecords(new LongField(parentID), indexedCol);
	}

}
