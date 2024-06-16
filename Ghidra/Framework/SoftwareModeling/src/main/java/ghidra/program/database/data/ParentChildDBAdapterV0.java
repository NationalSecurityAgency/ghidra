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
import java.util.HashSet;
import java.util.Set;

import db.*;
import ghidra.util.exception.VersionException;

/**
 * Version 0 implementation for accessing the datatype parent/child database table. 
 * 
 * NOTE: Use of tablePrefix introduced with this adapter version.
 */
class ParentChildDBAdapterV0 extends ParentChildAdapter {

	private static final int VERSION = 0;

	private static final int PARENT_COL = 0;
	private static final int CHILD_COL = 1;
	static final Schema V0_SCHEMA =
		new Schema(0, "KEY", new Field[] { LongField.INSTANCE, LongField.INSTANCE },
			new String[] { "Parent ID", "Child ID" });

	private Table table;
	private boolean needsInitializing = false;

	/**
	 * Gets a version 1 adapter for the datatype parent/child database table.
	 * @param handle handle to the database containing the table.
	 * @param tablePrefix prefix to be used with default table name
	 * @param create true if this constructor should create the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if an IO error occurs
	 */
	ParentChildDBAdapterV0(DBHandle handle, String tablePrefix, boolean create)
			throws VersionException, IOException {
		String tableName = tablePrefix + PARENT_CHILD_TABLE_NAME;
		if (create) {
			table = handle.createTable(tableName, V0_SCHEMA, new int[] { PARENT_COL, CHILD_COL });
		}
		else {
			table = handle.getTable(tableName);
			if (table == null) {
				throw new VersionException(true);
			}
			if (table.getSchema().getVersion() != VERSION) {
				throw new VersionException(false);
			}
		}
	}

	@Override
	public void createRecord(long parentID, long childID) throws IOException {
		long key = table.getKey();
		DBRecord record = V0_SCHEMA.createRecord(key);
		record.setLongValue(PARENT_COL, parentID);
		record.setLongValue(CHILD_COL, childID);
		table.putRecord(record);
	}

	@Override
	void removeRecord(long parentID, long childID) throws IOException {

		Field[] ids = table.findRecords(new LongField(childID), CHILD_COL);
		for (Field id : ids) {
			DBRecord rec = table.getRecord(id);
			if (rec.getLongValue(PARENT_COL) == parentID) {
				table.deleteRecord(id);
				return;
			}
		}
	}

	@Override
	Set<Long> getParentIds(long childID) throws IOException {
		Field[] ids = table.findRecords(new LongField(childID), CHILD_COL);
		Set<Long> parentIds = new HashSet<>(ids.length);
		for (int i = 0; i < ids.length; i++) {
			DBRecord rec = table.getRecord(ids[i]);
			parentIds.add(rec.getLongValue(PARENT_COL));
		}
		return parentIds;
	}

	public void setNeedsInitializing() {
		needsInitializing = true;
	}

	@Override
	boolean needsInitializing() {
		return needsInitializing;
	}

	@Override
	void removeAllRecordsForParent(long parentID) throws IOException {
		Field[] ids = table.findRecords(new LongField(parentID), PARENT_COL);
		for (Field id : ids) {
			table.deleteRecord(id);
		}
	}

	@Override
	void removeAllRecordsForChild(long childID) throws IOException {
		Field[] ids = table.findRecords(new LongField(childID), CHILD_COL);
		for (Field id : ids) {
			table.deleteRecord(id);
		}
	}
}
