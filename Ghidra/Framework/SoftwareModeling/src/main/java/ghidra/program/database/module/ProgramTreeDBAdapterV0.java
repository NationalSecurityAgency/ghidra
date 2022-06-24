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

public class ProgramTreeDBAdapterV0 extends ProgramTreeDBAdapter {

	static final int V0_VERSION = 0;

	static final int V0_TREE_NAME_COL = 0;
	static final int V0_MODIFICATION_NUM_COL = 1;

	static final Schema V0_PROGRAM_TREE_SCHEMA =
		new Schema(V0_VERSION, "Key", new Field[] { StringField.INSTANCE, LongField.INSTANCE },
			new String[] { "Name", "Modification Number" });

	private Table programTreeTable;

	/**
	 * Gets a version 0 adapter for the program tree database table.
	 * @param handle handle to the database containing the table.
	 * @param create true if this constructor should create the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if database IO error occurs
	 */
	public ProgramTreeDBAdapterV0(DBHandle handle, boolean create)
			throws VersionException, IOException {

		if (create) {
			programTreeTable = handle.createTable(PROGRAM_TREE_TABLE_NAME, V0_PROGRAM_TREE_SCHEMA,
				new int[] { V0_TREE_NAME_COL });
		}
		else {
			programTreeTable = handle.getTable(PROGRAM_TREE_TABLE_NAME);
			if (programTreeTable == null) {
				throw new VersionException("Missing Table: " + PROGRAM_TREE_TABLE_NAME);
			}
			int version = programTreeTable.getSchema().getVersion();
			if (version != V0_VERSION) {
				throw new VersionException(VersionException.NEWER_VERSION, false);
			}
		}
	}

	@Override
	DBRecord createRecord(String name) throws IOException {
		DBRecord record = V0_PROGRAM_TREE_SCHEMA.createRecord(programTreeTable.getKey());
		record.setString(V0_TREE_NAME_COL, name);
		record.setLongValue(V0_MODIFICATION_NUM_COL, 0);
		programTreeTable.putRecord(record);
		return record;
	}

	@Override
	boolean deleteRecord(long treeID) throws IOException {
		return programTreeTable.deleteRecord(treeID);
	}

	@Override
	DBRecord getRecord(long treeID) throws IOException {
		return programTreeTable.getRecord(treeID);
	}

	@Override
	DBRecord getRecord(String name) throws IOException {
		Field[] keys =
			programTreeTable.findRecords(new StringField(name), V0_TREE_NAME_COL);
		if (keys.length == 0) {
			return null;
		}
		if (keys.length > 1) {
			throw new AssertException("Found " + keys.length + " trees named " + name);
		}
		return programTreeTable.getRecord(keys[0]);
	}

	@Override
	RecordIterator getRecords() throws IOException {
		return programTreeTable.iterator();
	}

	@Override
	void updateRecord(DBRecord record) throws IOException {
		programTreeTable.putRecord(record);
	}

}
