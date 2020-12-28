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
package ghidra.program.database.symbol;

import java.io.IOException;

import db.*;
import ghidra.program.database.map.AddressMap;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

abstract class VariableStorageDBAdapter {

	static final String VARIABLE_STORAGE_TABLE_NAME = "Variable Storage";

	static final Schema VARIABLE_STORAGE_SCHEMA =
		new Schema(2, "Key", new Field[] { LongField.INSTANCE, StringField.INSTANCE },
			new String[] { "Hash", "Storage" });

	static final int HASH_COL = 0;
	static final int STORAGE_COL = 1;

	/**
	 * Gets a new VariableDatabaseAdapter
	 * @param dbHandle the database handle.
	 * @param openMode the openmode
	 * @param addrMap the address map
	 * @param monitor the progress monitor.
	 * @throws VersionException if the database table does not match the adapter.
	 * @throws CancelledException if the user cancels an upgrade.
	 * @throws IOException if a database io error occurs.
	 */
	static VariableStorageDBAdapter getAdapter(DBHandle dbHandle, int openMode, AddressMap addrMap,
			TaskMonitor monitor) throws VersionException, IOException, CancelledException {

		if (openMode == DBConstants.CREATE) {
			return new VariableStorageDBAdapterV2(dbHandle, true);
		}

		try {
			VariableStorageDBAdapter adapter = new VariableStorageDBAdapterV2(dbHandle, false);
			return adapter;
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			VariableStorageDBAdapter adapter = findReadOnlyAdapter(dbHandle, addrMap, openMode);
			if (openMode == DBConstants.UPGRADE) {
				adapter = VariableStorageDBAdapterV2.upgrade(dbHandle, adapter, monitor);
			}
			return adapter;
		}
	}

	private static VariableStorageDBAdapter findReadOnlyAdapter(DBHandle dbHandle,
			AddressMap addrMap, int openMode) {
		Table table = dbHandle.getTable(VARIABLE_STORAGE_TABLE_NAME);
		if (table == null) {
			return new VariableStorageDBAdapterNoTable();
		}
		throw new AssertException("Variable storage table is from newer version");
	}

	abstract void updateRecord(DBRecord record) throws IOException;

	abstract DBRecord getRecord(long key) throws IOException;

	/**
	 * Locate the record key which corresponds to the specified hash value.
	 * @param hash
	 * @return record key or -1 if not found
	 * @throws IOException
	 */
	abstract long findRecordKey(long hash) throws IOException;

	abstract long getNextStorageID();

	abstract void deleteRecord(long key) throws IOException;

	abstract RecordIterator getRecords() throws IOException;

	abstract int getRecordCount();

}
