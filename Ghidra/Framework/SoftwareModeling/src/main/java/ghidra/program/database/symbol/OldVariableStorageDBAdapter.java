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
package ghidra.program.database.symbol;

import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

import db.*;

abstract class OldVariableStorageDBAdapter {

	static final String VARIABLE_STORAGE_TABLE_NAME = "VariableStorage";

	static final Schema VARIABLE_STORAGE_SCHEMA = new Schema(1, "Key", new Class[] {
		LongField.class, LongField.class, IntField.class }, new String[] { "Address",
		"NamespaceID", "SymCount" });

	static final int STORAGE_ADDR_COL = 0;
	static final int NAMESPACE_ID_COL = 1;
	static final int SYMBOL_COUNT_COL = 2;

	boolean upgradeOldVariableAddressesRequired = false; // if true, must upgrade register and stack symbol addresses

	/**
	 * Gets a new VariableDatabaseAdapter
	 * @param dbHandle the database handle.
	 * @param openMode the openmode
	 * @param monitor the progress monitor.
	 * @throws VersionException if the database table does not match the adapter.
	 * @throws CancelledException if the user cancels an upgrade.
	 * @throws IOException if a database io error occurs.
	 */
	static OldVariableStorageDBAdapter getAdapter(DBHandle dbHandle, int openMode,
			TaskMonitor monitor) throws VersionException, IOException, CancelledException {

		if (openMode == DBConstants.CREATE) {
			return new OldVariableStorageDBAdapterV1(dbHandle, true);
		}

		try {
			OldVariableStorageDBAdapter adapter =
				new OldVariableStorageDBAdapterV1(dbHandle, false);
			return adapter;
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			OldVariableStorageDBAdapter adapter = findReadOnlyAdapter(dbHandle);
			if (openMode == DBConstants.UPGRADE) {
				if (adapter == null) {
					adapter = new OldVariableStorageDBAdapterV1(dbHandle, true);
					adapter.upgradeOldVariableAddressesRequired = true;
				}
				else {
					adapter = OldVariableStorageDBAdapterV1.upgrade(dbHandle, adapter, monitor);
				}
			}
			else if (adapter == null) {
				throw e; // upgrade required - read-only mode not supported
			}
			return adapter;
		}
	}

	static void deleteTable(DBHandle dbHandle) throws IOException {
		dbHandle.deleteTable(VARIABLE_STORAGE_TABLE_NAME);
	}

	private static OldVariableStorageDBAdapter findReadOnlyAdapter(DBHandle dbHandle)
			throws VersionException {
		if (dbHandle.getTable(VARIABLE_STORAGE_TABLE_NAME) == null) {
			return null;
		}
		return new OldVariableStorageDBAdapterV0(dbHandle);
	}

	abstract void updateRecord(Record record) throws IOException;

	abstract Record getRecord(long key) throws IOException;

	abstract Record[] getRecordsForNamespace(long longValue) throws IOException;

	abstract long getNextStorageID();

	abstract void deleteRecord(long key) throws IOException;

	abstract RecordIterator getRecords() throws IOException;

	abstract int getRecordCount();

}
