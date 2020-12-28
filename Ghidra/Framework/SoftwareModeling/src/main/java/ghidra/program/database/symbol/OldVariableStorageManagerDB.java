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
import java.util.Hashtable;

import db.DBHandle;
import db.DBRecord;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class OldVariableStorageManagerDB {

	private AddressMap addrMap;

	private OldVariableStorageDBAdapterV0V1 adapter;
	private DBHandle handle;

	private long lastNamespaceCacheID; // ID of cached namespace variables
	private Hashtable<Address, OldVariableStorage> variableAddrLookupCache =
		new Hashtable<Address, OldVariableStorage>();
	private Hashtable<Address, OldVariableStorage> storageAddrLookupCache =
		new Hashtable<Address, OldVariableStorage>();

	/**
	 * Construct a read-only variable storage manager for the old record format
	 * utilized by the VariableStorage table (NOTE: old table name does not have
	 * a space in the name).  This adapter is intended for use during upgrades
	 * only.
	 * @param handle the database handle.
	 * @param addrMap the address map
	 * @param monitor the task monitor.
	 * @throws IOException if a database error occurs.
	 * @throws CancelledException if the user cancels the upgrade.
	 */
	public OldVariableStorageManagerDB(DBHandle handle, AddressMap addrMap, TaskMonitor monitor)
			throws IOException, CancelledException {

		this.addrMap = addrMap;
		this.handle = handle;

		adapter = new OldVariableStorageDBAdapterV0V1(handle);
	}

	static boolean isOldVariableStorageManagerUpgradeRequired(DBHandle handle) {
		return handle.getTable(OldVariableStorageDBAdapterV0V1.VARIABLE_STORAGE_TABLE_NAME) != null;
	}

	void deleteTable() throws IOException {
		handle.deleteTable(OldVariableStorageDBAdapterV0V1.VARIABLE_STORAGE_TABLE_NAME);
	}

	private void cacheNamespaceStorage(long namespaceID) throws IOException {
		variableAddrLookupCache.clear();
		storageAddrLookupCache.clear();
		lastNamespaceCacheID = namespaceID;
		DBRecord[] records = adapter.getRecordsForNamespace(namespaceID);
		for (DBRecord rec : records) {
			OldVariableStorage varStore = new OldVariableStorage(rec);
			variableAddrLookupCache.put(varStore.variableAddr, varStore);
			storageAddrLookupCache.put(varStore.storageAddr, varStore);
		}
	}

	private OldVariableStorage getVariableStorage(Address variableAddr) throws IOException {
		if (!variableAddr.isVariableAddress()) {
			throw new IllegalArgumentException();
		}
		if (lastNamespaceCacheID != -1) {
			OldVariableStorage varStore = variableAddrLookupCache.get(variableAddr);
			if (varStore != null) {
				return varStore;
			}
		}
		DBRecord rec = adapter.getRecord(variableAddr.getOffset());
		if (rec == null) {
			return null;
		}
		cacheNamespaceStorage(rec.getLongValue(OldVariableStorageDBAdapterV0V1.NAMESPACE_ID_COL));
		return variableAddrLookupCache.get(variableAddr);
	}

	public Address getStorageAddress(Address variableAddr) throws IOException {
		OldVariableStorage varStore = getVariableStorage(variableAddr);
		return varStore != null ? varStore.storageAddr : null;
	}

	private class OldVariableStorage {
		private final Address variableAddr;
		private final Address storageAddr;

		private OldVariableStorage(DBRecord record) {
			this.variableAddr = AddressSpace.VARIABLE_SPACE.getAddress(record.getKey());
			this.storageAddr = addrMap.decodeAddress(
				record.getLongValue(OldVariableStorageDBAdapterV0V1.STORAGE_ADDR_COL));
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof OldVariableStorage)) {
				return false;
			}
			return variableAddr.getOffset() == ((OldVariableStorage) obj).variableAddr.getOffset();
		}

		@Override
		public int hashCode() {
			return (int) variableAddr.getOffset();
		}
	}

}
