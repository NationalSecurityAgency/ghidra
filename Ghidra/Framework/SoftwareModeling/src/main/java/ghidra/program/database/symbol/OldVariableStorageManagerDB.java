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

import ghidra.program.database.ManagerDB;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.util.LanguageTranslator;
import ghidra.util.Lock;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.Hashtable;

import db.*;

public class OldVariableStorageManagerDB implements ManagerDB {

	private ProgramDB program;
	private AddressMap addrMap;
	private Lock lock;

	private OldVariableStorageDBAdapter adapter;
	private DBHandle handle;

	private long lastNamespaceCacheID; // ID of cached namespace variables
	private Hashtable<Address, OldVariableStorage> variableAddrLookupCache =
		new Hashtable<Address, OldVariableStorage>();
	private Hashtable<Address, OldVariableStorage> storageAddrLookupCache =
		new Hashtable<Address, OldVariableStorage>();

	/**
	 * Construct a new variable manager.
	 * @param handle the database handle.
	 * @param addrMap the address map
	 * @param openMode the open mode
	 * @param lock the program synchronization lock
	 * @param monitor the task monitor.
	 * @throws IOException if a database error occurs.
	 * @throws VersionException if the table version is different from this adapter.
	 * @throws IOException 
	 * @throws CancelledException if the user cancels the upgrade.
	 */
	public OldVariableStorageManagerDB(DBHandle handle, AddressMap addrMap, int openMode,
			Lock lock, TaskMonitor monitor) throws VersionException, IOException,
			CancelledException {

		this.addrMap = addrMap;
		this.lock = lock;
		this.handle = handle;

		adapter = OldVariableStorageDBAdapter.getAdapter(handle, openMode, monitor);

	}

	public static boolean isOldVariableStorageManagerUpgradeRequired(DBHandle handle) {
		return handle.getTable(OldVariableStorageDBAdapter.VARIABLE_STORAGE_TABLE_NAME) != null;
	}

	@Override
	public void invalidateCache(boolean all) {
		lastNamespaceCacheID = -1;
		variableAddrLookupCache.clear();
		storageAddrLookupCache.clear();
	}

	@Override
	public void programReady(int openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
	}

	@Override
	public void setProgram(ProgramDB program) {
		this.program = program;
	}

	void deleteTable() throws IOException {
		handle.deleteTable(OldVariableStorageDBAdapter.VARIABLE_STORAGE_TABLE_NAME);
		invalidateCache(true);
	}

	private void cacheNamespaceStorage(long namespaceID) throws IOException {
		variableAddrLookupCache.clear();
		storageAddrLookupCache.clear();
		lastNamespaceCacheID = namespaceID;
		Record[] records = adapter.getRecordsForNamespace(namespaceID);
		for (Record rec : records) {
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
		Record rec = adapter.getRecord(variableAddr.getOffset());
		if (rec == null) {
			return null;
		}
		cacheNamespaceStorage(rec.getLongValue(OldVariableStorageDBAdapter.NAMESPACE_ID_COL));
		return variableAddrLookupCache.get(variableAddr);
	}

	public Address getStorageAddress(Address variableAddr) throws IOException {
		lock.acquire();
		try {
			OldVariableStorage varStore = getVariableStorage(variableAddr);
			if (varStore != null) {
				return varStore.storageAddr;
			}
		}
		finally {
			lock.release();
		}
		return null;
	}

	public boolean isUpgradeOldVariableAddressesRequired() {
		return adapter.upgradeOldVariableAddressesRequired;
	}

	@Override
	public void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException {
		throw new UnsupportedOperationException();
	}

	private class OldVariableStorage {
		private final Address variableAddr;
		private final Address storageAddr;

		private OldVariableStorage(Record record) {
			this.variableAddr = AddressSpace.VARIABLE_SPACE.getAddress(record.getKey());
			this.storageAddr =
				addrMap.decodeAddress(record.getLongValue(OldVariableStorageDBAdapter.STORAGE_ADDR_COL));
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

	/**
	 * Update storage locations to reflect register changes resulting from
	 * a new/updated language.  Programs address map must already be updated
	 * to reflect new language.
	 * @param translator
	 * @param monitor
	 * @throws CancelledException 
	 * @throws IOException 
	 */
	public void setLanguage(LanguageTranslator translator, TaskMonitor monitor)
			throws CancelledException, IOException {

		monitor.initialize(adapter.getRecordCount());
		int cnt = 0;

		lock.acquire();
		try {
			RecordIterator recIter = adapter.getRecords();
			while (recIter.hasNext()) {
				monitor.checkCanceled();
				Record rec = recIter.next();
				// NOTE: addrMap has already been switched-over to new language and its address spaces
				Address storageAddr =
					addrMap.decodeAddress(rec.getLongValue(OldVariableStorageDBAdapter.STORAGE_ADDR_COL));
				Register oldReg = translator.getOldRegister(storageAddr, 0);
				if (oldReg != null) {
					Register newReg = translator.getNewRegister(oldReg);
					if (newReg != null) {
						rec.setLongValue(OldVariableStorageDBAdapter.STORAGE_ADDR_COL,
							addrMap.getKey(newReg.getAddress(), true));
						adapter.updateRecord(rec);
					}
				}
				monitor.setProgress(++cnt);
			}
		}
		finally {
			invalidateCache(true);
			lock.release();
		}
	}

}
