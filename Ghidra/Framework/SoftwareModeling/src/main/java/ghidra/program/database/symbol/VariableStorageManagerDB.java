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
import java.util.List;

import db.*;
import ghidra.program.database.*;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.LanguageTranslator;
import ghidra.util.Lock;
import ghidra.util.Msg;
import ghidra.util.datastruct.WeakValueHashMap;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class VariableStorageManagerDB {

	private ProgramDB program;
	private AddressMap addrMap;
	private Lock lock;

	private VariableStorageDBAdapter adapter;

	private DBObjectCache<MyVariableStorage> cache = new DBObjectCache<>(256);
	private WeakValueHashMap<Long, MyVariableStorage> cacheMap =
		new WeakValueHashMap<Long, MyVariableStorage>(256);

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
	public VariableStorageManagerDB(DBHandle handle, AddressMap addrMap, int openMode, Lock lock,
			TaskMonitor monitor) throws VersionException, IOException, CancelledException {

		this.addrMap = addrMap;
		this.lock = lock;

		adapter = VariableStorageDBAdapter.getAdapter(handle, openMode, addrMap, monitor);
	}

	void invalidateCache(boolean all) {
		cache.invalidate();
		cacheMap.clear();
	}

	void setProgram(ProgramDB program) {
		this.program = program;
	}

//	private void cacheNamespaceStorage(long namespaceID) throws IOException {
//		variableAddrLookupCache.clear();
//		storageLookupCache.clear();
//		lastNamespaceCacheID = namespaceID;
//		Record[] records = adapter.getRecordsForNamespace(namespaceID);
//		for (Record rec : records) {
//			MyVariableStorage varStore = new MyVariableStorage(rec);
//			variableAddrLookupCache.put(varStore.getVariableAddress(), varStore);
//			storageLookupCache.put(varStore.getVariableStorage(), varStore);
//		}
//	}

	private MyVariableStorage getMyVariableStorage(Address variableAddr) throws IOException {
		if (!variableAddr.isVariableAddress()) {
			throw new IllegalArgumentException("Address is not a VariableAddress: " + variableAddr);
		}
		MyVariableStorage varStore = cache.get(variableAddr.getOffset());
		if (varStore != null) {
			return varStore;
		}
		DBRecord rec = adapter.getRecord(variableAddr.getOffset());
		if (rec == null) {
			return null;
		}
		varStore = new MyVariableStorage(cache, rec);
		cacheMap.put(varStore.getLongHash(), varStore);
		return varStore;
	}

	List<Varnode> getStorageVarnodes(Address variableAddr) throws IOException {
		if (!variableAddr.isVariableAddress()) {
			throw new IllegalArgumentException();
		}
		DBRecord rec = adapter.getRecord(variableAddr.getOffset());
		if (rec == null) {
			return null;
		}
		try {
			return VariableStorage.getVarnodes(program.getAddressFactory(),
				rec.getString(VariableStorageDBAdapter.STORAGE_COL));
		}
		catch (InvalidInputException e) {
			Msg.error(this, "Invalid variable storage: " + e.getMessage());
		}
		return null;
	}

	VariableStorage getVariableStorage(Address variableAddr) throws IOException {
		MyVariableStorage myStorage = getMyVariableStorage(variableAddr);
		if (myStorage != null) {
			return myStorage.getVariableStorage();
		}
		return null;
	}

	public Address getVariableStorageAddress(VariableStorage storage, boolean create)
			throws IOException {
		long hash = storage.getLongHash();
		MyVariableStorage myStorage = cacheMap.get(hash);
		long key;
		if (myStorage != null) {
			key = myStorage.getKey();
			// verify that cache entry is still valid
			if (cache.get(key) == null) {
				key = -1;
			}
		}
		else {
			key = adapter.findRecordKey(hash);
		}

		if (key == -1) {
			if (!create) {
				return null;
			}

			// create new storage record
			key = adapter.getNextStorageID();
			DBRecord rec = VariableStorageDBAdapter.VARIABLE_STORAGE_SCHEMA.createRecord(key);
			rec.setLongValue(VariableStorageDBAdapter.HASH_COL, storage.getLongHash());
			rec.setString(VariableStorageDBAdapter.STORAGE_COL, storage.getSerializationString());
			adapter.updateRecord(rec);

			// add to cache
			myStorage = new MyVariableStorage(cache, rec);
			cacheMap.put(hash, myStorage);
		}
		return AddressSpace.VARIABLE_SPACE.getAddress(key);
	}

//	void deleteVariableStorage(Address variableAddr) throws IOException {
//		cache.removeObj(variableAddr.getOffset());
//		adapter.deleteRecord(variableAddr.getOffset());
//	}
//
//	void setVariableStorage(Address variableAddr, VariableStorage storage) throws IOException {
//		if (storage == null || storage.isUnassignedStorage()) {
//			deleteVariableStorage(variableAddr);
//			return;
//		}
//		cache.invalidate(variableAddr.getOffset());
//		Record rec = adapter.getRecord(variableAddr.getOffset());
//		if (rec == null) {
//			rec =
//				VariableStorageDBAdapter.VARIABLE_STORAGE_SCHEMA.createRecord(variableAddr.getOffset());
//		}
//		rec.setString(VariableStorageDBAdapter.STORAGE_COL, storage.getSerializationString());
//		adapter.updateRecord(rec);
//	}
//
//	/**
//	 * Set variable storage based upon unrestricted varnodes (useful for upgrades)
//	 * @param variableAddr
//	 * @param varnodes
//	 * @throws IOException
//	 */
//	void setVariableStorage(Address variableAddr, Varnode... varnodes) throws IOException {
//		if (varnodes == null || varnodes.length == 0) {
//			deleteVariableStorage(variableAddr);
//			return;
//		}
//		cache.invalidate(variableAddr.getOffset());
//		Record rec = adapter.getRecord(variableAddr.getOffset());
//		if (rec == null) {
//			rec =
//				VariableStorageDBAdapter.VARIABLE_STORAGE_SCHEMA.createRecord(variableAddr.getOffset());
//		}
//		rec.setString(VariableStorageDBAdapter.STORAGE_COL,
//			VariableStorage.getSerializationString(varnodes));
//		adapter.updateRecord(rec);
//	}

	private class MyVariableStorage extends DatabaseObject {

		private VariableStorage storage;
		private DBRecord record;

		private MyVariableStorage(DBObjectCache<MyVariableStorage> cache, DBRecord record) {
			super(cache, record.getKey());
			this.record = record;
			try {
				storage = VariableStorage.deserialize(program,
					record.getString(VariableStorageDBAdapter.STORAGE_COL));
			}
			catch (InvalidInputException e) {
				storage = VariableStorage.BAD_STORAGE;
			}
		}

		VariableStorage getVariableStorage() {
			lock.acquire();
			try {
				checkIsValid();
				return storage;
			}
			finally {
				lock.release();
			}
		}

		long getLongHash() {
			return storage.getLongHash();
		}

		@Override
		protected boolean refresh() {
			lock.acquire();
			try {
				storage = VariableStorage.BAD_STORAGE;
				if (record != null) {
					DBRecord rec = adapter.getRecord(key);
					if (rec == null) {
						return false;
					}
					record = rec;
					try {
						storage = VariableStorage.deserialize(program,
							record.getString(VariableStorageDBAdapter.STORAGE_COL));
					}
					catch (InvalidInputException e) {
						// treat as bad storage
					}
					return true;
				}
			}
			catch (IOException e) {
				program.dbError(e);
			}
			finally {
				lock.release();
			}
			return false;
		}

	}

	/**
	 * Perform language translation.
	 * Update variable storage specifications to reflect address space and register mappings
	 * @param translator
	 * @param monitor
	 * @throws CancelledException 
	 */
	public void setLanguage(LanguageTranslator translator, TaskMonitor monitor)
			throws CancelledException {

		monitor.initialize(adapter.getRecordCount());
		int cnt = 0;

		lock.acquire();
		try {
			RecordIterator recIter = adapter.getRecords();
			while (recIter.hasNext()) {
				monitor.checkCanceled();

				DBRecord rec = recIter.next();
				// NOTE: addrMap has already been switched-over to new language and its address spaces
				String serialization = rec.getString(VariableStorageDBAdapter.STORAGE_COL);

				try {
					// Translate address spaces and registers
					serialization =
						VariableStorage.translateSerialization(translator, serialization);
					rec.setString(VariableStorageDBAdapter.STORAGE_COL, serialization);
					adapter.updateRecord(rec);
				}
				catch (InvalidInputException e) {
					// Failed to process - skip record
					continue;
				}
				monitor.setProgress(++cnt);
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			invalidateCache(true);
			lock.release();
		}
	}
}
