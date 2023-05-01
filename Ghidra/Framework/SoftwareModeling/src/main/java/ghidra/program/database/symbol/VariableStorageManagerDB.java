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
import db.util.ErrorHandler;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.ProgramArchitecture;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.LanguageTranslator;
import ghidra.util.Lock;
import ghidra.util.Msg;
import ghidra.util.datastruct.WeakValueHashMap;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class VariableStorageManagerDB implements VariableStorageManager {

	private ProgramArchitecture arch;
	private Lock lock;
	private ErrorHandler errorHandler;

	private VariableStorageDBAdapter adapter;

	private DBObjectCache<MyVariableStorage> cache = new DBObjectCache<>(256);
	private WeakValueHashMap<Long, MyVariableStorage> cacheMap =
		new WeakValueHashMap<Long, MyVariableStorage>(256);

	/**
	 * Construct a new variable manager.
	 * @param handle the database handle.
	 * @param addrMap the address map (required for legacy adpter use only)
	 * @param openMode the open mode
	 * @param errorHandler database error handler
	 * @param lock the program synchronization lock
	 * @param monitor the task monitor.
	 * @throws IOException if a database error occurs.
	 * @throws VersionException if the table version is different from this adapter.
	 * @throws IOException if an IO error occurs
	 * @throws CancelledException if the user cancels the upgrade.
	 */
	public VariableStorageManagerDB(DBHandle handle, AddressMap addrMap, int openMode,
			ErrorHandler errorHandler, Lock lock, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {
		this.errorHandler = errorHandler;
		this.lock = lock;
		adapter = VariableStorageDBAdapter.getAdapter(handle, openMode, addrMap, monitor);
	}

	/**
	 * Set program architecture.
	 * @param arch program architecture
	 */
	public void setProgramArchitecture(ProgramArchitecture arch) {
		this.arch = arch;
	}

	/**
	 * Delete the DB table which correspnds to this variable storage implementation
	 * @param dbHandle database handle
	 * @throws IOException if an IO error occurs
	 */
	public static void delete(DBHandle dbHandle) throws IOException {
		dbHandle.deleteTable(VariableStorageDBAdapter.VARIABLE_STORAGE_TABLE_NAME);
	}

	/**
	 * Determine if the variable storage manager table already exists
	 * @param dbHandle database handle
	 * @return true if storage table exists
	 */
	public static boolean exists(DBHandle dbHandle) {
		return dbHandle.getTable(VariableStorageDBAdapter.VARIABLE_STORAGE_TABLE_NAME) != null;
	}

	void invalidateCache(boolean all) {
		cache.invalidate();
		cacheMap.clear();
	}

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

	/**
	 * Get the list of varnodes associated with the specified variable storage address.
	 * NOTE: The program architecture and error handler must be set appropriately prior to 
	 * invocation of this method (see {@link #setProgramArchitecture(ProgramArchitecture)}.
	 * @param variableAddr variable storage address
	 * @return storage varnode list or null if address unknown
	 * @throws IOException if a database IO error occurs
	 */
	List<Varnode> getStorageVarnodes(Address variableAddr) throws IOException {
		if (!variableAddr.isVariableAddress()) {
			throw new IllegalArgumentException();
		}
		DBRecord rec = adapter.getRecord(variableAddr.getOffset());
		if (rec == null) {
			return null;
		}
		try {
			return VariableStorage.getVarnodes(arch.getAddressFactory(),
				rec.getString(VariableStorageDBAdapter.STORAGE_COL));
		}
		catch (InvalidInputException e) {
			Msg.error(this, "Invalid variable storage: " + e.getMessage());
		}
		return null;
	}

	/**
	 * Get the variable storage object associated with the specified variable storage address.
	 * NOTE: The program architecture and error handler must be set appropriately prior to 
	 * invocation of this method (see {@link #setProgramArchitecture(ProgramArchitecture)}.
	 * @param variableAddr variable storage address
	 * @return variable storage object or null if address unknown
	 * @throws IOException if a database IO error occurs
	 */
	VariableStorage getVariableStorage(Address variableAddr) throws IOException {
		MyVariableStorage myStorage = getMyVariableStorage(variableAddr);
		if (myStorage != null) {
			return myStorage.getVariableStorage();
		}
		return null;
	}

	/**
	 * Get a variable address for the given storage specification.
	 * NOTE: The program architecture and error handler must be set appropriately prior to 
	 * invocation of this method (see {@link #setProgramArchitecture(ProgramArchitecture)}.
	 * @param storage variable storage specification
	 * @param create if true a new variable address will be allocated if needed
	 * @return variable address which corresponds to the storage specification or null if not found
	 * and create is false.
	 * @throws IOException if an IO error occurs
	 */
	@Override
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
				storage = VariableStorage.deserialize(arch,
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
						storage = VariableStorage.deserialize(arch,
							record.getString(VariableStorageDBAdapter.STORAGE_COL));
					}
					catch (InvalidInputException e) {
						// treat as bad storage
					}
					return true;
				}
			}
			catch (IOException e) {
				errorHandler.dbError(e);
			}
			finally {
				lock.release();
			}
			return false;
		}

	}

	/**
	 * Perform language translation.
	 * Following the invocation of this method it is important to ensure that the program 
	 * architecure is adjusted if neccessary.
	 * Update variable storage specifications to reflect address space and register mappings
	 * @param translator language translator to be used for mapping storage varnodes to new
	 * architecture.
	 * @param monitor task monitor
	 * @throws CancelledException if task is cancelled
	 */
	public void setLanguage(LanguageTranslator translator, TaskMonitor monitor)
			throws CancelledException {

		monitor.initialize(adapter.getRecordCount());
		int cnt = 0;

		lock.acquire();
		try {
			RecordIterator recIter = adapter.getRecords();
			while (recIter.hasNext()) {
				monitor.checkCancelled();

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
			errorHandler.dbError(e);
		}
		finally {
			invalidateCache(true);
			lock.release();
		}
	}
}
