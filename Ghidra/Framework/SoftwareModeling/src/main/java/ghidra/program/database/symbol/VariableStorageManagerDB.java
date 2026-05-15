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
import db.util.ErrorHandler;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.*;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.ProgramArchitecture;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.util.LanguageTranslator;
import ghidra.util.Lock;
import ghidra.util.Lock.Closeable;
import ghidra.util.datastruct.WeakValueHashMap;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class VariableStorageManagerDB implements VariableStorageManager {

	private ProgramArchitecture arch;
	private Lock lock;
	private ErrorHandler errorHandler;

	private VariableStorageDBAdapter adapter;

	private DbCache<MyVariableStorage> cache;
	private ByHashCache byHashCache = new ByHashCache();

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
	public VariableStorageManagerDB(DBHandle handle, AddressMap addrMap, OpenMode openMode,
			ErrorHandler errorHandler, Lock lock, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {
		this.errorHandler = errorHandler;
		this.lock = lock;
		adapter = VariableStorageDBAdapter.getAdapter(handle, openMode, addrMap, monitor);
		cache = new DbCache<MyVariableStorage>(new VariableStorageFactory(), lock, 256);
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
		byHashCache.clear();
	}

	private MyVariableStorage getMyVariableStorage(Address variableAddr) {
		if (!variableAddr.isVariableAddress()) {
			throw new IllegalArgumentException("Address is not a VariableAddress: " + variableAddr);
		}
		return cache.getCachedInstance(variableAddr.getOffset());
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

		long key = getExistingKey(storage);
		if (key == -1 && create) {
			// create new storage record
			key = adapter.getNextStorageID();
			DBRecord rec = VariableStorageDBAdapter.VARIABLE_STORAGE_SCHEMA.createRecord(key);
			rec.setLongValue(VariableStorageDBAdapter.HASH_COL, storage.getLongHash());
			rec.setString(VariableStorageDBAdapter.STORAGE_COL, storage.getSerializationString());
			adapter.updateRecord(rec);
			MyVariableStorage myStorage = new MyVariableStorage(rec);
			cache.add(myStorage);
			byHashCache.add(myStorage);
		}
		return key == -1 ? null : AddressSpace.VARIABLE_SPACE.getAddress(key);
	}

	private long getExistingKey(VariableStorage storage) throws IOException {
		long hash = storage.getLongHash();
		MyVariableStorage myStorage = byHashCache.get(hash);
		if (myStorage != null && myStorage.isValid()) {
			return myStorage.getKey();
		}
		return adapter.findRecordKey(hash);
	}

	private class VariableStorageFactory implements DbFactory<MyVariableStorage> {

		@Override
		public MyVariableStorage instantiate(long key) {
			DBRecord record;
			try {
				record = adapter.getRecord(key);
				return record == null ? null : instantiate(record);
			}
			catch (IOException e) {
				errorHandler.dbError(e);
				return null;
			}
		}

		@Override
		public MyVariableStorage instantiate(DBRecord record) {
			MyVariableStorage storage = new MyVariableStorage(record);
			byHashCache.add(storage);
			return storage;
		}
	}

	private class MyVariableStorage extends DbObject {

		private VariableStorage storage;
		private DBRecord record;

		private MyVariableStorage(DBRecord record) {
			super(record.getKey());
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
			try (Closeable c = lock.read()) {
				refreshIfNeeded();
				return storage;
			}
		}

		long getLongHash() {
			return storage.getLongHash();
		}

		@Override
		protected boolean refresh() {
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

		try (Closeable c = lock.write()) {
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
				invalidateCache(true);
			}
		}
		catch (IOException e) {
			errorHandler.dbError(e);
		}
	}

	/**
	 * Cache of MyVariableStorage by their long hash value
	 */
	private static class ByHashCache {
		private WeakValueHashMap<Long, MyVariableStorage> cacheMap =
			new WeakValueHashMap<Long, MyVariableStorage>();

		synchronized void add(MyVariableStorage storage) {
			cacheMap.put(storage.getLongHash(), storage);
		}

		synchronized void clear() {
			cacheMap.clear();
		}

		synchronized MyVariableStorage get(long hash) {
			return cacheMap.get(hash);
		}
	}

}
