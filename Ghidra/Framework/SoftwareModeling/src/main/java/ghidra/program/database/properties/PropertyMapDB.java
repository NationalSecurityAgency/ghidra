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
package ghidra.program.database.properties;

import java.io.IOException;
import java.util.NoSuchElementException;

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.map.*;
import ghidra.program.database.util.DatabaseTableUtils;
import ghidra.program.model.address.*;
import ghidra.program.model.util.PropertyMap;
import ghidra.program.util.ChangeManager;
import ghidra.program.util.ChangeManagerAdapter;
import ghidra.util.Lock;
import ghidra.util.datastruct.ObjectCache;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Abstract class which defines a map containing properties over a set of addresses.
 * The map is stored within a database table.
 */
public abstract class PropertyMapDB implements PropertyMap {

	private static final String PROPERTY_TABLE_PREFIX = "Property Map - ";

	protected static final String[] SCHEMA_FIELD_NAMES = new String[] { "Value" };
	protected static final String[] NO_SCHEMA_FIELD_NAMES = new String[0];
	protected static final Field[] NO_SCHEMA_FIELDS = new Field[0];

	protected static final int PROPERTY_VALUE_COL = 0;

	protected static final int DEFAULT_CACHE_SIZE = 100;

	static final NoValueException NO_VALUE_EXCEPTION = new NoValueException();

	public static String getTableName(String propertyName) {
		return PROPERTY_TABLE_PREFIX + propertyName;
	}

	protected DBHandle dbHandle;
	protected ErrorHandler errHandler;
	protected ChangeManager changeMgr;
	protected Schema schema;
	protected Table propertyTable;
	protected AddressMap addrMap;
	protected String name;

	protected ObjectCache cache = new ObjectCache(DEFAULT_CACHE_SIZE);
	protected Lock lock;

	/**
	 * Construct a property map.
	 * @param dbHandle database handle.
	 * @param errHandler database error handler.
	 * @param changeMgr notification of events
	 * @param addrMap address map.
	 * @param name property name.
	 * @param lock the synchronization lock
	 */
	PropertyMapDB(DBHandle dbHandle, ErrorHandler errHandler, ChangeManager changeMgr,
			AddressMap addrMap, String name) {

		this.dbHandle = dbHandle;
		this.errHandler = errHandler;
		this.changeMgr = changeMgr;
		this.lock = new Lock("Property");
		if (changeMgr == null) {
			this.changeMgr = new ChangeManagerAdapter();
		}
		this.addrMap = addrMap;
		this.name = name;
		propertyTable = dbHandle.getTable(getTableName());
		if (propertyTable != null) {
			schema = propertyTable.getSchema();
		}
	}

	void checkMapVersion(int openMode, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		if (propertyTable != null && addrMap.isUpgraded()) {
			if (openMode == DBConstants.UPGRADE) {
				upgradeTable(monitor);
			}
			else if (openMode != -1) {
				throw new VersionException(true);
			}
		}
	}

	private void upgradeTable(TaskMonitor monitor) throws IOException, CancelledException {

		AddressMap oldAddressMap = addrMap.getOldAddressMap();

		monitor.setMessage("Upgrading '" + name + "' Properties...");
		monitor.initialize(propertyTable.getRecordCount() * 2);
		int count = 0;

		DBHandle tmpDb = new DBHandle();
		try {
			tmpDb.startTransaction();

			Table tempTable = null;

			// Upgrade map entries into temporary database
			RecordIterator iter = propertyTable.iterator();
			while (iter.hasNext()) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				DBRecord rec = iter.next();
				if (tempTable == null) {
					// Create table on first entry upgrade
					tempTable = tmpDb.createTable(getTableName(), schema);
				}
				Address addr = oldAddressMap.decodeAddress(rec.getKey());
				rec.setKey(addrMap.getKey(addr, true));
				tempTable.putRecord(rec);
				monitor.setProgress(++count);
			}

			if (tempTable == null) {
				return;
			}

			// Remove old table
			dbHandle.deleteTable(getTableName());

			// Create new map table	
			propertyTable = dbHandle.createTable(getTableName(), schema);

			// Copy upgraded records
			iter = tempTable.iterator();
			while (iter.hasNext()) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				DBRecord rec = iter.next();
				propertyTable.putRecord(rec);
				monitor.setProgress(++count);
			}
		}
		finally {
			tmpDb.close();
		}
	}

	/**
	 * Get the default property table name for this property map.
	 * @return default property map table name.
	 */
	protected String getTableName() {
		return PROPERTY_TABLE_PREFIX + name;
	}

	/**
	 * Create the default propertyTable.
	 * This method may be called by add property methods if propertyTable
	 * is null.
	 * @throws IOException
	 */
	protected void createTable(Field valueField) throws IOException {
		if (valueField != null) {
			// Create default table schema with a value column and an long Address key
			Field[] fields = new Field[] { valueField };
			schema = new Schema(0, "Address", fields, SCHEMA_FIELD_NAMES);
		}
		else {
			// Table contains only a long Address key
			schema = new Schema(0, "Address", NO_SCHEMA_FIELDS, NO_SCHEMA_FIELD_NAMES);
		}
		propertyTable = dbHandle.createTable(getTableName(), schema);
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#getName()
	 */
	@Override
	public String getName() {
		return name;
	}

	/**
	 * Adjust the size of the underlying read cache.
	 * @param size the size of the cache.
	 */
	public void setCacheSize(int size) {
		lock.acquire();
		try {
			cache.setHardCacheSize(size);
		}
		finally {
			lock.release();
		}

	}

	/**
	 * Delete this property map and all underlying tables.
	 * This method should be overidden if any table other than the 
	 * default propertyTable is used.
	 * @throws IOException
	 */
	public void delete() throws IOException {
		lock.acquire();
		try {
			if (propertyTable != null) {
				cache = null;
				dbHandle.deleteTable(getTableName());
				propertyTable = null;
			}
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#intersects(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	public boolean intersects(Address startAddr, Address endAddr) {
		if (propertyTable == null) {
			return false;
		}
		try {
			AddressKeyIterator iter =
				new AddressKeyIterator(propertyTable, addrMap, startAddr, endAddr, startAddr, true);
			return iter.hasNext();
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return false;
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#intersects(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public boolean intersects(AddressSetView set) {
		if (propertyTable == null) {
			return false;
		}
		try {
			AddressKeyIterator iter =
				new AddressKeyIterator(propertyTable, addrMap, set, set.getMinAddress(), true);
			return iter.hasNext();
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return false;
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#removeRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	public boolean removeRange(Address startAddr, Address endAddr) {
		if (propertyTable == null) {
			return false;
		}
		lock.acquire();
		try {
			if (AddressRecordDeleter.deleteRecords(propertyTable, addrMap, startAddr, endAddr)) {
				cache = new ObjectCache(DEFAULT_CACHE_SIZE);
				return true;
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
		return false;
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#remove(ghidra.program.model.address.Address)
	 */
	@Override
	public boolean remove(Address addr) {
		if (propertyTable == null) {
			return false;
		}
		lock.acquire();
		boolean result = false;
		try {
			long key = addrMap.getKey(addr, false);
			cache.remove(key);
			result = propertyTable.deleteRecord(key);
			changeMgr.setPropertyChanged(name, addr, null, null);
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
		return result;
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#hasProperty(ghidra.program.model.address.Address)
	 */
	@Override
	public boolean hasProperty(Address addr) {
		if (propertyTable == null) {
			return false;
		}
		lock.acquire();
		boolean result = false;
		try {
			long key = addrMap.getKey(addr, false);
			if (key != AddressMap.INVALID_ADDRESS_KEY) {
				result = cache.contains(key) || propertyTable.hasRecord(key);
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
		return result;
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#getNextPropertyAddress(ghidra.program.model.address.Address)
	 */
	@Override
	public Address getNextPropertyAddress(Address addr) {
		if (propertyTable == null) {
			return null;
		}
		try {
			AddressKeyIterator iter = new AddressKeyIterator(propertyTable, addrMap, addr, false);
			return addrMap.decodeAddress(iter.next());
		}
		catch (NoSuchElementException e) {
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return null;
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#getPreviousPropertyAddress(ghidra.program.model.address.Address)
	 */
	@Override
	public Address getPreviousPropertyAddress(Address addr) {
		if (propertyTable == null) {
			return null;
		}
		try {
			AddressKeyIterator iter = new AddressKeyIterator(propertyTable, addrMap, addr, true);
			return addrMap.decodeAddress(iter.previous());
		}
		catch (NoSuchElementException e) {
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return null;
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#getFirstPropertyAddress()
	 */
	@Override
	public Address getFirstPropertyAddress() {
		if (propertyTable == null) {
			return null;
		}
		try {
			AddressKeyIterator iter = new AddressKeyIterator(propertyTable, addrMap, true);
			return addrMap.decodeAddress(iter.next());
		}
		catch (NoSuchElementException e) {
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return null;
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#getLastPropertyAddress()
	 */
	@Override
	public Address getLastPropertyAddress() {
		if (propertyTable == null) {
			return null;
		}
		try {
			AddressKeyIterator iter = new AddressKeyIterator(propertyTable, addrMap,
				addrMap.getAddressFactory().getAddressSet().getMaxAddress(), false);
			return addrMap.decodeAddress(iter.previous());
		}
		catch (NoSuchElementException e) {
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return null;
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#getSize()
	 */
	@Override
	public int getSize() {
		return propertyTable != null ? propertyTable.getRecordCount() : 0;
	}

	/**
	 * Get an iterator over the long address keys which contain a property value.
	 * @param set
	 * @param atStart true if the iterator should be positioned at the start
	 * of the range
	 * @return long address iterator.
	 * @throws IOException
	 */
	public AddressKeyIterator getAddressKeyIterator(AddressSetView set, boolean atStart)
			throws IOException {

		if (propertyTable == null) {
			return new AddressKeyIterator();
		}
		if (atStart) {
			return new AddressKeyIterator(propertyTable, addrMap, set, set.getMinAddress(), true);
		}
		return new AddressKeyIterator(propertyTable, addrMap, set, set.getMaxAddress(), false);
	}

	/**
	 * Get an iterator over the long address keys which contain a property value.
	 * @param start
	 * @param before true if the iterator should be positioned before the start address
	 * @return long address iterator.
	 * @throws IOException
	 */
	public AddressKeyIterator getAddressKeyIterator(Address start, boolean before)
			throws IOException {

		if (propertyTable == null) {
			return new AddressKeyIterator();
		}
		return new AddressKeyIterator(propertyTable, addrMap, start, before);
	}

	/**
	 * Get an iterator over the long address keys which contain a property value.
	 * @param start
	 * @param end
	 * @param atStart true if the iterator should be positioned at the start
	 * of the range
	 * @return long address iterator.
	 * @throws IOException
	 */
	public AddressKeyIterator getAddressKeyIterator(Address start, Address end, boolean atStart)
			throws IOException {

		if (propertyTable == null) {
			return new AddressKeyIterator();
		}
		if (atStart) {
			return new AddressKeyIterator(propertyTable, addrMap, start, end, start, true);
		}
		return new AddressKeyIterator(propertyTable, addrMap, start, end, end, false);
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#getPropertyIterator(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	public AddressIterator getPropertyIterator(Address start, Address end) {
		AddressKeyIterator keyIter = null;
		try {
			keyIter = getAddressKeyIterator(start, end, true);
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return new AddressKeyAddressIterator(keyIter, true, addrMap, errHandler);
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#getPropertyIterator(ghidra.program.model.address.Address, ghidra.program.model.address.Address, boolean)
	 */
	@Override
	public AddressIterator getPropertyIterator(Address start, Address end, boolean forward) {
		AddressKeyIterator keyIter = null;
		try {
			keyIter = getAddressKeyIterator(start, end, forward);
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return new AddressKeyAddressIterator(keyIter, forward, addrMap, errHandler);
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#getPropertyIterator()
	 */
	@Override
	public AddressIterator getPropertyIterator() {
		if (propertyTable == null) {
			return new EmptyAddressIterator();
		}
		AddressKeyIterator keyIter = null;
		try {
			keyIter = new AddressKeyIterator(propertyTable, addrMap, true);
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return new AddressKeyAddressIterator(keyIter, true, addrMap, errHandler);
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#getPropertyIterator(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	public AddressIterator getPropertyIterator(AddressSetView asv) {
		if (propertyTable == null) {
			return new EmptyAddressIterator();
		}
		AddressKeyIterator keyIter = null;
		try {
			keyIter =
				new AddressKeyIterator(propertyTable, addrMap, asv, asv.getMinAddress(), true);
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return new AddressKeyAddressIterator(keyIter, true, addrMap, errHandler);
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#getPropertyIterator(ghidra.program.model.address.AddressSetView, boolean)
	 */
	@Override
	public AddressIterator getPropertyIterator(AddressSetView asv, boolean forward) {
		if (propertyTable == null) {
			return new EmptyAddressIterator();
		}
		AddressKeyIterator keyIter = null;
		try {
			if (forward) {
				keyIter =
					new AddressKeyIterator(propertyTable, addrMap, asv, asv.getMinAddress(), true);
			}
			else {
				keyIter =
					new AddressKeyIterator(propertyTable, addrMap, asv, asv.getMaxAddress(), false);
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return new AddressKeyAddressIterator(keyIter, forward, addrMap, errHandler);
	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#getPropertyIterator(ghidra.program.model.address.Address, boolean)
	 */
	@Override
	public AddressIterator getPropertyIterator(Address start, boolean forward) {
		if (propertyTable == null) {
			return new EmptyAddressIterator();
		}
		AddressKeyIterator keyIter = null;
		try {
			keyIter = new AddressKeyIterator(propertyTable, addrMap, start, forward);
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return new AddressKeyAddressIterator(keyIter, forward, addrMap, errHandler);
	}

	/**
	 * Invalidates the cache.
	 */
	public void invalidateCache() {
		lock.acquire();
		try {
			propertyTable = dbHandle.getTable(getTableName());
			cache = new ObjectCache(DEFAULT_CACHE_SIZE);
		}
		finally {
			lock.release();
		}

	}

	/**
	 * @see ghidra.program.model.util.PropertyMap#moveRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	public void moveRange(Address start, Address end, Address newStart) {
		lock.acquire();
		try {
			cache = new ObjectCache(DEFAULT_CACHE_SIZE);
			if (propertyTable != null) {
				try {
					DatabaseTableUtils.updateAddressKey(propertyTable, addrMap, start, end,
						newStart, TaskMonitorAdapter.DUMMY_MONITOR);
				}
				catch (CancelledException e) {
				}
				catch (IOException e) {
					errHandler.dbError(e);
				}
			}

		}
		finally {
			lock.release();
		}
	}
}
