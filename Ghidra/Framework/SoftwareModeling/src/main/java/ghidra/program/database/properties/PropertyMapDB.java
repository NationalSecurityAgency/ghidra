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
import ghidra.framework.data.OpenMode;
import ghidra.program.database.DatabaseObject;
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

/**
 * Abstract class which defines a map containing properties over a set of addresses.
 * The map is stored within a database table.
 * @param <T> property value type
 */
public abstract class PropertyMapDB<T> extends DatabaseObject implements PropertyMap<T> {

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

	protected ObjectCache<T> cache = new ObjectCache<>(DEFAULT_CACHE_SIZE);
	protected Lock lock;

	/**
	 * Construct a property map.
	 * @param dbHandle database handle.
	 * @param errHandler database error handler.
	 * @param changeMgr notification of events
	 * @param addrMap address map.
	 * @param name property name.
	 */
	PropertyMapDB(DBHandle dbHandle, ErrorHandler errHandler, ChangeManager changeMgr,
			AddressMap addrMap, String name) {
		super(null, 0); // DatabaseObject cache is not used

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

	// Expose validate method to DBPropertyMapManager
	@Override
	protected boolean validate(Lock lck) {
		return super.validate(lck);
	}

	/**
	 * Check if a table upgrade should be performed or a version error thrown.
	 * @param openMode the mode that the program was openned in or null if instantiated during
	 * cache invalidate.  Used to detect versioning error only.
	 * @param monitor task monitor
	 * @throws VersionException if the database version is not the expected version.
	 * @throws CancelledException if the user cancels the upgrade operation.
	 * @throws IOException if an IO error occurs
	 */
	void checkMapVersion(OpenMode openMode, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		if (propertyTable != null && addrMap.isUpgraded()) {
			if (openMode == OpenMode.UPGRADE) {
				upgradeTable(monitor);
			}
			else if (openMode != null) {
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
	 * This method may be called by add property methods if propertyTable is null.
	 * @param valueField property value field type (null corresponds to void map table)
	 * @throws IOException if IO error occurs
	 */
	protected void createTable(Field valueField) throws IOException {
		schema = getTableSchema(valueField);
		propertyTable = dbHandle.createTable(getTableName(), schema);
	}

	private static Schema getTableSchema(Field valueField) {
		if (valueField != null) {
			// Create default table schema with a value column and an long Address key
			Field[] fields = new Field[] { valueField };
			return new Schema(0, "Address", fields, SCHEMA_FIELD_NAMES);
		}

		// Table contains only a long Address key (i.e., void property map)
		return new Schema(0, "Address", NO_SCHEMA_FIELDS, NO_SCHEMA_FIELD_NAMES);
	}

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
	 * @throws IOException if IO error occurs
	 */
	public void delete() throws IOException {
		lock.acquire();
		try {
			checkDeleted();
			setDeleted();
			if (propertyTable != null) {
				cache = new ObjectCache<>(DEFAULT_CACHE_SIZE);
				dbHandle.deleteTable(getTableName());
				propertyTable = null;
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean intersects(Address startAddr, Address endAddr) {
		validate(lock);
		Table table = propertyTable;
		if (table == null) {
			return false;
		}
		try {
			AddressKeyIterator iter =
				new AddressKeyIterator(table, addrMap, startAddr, endAddr, startAddr, true);
			return iter.hasNext();
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return false;
	}

	@Override
	public boolean intersects(AddressSetView set) {
		validate(lock);
		Table table = propertyTable;
		if (table == null) {
			return false;
		}
		try {
			AddressKeyIterator iter =
				new AddressKeyIterator(table, addrMap, set, set.getMinAddress(), true);
			return iter.hasNext();
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return false;
	}

	@Override
	public boolean removeRange(Address startAddr, Address endAddr) {
		lock.acquire();
		try {
			checkDeleted();
			if (propertyTable == null) {
				return false;
			}
			if (AddressRecordDeleter.deleteRecords(propertyTable, addrMap, startAddr, endAddr)) {
				cache = new ObjectCache<>(DEFAULT_CACHE_SIZE);
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

	@Override
	public boolean remove(Address addr) {
		lock.acquire();
		boolean result = false;
		try {
			checkDeleted();
			if (propertyTable == null) {
				return false;
			}
			long addrKey = addrMap.getKey(addr, false);
			cache.remove(addrKey);
			result = propertyTable.deleteRecord(addrKey);
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

	@Override
	public boolean hasProperty(Address addr) {
		validate(lock);
		Table table = propertyTable;
		if (table == null) {
			return false;
		}
		try {
			long addrKey = addrMap.getKey(addr, false);
			if (addrKey != AddressMap.INVALID_ADDRESS_KEY) {
				return cache.contains(addrKey) || table.hasRecord(addrKey);
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return false;
	}

	@Override
	public Address getNextPropertyAddress(Address addr) {
		validate(lock);
		Table table = propertyTable;
		if (table == null) {
			return null;
		}
		try {
			AddressKeyIterator iter = new AddressKeyIterator(table, addrMap, addr, false);
			return addrMap.decodeAddress(iter.next());
		}
		catch (NoSuchElementException e) {
			// ignore
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return null;
	}

	@Override
	public Address getPreviousPropertyAddress(Address addr) {
		validate(lock);
		Table table = propertyTable;
		if (table == null) {
			return null;
		}
		try {
			AddressKeyIterator iter = new AddressKeyIterator(table, addrMap, addr, true);
			return addrMap.decodeAddress(iter.previous());
		}
		catch (NoSuchElementException e) {
			// ignore
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return null;
	}

	@Override
	public Address getFirstPropertyAddress() {
		validate(lock);
		Table table = propertyTable;
		if (table == null) {
			return null;
		}
		try {
			AddressKeyIterator iter = new AddressKeyIterator(table, addrMap, true);
			return addrMap.decodeAddress(iter.next());
		}
		catch (NoSuchElementException e) {
			// ignore
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return null;
	}

	@Override
	public Address getLastPropertyAddress() {
		validate(lock);
		Table table = propertyTable;
		if (table == null) {
			return null;
		}
		try {
			AddressKeyIterator iter = new AddressKeyIterator(table, addrMap,
				addrMap.getAddressFactory().getAddressSet().getMaxAddress(), false);
			return addrMap.decodeAddress(iter.previous());
		}
		catch (NoSuchElementException e) {
			// ignore
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return null;
	}

	@Override
	public int getSize() {
		validate(lock);
		Table table = propertyTable;
		return table != null ? table.getRecordCount() : 0;
	}

	/**
	 * Get an iterator over the long address keys which contain a property value.
	 * @param set addresses over which to iterate (null indicates all defined memory regions)
	 * @param atStart true if the iterator should be positioned at the start
	 * of the range
	 * @return long address iterator.
	 * @throws IOException if IO error occurs
	 */
	public AddressKeyIterator getAddressKeyIterator(AddressSetView set, boolean atStart)
			throws IOException {
		validate(lock);
		Table table = propertyTable;
		if (table == null || (set != null && set.isEmpty())) {
			return AddressKeyIterator.EMPTY_ITERATOR;
		}
		if (atStart) {
			return new AddressKeyIterator(table, addrMap, set, set.getMinAddress(), true);
		}
		return new AddressKeyIterator(table, addrMap, set, set.getMaxAddress(), false);
	}

	/**
	 * Get an iterator over the long address keys which contain a property value.
	 * @param start iterator starting position
	 * @param before true if the iterator should be positioned before the start address
	 * @return long address iterator.
	 * @throws IOException if IO error occurs
	 */
	public AddressKeyIterator getAddressKeyIterator(Address start, boolean before)
			throws IOException {
		validate(lock);
		Table table = propertyTable;
		if (table == null) {
			return AddressKeyIterator.EMPTY_ITERATOR;
		}
		return new AddressKeyIterator(table, addrMap, start, before);
	}

	/**
	 * Get an iterator over the long address keys which contain a property value.
	 * @param start start of iterator address range
	 * @param end end of iterator address range
	 * @param atStart true if the iterator should be positioned at the start
	 * of the range
	 * @return long address iterator.
	 * @throws IOException if IO error occurs
	 */
	public AddressKeyIterator getAddressKeyIterator(Address start, Address end, boolean atStart)
			throws IOException {
		validate(lock);
		Table table = propertyTable;
		if (table == null) {
			return AddressKeyIterator.EMPTY_ITERATOR;
		}
		if (atStart) {
			return new AddressKeyIterator(table, addrMap, start, end, start, true);
		}
		return new AddressKeyIterator(table, addrMap, start, end, end, false);
	}

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

	@Override
	public AddressIterator getPropertyIterator() {
		validate(lock);
		Table table = propertyTable;
		if (table == null) {
			return new EmptyAddressIterator();
		}
		AddressKeyIterator keyIter = null;
		try {
			keyIter = new AddressKeyIterator(table, addrMap, true);
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return new AddressKeyAddressIterator(keyIter, true, addrMap, errHandler);
	}

	@Override
	public AddressIterator getPropertyIterator(AddressSetView asv) {
		validate(lock);
		Table table = propertyTable;
		if (table == null) {
			return new EmptyAddressIterator();
		}
		AddressKeyIterator keyIter = null;
		try {
			keyIter = new AddressKeyIterator(table, addrMap, asv, asv.getMinAddress(), true);
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return new AddressKeyAddressIterator(keyIter, true, addrMap, errHandler);
	}

	@Override
	public AddressIterator getPropertyIterator(AddressSetView asv, boolean forward) {
		validate(lock);
		Table table = propertyTable;
		if (table == null || (asv != null && asv.isEmpty())) {
			return AddressIterator.EMPTY_ITERATOR;
		}
		AddressKeyIterator keyIter = null;
		try {
			if (forward) {
				keyIter = new AddressKeyIterator(table, addrMap, asv, asv.getMinAddress(), true);
			}
			else {
				keyIter = new AddressKeyIterator(table, addrMap, asv, asv.getMaxAddress(), false);
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return new AddressKeyAddressIterator(keyIter, forward, addrMap, errHandler);
	}

	@Override
	public AddressIterator getPropertyIterator(Address start, boolean forward) {
		validate(lock);
		Table table = propertyTable;
		if (table == null) {
			return new EmptyAddressIterator();
		}
		AddressKeyIterator keyIter = null;
		try {
			keyIter = new AddressKeyIterator(table, addrMap, start, forward);
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return new AddressKeyAddressIterator(keyIter, forward, addrMap, errHandler);
	}

	/**
	 * Invalidates the cache.
	 */
	public void invalidate() {
		lock.acquire();
		try {
			setInvalid();
		}
		finally {
			lock.release();
		}
	}

	@Override
	protected boolean refresh() {
		cache = new ObjectCache<>(DEFAULT_CACHE_SIZE);
		propertyTable = dbHandle.getTable(getTableName());
		if (propertyTable != null) {
			if (!propertyTable.getSchema().equals(schema)) {
				propertyTable = null;
				return false;
			}
		}
		// Must assume lazy table and empty map
		return true;
	}

	@Override
	public void moveRange(Address start, Address end, Address newStart) {
		lock.acquire();
		try {
			checkDeleted();
			cache = new ObjectCache<>(DEFAULT_CACHE_SIZE);
			if (propertyTable != null) {
				try {
					DatabaseTableUtils.updateAddressKey(propertyTable, addrMap, start, end,
						newStart, TaskMonitor.DUMMY);
				}
				catch (CancelledException e) {
					// will not happen
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
