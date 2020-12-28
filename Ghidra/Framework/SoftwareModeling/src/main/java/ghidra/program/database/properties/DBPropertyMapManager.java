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
/*
 * Created on May 1, 2003
 */
package ghidra.program.database.properties;

import java.io.IOException;
import java.util.Iterator;
import java.util.TreeMap;

import db.*;
import ghidra.program.database.ManagerDB;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.bookmark.OldBookmark;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.util.*;
import ghidra.program.util.ChangeManager;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Manages generic address keyed properties.
 */
public class DBPropertyMapManager implements PropertyMapManager, ManagerDB {

	private DBHandle dbHandle;
	private ProgramDB program;
	private AddressMap addrMap;
	private ChangeManager changeMgr;
	private PropertiesDBAdapter propertiesDBAdapter;
	private TreeMap<String, PropertyMap> propertyMapCache;
	private Lock lock;

	static final int CURRENT_PROPERTIES_TABLE_VERSION = 0;

	static final String PROPERTIES_TABLE_NAME = "Properties";

	// Column for Properties table (key is the property name)
	static final int PROPERTY_TYPE_COL = 0;
	static final int OBJECT_CLASS_COL = 1;

	// Property types
	static final byte INT_PROPERTY_TYPE = 0;
	static final byte LONG_PROPERTY_TYPE = 1;
	static final byte STRING_PROPERTY_TYPE = 2;
	static final byte VOID_PROPERTY_TYPE = 3;
	static final byte OBJECT_PROPERTY_TYPE = 4;

	static final Schema PROPERTIES_SCHEMA;

	static {

		PROPERTIES_SCHEMA = new Schema(CURRENT_PROPERTIES_TABLE_VERSION, StringField.INSTANCE,
			"Name", new Field[] { ByteField.INSTANCE, StringField.INSTANCE, IntField.INSTANCE },
			new String[] { "Type", "Object Class", "Version" });

	}

	/**
	 * Constructs a new DBPropertyMapManager
	 * @param handle the database handle
	 * @param changeMgr the change manager
	 * @param addrMap the address map
	 * @param openMode the program open mode.
	 * @param lock the program synchronization lock
	 * @param monitor the task monitor
	 * @throws IOException
	 * @throws VersionException
	 * @throws CancelledException
	 */
	public DBPropertyMapManager(DBHandle handle, ChangeManager changeMgr, AddressMap addrMap,
			int openMode, Lock lock, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException {
		this.dbHandle = handle;
		this.changeMgr = changeMgr;
		this.addrMap = addrMap;
		this.lock = lock;
		if (openMode == DBConstants.CREATE) {
			dbHandle.createTable(PROPERTIES_TABLE_NAME, PROPERTIES_SCHEMA);
		}
		findAdapters(handle);
		propertyMapCache = new TreeMap<String, PropertyMap>();
		loadPropertyMaps(openMode, monitor);
	}

	/**
	 * @see ghidra.program.database.ManagerDB#setProgram(ghidra.program.database.ProgramDB)
	 */
	@Override
	public void setProgram(ProgramDB program) {
		this.program = program;
	}

	/**
	 * @see ghidra.program.database.ManagerDB#programReady(int, int, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void programReady(int openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
		// Nothing to do
	}

	/**
	 * @see ghidra.program.database.ManagerDB#invalidateCache(boolean)
	 */
	@Override
	public void invalidateCache(boolean all) throws IOException {
		lock.acquire();
		try {
			propertyMapCache.clear();
			loadPropertyMaps(-1, TaskMonitorAdapter.DUMMY_MONITOR);
		}
		catch (CancelledException e) {
		}
		catch (VersionException e) {
			throw new AssertException();
		}
		finally {
			lock.release();
		}
	}

	private void loadPropertyMaps(int openMode, TaskMonitor monitor)
			throws VersionException, CancelledException {
		try {
			VersionException ve = null;
			RecordIterator iter = propertiesDBAdapter.getRecords();
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				String name = rec.getKeyField().getString();
				byte propertyType = rec.getByteValue(PROPERTY_TYPE_COL);
				PropertyMap pm = null;
				try {
					switch (propertyType) {
						case INT_PROPERTY_TYPE:
							pm = new IntPropertyMapDB(dbHandle, openMode, program, changeMgr,
								addrMap, name, monitor);
							break;
						case LONG_PROPERTY_TYPE:
							pm = new LongPropertyMapDB(dbHandle, openMode, program, changeMgr,
								addrMap, name, monitor);
							break;
						case STRING_PROPERTY_TYPE:
							pm = new StringPropertyMapDB(dbHandle, openMode, program, changeMgr,
								addrMap, name, monitor);
							break;
						case VOID_PROPERTY_TYPE:
							pm = new VoidPropertyMapDB(dbHandle, openMode, program, changeMgr,
								addrMap, name, monitor);
							break;
						case OBJECT_PROPERTY_TYPE:
							String className = rec.getString(OBJECT_CLASS_COL);
							//boolean upgrade = (openMode == ProgramDB.UPGRADE);
							if (BookmarkManager.OLD_BOOKMARK_PROPERTY_OBJECT_CLASS1.equals(
								className) ||
								BookmarkManager.OLD_BOOKMARK_PROPERTY_OBJECT_CLASS2.equals(
									className)) {
								// Upgrade handled by new BookmarkManager
								if (openMode == DBConstants.UPDATE) {
									throw new VersionException(VersionException.OLDER_VERSION,
										true);
								}
								pm = new ObjectPropertyMapDB(dbHandle, openMode, program, changeMgr,
									addrMap, name, OldBookmark.class, monitor, false);
							}
							else {
								pm = new ObjectPropertyMapDB(dbHandle, openMode, program, changeMgr,
									addrMap, name,
									ObjectPropertyMapDB.getSaveableClassForName(className), monitor,
									false);
							}

							break;
						default:
							if (openMode >= 0) {
								// employ unsupported property class
								Msg.showError(this, null, "Unsupported Property", "WARNING: " +
									" property ignored, unrecognized type: " + propertyType);
							}
					}
				}
				catch (VersionException e) {
					ve = e.combine(ve);
				}
				if (pm == null) {
					pm = new UnsupportedMapDB(dbHandle, openMode, program, changeMgr, addrMap, name,
						monitor);
				}
				propertyMapCache.put(name, pm);
			}
			if (ve != null) {
				throw ve;
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
	}

	private void findAdapters(DBHandle handle) throws VersionException {
		propertiesDBAdapter = new PropertiesDBAdapterV0(dbHandle);
	}

	/**
	 * Creates a new IntPropertyMap with the given name.
	 * @param propertyName the name of the property to create.
	 * @exception DuplicateNameException thrown if a PropertyMap already
	 * exists with that name.
	 */
	@Override
	public IntPropertyMap createIntPropertyMap(String propertyName) throws DuplicateNameException {

		lock.acquire();
		try {
			if (propertyMapCache.containsKey(propertyName)) {
				throw new DuplicateNameException();
			}
			IntPropertyMap pm = null;
			try {
				pm = new IntPropertyMapDB(dbHandle, DBConstants.CREATE, program, changeMgr, addrMap,
					propertyName, TaskMonitorAdapter.DUMMY_MONITOR);
				propertiesDBAdapter.putRecord(propertyName, INT_PROPERTY_TYPE, null);
				propertyMapCache.put(propertyName, pm);
			}
			catch (VersionException e) {
				throw new AssertException();
			}
			catch (CancelledException e) {
			}
			catch (IOException e) {
				program.dbError(e);
			}
			return pm;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Creates a new LongPropertyMap with the given name.
	 * @param propertyName the name of the property to create.
	 * @exception DuplicateNameException thrown if a PropertyMap already
	 * exists with that name.
	 */
	@Override
	public LongPropertyMap createLongPropertyMap(String propertyName)
			throws DuplicateNameException {

		lock.acquire();
		try {
			if (propertyMapCache.containsKey(propertyName)) {
				throw new DuplicateNameException();
			}
			LongPropertyMap pm = null;
			try {
				pm = new LongPropertyMapDB(dbHandle, DBConstants.CREATE, program, changeMgr,
					addrMap, propertyName, TaskMonitorAdapter.DUMMY_MONITOR);
				propertiesDBAdapter.putRecord(propertyName, LONG_PROPERTY_TYPE, null);
				propertyMapCache.put(propertyName, pm);
			}
			catch (VersionException e) {
				throw new AssertException();
			}
			catch (CancelledException e) {
			}
			catch (IOException e) {
				program.dbError(e);
			}
			return pm;

		}
		finally {
			lock.release();
		}
	}

	/**
	 * Creates a new StringPropertyMap with the given name.
	 * @param propertyName the name of the property to create.
	 * @exception DuplicateNameException thrown if a PropertyMap already
	 * exists with that name.
	 */
	@Override
	public StringPropertyMap createStringPropertyMap(String propertyName)
			throws DuplicateNameException {

		lock.acquire();
		try {
			if (propertyMapCache.containsKey(propertyName)) {
				throw new DuplicateNameException();
			}
			StringPropertyMap pm = null;
			try {
				pm = new StringPropertyMapDB(dbHandle, DBConstants.CREATE, program, changeMgr,
					addrMap, propertyName, TaskMonitorAdapter.DUMMY_MONITOR);
				propertiesDBAdapter.putRecord(propertyName, STRING_PROPERTY_TYPE, null);
				propertyMapCache.put(propertyName, pm);
			}
			catch (VersionException e) {
				throw new AssertException();
			}
			catch (CancelledException e) {
			}
			catch (IOException e) {
				program.dbError(e);
			}
			return pm;
		}
		finally {
			lock.release();
		}

	}

	/**
	 * Creates a new ObjectPropertyMap with the given name.
	 * @param propertyName the name of the property to create.
	 * @param objectClass the class of the objects that will be stored in the property.
	 * @exception DuplicateNameException thrown if a PropertyMap already
	 * exists with that name.
	 */
	@Override
	public ObjectPropertyMap createObjectPropertyMap(String propertyName,
			Class<? extends Saveable> objectClass) throws DuplicateNameException {

		lock.acquire();
		try {
			if (propertyMapCache.containsKey(propertyName)) {
				throw new DuplicateNameException();
			}
			ObjectPropertyMap pm = null;
			try {
				pm = new ObjectPropertyMapDB(dbHandle, DBConstants.CREATE, program, changeMgr,
					addrMap, propertyName, objectClass, TaskMonitorAdapter.DUMMY_MONITOR, false);
				propertiesDBAdapter.putRecord(propertyName, OBJECT_PROPERTY_TYPE,
					objectClass.getName());
				propertyMapCache.put(propertyName, pm);
			}
			catch (VersionException e) {
				throw new AssertException();
			}
			catch (CancelledException e) {
			}
			catch (IOException e) {
				program.dbError(e);
			}
			return pm;
		}
		finally {
			lock.release();
		}

	}

	/**
	 * Creates a new VoidPropertyMap with the given name.
	 * @param propertyName the name of the property to create.
	 * @exception DuplicateNameException thrown if a PropertyMap already
	 * exists with that name.
	 */
	@Override
	public VoidPropertyMap createVoidPropertyMap(String propertyName)
			throws DuplicateNameException {

		lock.acquire();
		try {
			if (propertyMapCache.containsKey(propertyName)) {
				throw new DuplicateNameException();
			}
			VoidPropertyMap pm = null;
			try {
				pm = new VoidPropertyMapDB(dbHandle, DBConstants.CREATE, program, changeMgr,
					addrMap, propertyName, TaskMonitorAdapter.DUMMY_MONITOR);
				propertiesDBAdapter.putRecord(propertyName, VOID_PROPERTY_TYPE, null);
				propertyMapCache.put(propertyName, pm);
			}
			catch (VersionException e) {
				throw new AssertException();
			}
			catch (CancelledException e) {
			}
			catch (IOException e) {
				program.dbError(e);
			}
			return pm;
		}
		finally {
			lock.release();
		}

	}

	/**
	 * Returns the PropertyMap with the given name or null if no PropertyMap
	 * exists with that name.
	 * @param propertyName the name of the property to retrieve.
	 */
	@Override
	public PropertyMap getPropertyMap(String propertyName) {
		lock.acquire();
		try {
			return propertyMapCache.get(propertyName);
		}
		finally {
			lock.release();
		}

	}

	/**
	 * Returns the IntPropertyMap associated with the given name.
	 * @param propertyName the name of the property to retrieve.
	 * @throws TypeMismatchException if a propertyMap named propertyName
	 * exists but is not an IntPropertyMap.
	 */
	@Override
	public IntPropertyMap getIntPropertyMap(String propertyName) {

		lock.acquire();
		try {
			PropertyMap pm = propertyMapCache.get(propertyName);
			if (pm == null || pm instanceof IntPropertyMap) {
				return (IntPropertyMap) pm;
			}
			throw new TypeMismatchException("Property " + propertyName + " is not int type");
		}
		finally {
			lock.release();
		}

	}

	/**
	 * Returns the LongPropertyMap associated with the given name.
	 * @param propertyName the name of the property to retrieve.
	 * @throws TypeMismatchException if a propertyMap named propertyName
	 * exists but is not an LongPropertyMap.
	 */
	@Override
	public LongPropertyMap getLongPropertyMap(String propertyName) {
		lock.acquire();
		try {
			PropertyMap pm = propertyMapCache.get(propertyName);
			if (pm == null || pm instanceof LongPropertyMap) {
				return (LongPropertyMap) pm;
			}
			throw new TypeMismatchException("Property " + propertyName + " is not long type");
		}
		finally {
			lock.release();
		}

	}

	/**
	 * Returns the StringPropertyMap associated with the given name.
	 * @param propertyName the name of the property to retrieve.
	 * @throws TypeMismatchException if a propertyMap named propertyName
	 * exists but is not a StringPropertyMap.
	 */
	@Override
	public StringPropertyMap getStringPropertyMap(String propertyName) {
		lock.acquire();
		try {
			PropertyMap pm = propertyMapCache.get(propertyName);
			if (pm == null || pm instanceof StringPropertyMap) {
				return (StringPropertyMap) pm;
			}
			throw new TypeMismatchException("Property " + propertyName + " is not String type");

		}
		finally {
			lock.release();
		}
	}

	/**
	 * Returns the ObjectPropertyMap associated with the given name.
	 * @param propertyName the name of the property to retrieve.
	 * @throws TypeMismatchException if a propertyMap named propertyName
	 * exists but is not an ObjectPropertyMap.
	 */
	@Override
	public ObjectPropertyMap getObjectPropertyMap(String propertyName) {
		lock.acquire();
		try {
			PropertyMap pm = propertyMapCache.get(propertyName);
			if (pm == null || pm instanceof ObjectPropertyMap) {
				return (ObjectPropertyMap) pm;
			}
			throw new TypeMismatchException("Property " + propertyName + " is not object type");

		}
		finally {
			lock.release();
		}
	}

	/**
	 * Returns the VoidPropertyMap associated with the given name.
	 * @param propertyName the name of the property to retrieve.
	 * @throws TypeMismatchException if a propertyMap named propertyName
	 * exists but is not a VoidPropertyMap.
	 */
	@Override
	public VoidPropertyMap getVoidPropertyMap(String propertyName) {
		lock.acquire();
		try {
			PropertyMap pm = propertyMapCache.get(propertyName);
			if (pm == null || pm instanceof VoidPropertyMap) {
				return (VoidPropertyMap) pm;
			}
			throw new TypeMismatchException("Property " + propertyName + " is not Void type");
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Removes the PropertyMap with the given name.
	 * @param propertyName the name of the property to remove.
	 * @return true if a PropertyMap with that name was found (and removed)
	 */
	@Override
	public boolean removePropertyMap(String propertyName) {
		lock.acquire();
		try {
			if (propertyMapCache.containsKey(propertyName)) {
				PropertyMapDB pm = (PropertyMapDB) propertyMapCache.get(propertyName);
				pm.delete();
				propertiesDBAdapter.removeRecord(propertyName);
				propertyMapCache.remove(propertyName);
				changeMgr.setObjChanged(ChangeManager.DOCR_CODE_UNIT_PROPERTY_ALL_REMOVED,
					propertyName, null, null);
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

	/**
	 * Returns an iterator over the names of all existing PropertyMangers.
	 */
	@Override
	public Iterator<String> propertyManagers() {
		lock.acquire();
		try {
			return propertyMapCache.keySet().iterator();
		}
		finally {
			lock.release();
		}

	}

	/**
	 * Removes any property at the given address from all defined
	 * PropertyManagers.
	 * @param addr the address at which to remove all properties.
	 */
	@Override
	public void removeAll(Address addr) {
		lock.acquire();
		try {
			Iterator<PropertyMap> iter = propertyMapCache.values().iterator();
			while (iter.hasNext()) {
				PropertyMapDB pm = (PropertyMapDB) iter.next();
				pm.remove(addr);
			}

		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.util.PropertyMapManager#removeAll(ghidra.program.model.address.Address, ghidra.program.model.address.Address, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void removeAll(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		lock.acquire();
		try {
			Iterator<PropertyMap> iter = propertyMapCache.values().iterator();
			while (iter.hasNext()) {
				monitor.checkCanceled();
				PropertyMapDB pm = (PropertyMapDB) iter.next();
				pm.removeRange(startAddr, endAddr);
			}

		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.database.ManagerDB#moveAddressRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address, long, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException {
		lock.acquire();
		try {
			Iterator<PropertyMap> iter = propertyMapCache.values().iterator();
			while (iter.hasNext()) {
				monitor.checkCanceled();
				PropertyMapDB pm = (PropertyMapDB) iter.next();
				pm.moveRange(fromAddr, fromAddr.add(length - 1), toAddr);
			}

		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.database.ManagerDB#deleteAddressRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		removeAll(startAddr, endAddr, monitor);

	}

}
