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
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import db.*;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.ManagerDB;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.bookmark.OldBookmark;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.util.*;
import ghidra.program.util.ChangeManager;
import ghidra.program.util.ProgramEvent;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.map.TypeMismatchException;
import ghidra.util.task.TaskMonitor;

/**
 * Manages generic address keyed properties.
 */
public class DBPropertyMapManager implements PropertyMapManager, ManagerDB {

	private DBHandle dbHandle;
	private ProgramDB program;
	private AddressMap addrMap;
	private ChangeManager changeMgr;
	private PropertiesDBAdapter propertiesDBAdapter;
	private ConcurrentHashMap<String, PropertyMapDB<?>> propertyMapCache;
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
	 * @throws IOException if an IO error occurs
	 * @throws VersionException if a version error occurs
	 * @throws CancelledException if task is cancelled
	 */
	public DBPropertyMapManager(DBHandle handle, ChangeManager changeMgr, AddressMap addrMap,
			OpenMode openMode, Lock lock, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException {
		this.dbHandle = handle;
		this.changeMgr = changeMgr;
		this.addrMap = addrMap;
		this.lock = lock;
		if (openMode == OpenMode.CREATE) {
			dbHandle.createTable(PROPERTIES_TABLE_NAME, PROPERTIES_SCHEMA);
		}
		findAdapters(handle);
		propertyMapCache = new ConcurrentHashMap<String, PropertyMapDB<?>>();
		loadPropertyMaps(openMode, monitor);
	}

	@Override
	public void setProgram(ProgramDB program) {
		this.program = program;
	}

	@Override
	public void programReady(OpenMode openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
		// Nothing to do
	}

	@Override
	public void invalidateCache(boolean all) throws IOException {
		lock.acquire();
		try {
			for (PropertyMapDB<?> map : propertyMapCache.values()) {
				map.invalidate();
			}
			// NOTE: Reconciling maps immediately allows use to reliably use cache without
			// requiring map re-validation.
			loadPropertyMaps(null, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			// will not happen
		}
		catch (VersionException e) {
			throw new AssertException();
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Load {@code propertyMapCache} with all property map instances.
	 * @param openMode open mode or null if in response to a cache invalidate
	 * @param monitor task monitor
	 * @throws VersionException if a version error occurs
	 * @throws CancelledException if task is cancelled
	 */
	private void loadPropertyMaps(OpenMode openMode, TaskMonitor monitor)
			throws VersionException, CancelledException {
		try {
			VersionException ve = null;
			Set<String> oldMapNames = new HashSet<>(propertyMapCache.keySet());
			RecordIterator iter = propertiesDBAdapter.getRecords();
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				byte propertyType = rec.getByteValue(PROPERTY_TYPE_COL);
				String name = rec.getKeyField().getString();
				oldMapNames.remove(name);

				// Check for pre-existing map
				PropertyMapDB<?> pm = propertyMapCache.get(name);
				if (pm != null) {
					if (pm.validate(lock)) {
						continue; // keep the map we already have
					}
					propertyMapCache.remove(name);
				}

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
							if (BookmarkManager.OLD_BOOKMARK_PROPERTY_OBJECT_CLASS1
									.equals(className) ||
								BookmarkManager.OLD_BOOKMARK_PROPERTY_OBJECT_CLASS2
										.equals(className)) {
								// Upgrade handled by new BookmarkManager
								if (openMode == OpenMode.UPDATE) {
									throw new VersionException(VersionException.OLDER_VERSION,
										true);
								}
								pm = new ObjectPropertyMapDB<>(dbHandle, openMode, program,
									changeMgr, addrMap, name, OldBookmark.class, monitor, false);
							}
							else {
								pm = new ObjectPropertyMapDB<>(dbHandle, openMode, program,
									changeMgr, addrMap, name,
									ObjectPropertyMapDB.getSaveableClassForName(className), monitor,
									false);
							}

							break;
						default:
							if (openMode != null) {
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

			// Remove obsolete maps from cache
			for (String obsoleteMapName : oldMapNames) {
				propertyMapCache.remove(obsoleteMapName);
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
			IntPropertyMapDB pm = null;
			try {
				pm = new IntPropertyMapDB(dbHandle, OpenMode.CREATE, program, changeMgr, addrMap,
					propertyName, TaskMonitor.DUMMY);
				propertiesDBAdapter.putRecord(propertyName, INT_PROPERTY_TYPE, null);
				propertyMapCache.put(propertyName, pm);
			}
			catch (VersionException e) {
				throw new AssertException();
			}
			catch (CancelledException e) {
				// will not happen
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
			LongPropertyMapDB pm = null;
			try {
				pm = new LongPropertyMapDB(dbHandle, OpenMode.CREATE, program, changeMgr, addrMap,
					propertyName, TaskMonitor.DUMMY);
				propertiesDBAdapter.putRecord(propertyName, LONG_PROPERTY_TYPE, null);
				propertyMapCache.put(propertyName, pm);
			}
			catch (VersionException e) {
				throw new AssertException();
			}
			catch (CancelledException e) {
				// will not happen
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
			StringPropertyMapDB pm = null;
			try {
				pm = new StringPropertyMapDB(dbHandle, OpenMode.CREATE, program, changeMgr, addrMap,
					propertyName, TaskMonitor.DUMMY);
				propertiesDBAdapter.putRecord(propertyName, STRING_PROPERTY_TYPE, null);
				propertyMapCache.put(propertyName, pm);
			}
			catch (VersionException e) {
				throw new AssertException();
			}
			catch (CancelledException e) {
				// will not happen
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

	@Override
	public <T extends Saveable> ObjectPropertyMap<T> createObjectPropertyMap(String propertyName,
			Class<T> objectClass) throws DuplicateNameException {

		lock.acquire();
		try {
			if (propertyMapCache.containsKey(propertyName)) {
				throw new DuplicateNameException();
			}
			ObjectPropertyMapDB<T> pm = null;
			try {
				pm = new ObjectPropertyMapDB<>(dbHandle, OpenMode.CREATE, program, changeMgr,
					addrMap, propertyName, objectClass, TaskMonitor.DUMMY, false);
				propertiesDBAdapter.putRecord(propertyName, OBJECT_PROPERTY_TYPE,
					objectClass.getName());
				propertyMapCache.put(propertyName, pm);
			}
			catch (VersionException e) {
				throw new AssertException();
			}
			catch (CancelledException e) {
				// will not happen
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
			VoidPropertyMapDB pm = null;
			try {
				pm = new VoidPropertyMapDB(dbHandle, OpenMode.CREATE, program, changeMgr, addrMap,
					propertyName, TaskMonitor.DUMMY);
				propertiesDBAdapter.putRecord(propertyName, VOID_PROPERTY_TYPE, null);
				propertyMapCache.put(propertyName, pm);
			}
			catch (VersionException e) {
				throw new AssertException();
			}
			catch (CancelledException e) {
				// will not happen
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
	public PropertyMap<?> getPropertyMap(String propertyName) {
		return propertyMapCache.get(propertyName);
	}

	/**
	 * Returns the IntPropertyMap associated with the given name.
	 * @param propertyName the name of the property to retrieve.
	 * @throws TypeMismatchException if a propertyMap named propertyName
	 * exists but is not an IntPropertyMap.
	 */
	@Override
	public IntPropertyMap getIntPropertyMap(String propertyName) {
		PropertyMapDB<?> pm = propertyMapCache.get(propertyName);
		if (pm == null || pm instanceof IntPropertyMap) {
			return (IntPropertyMap) pm;
		}
		throw new TypeMismatchException("Property " + propertyName + " is not int type");
	}

	/**
	 * Returns the LongPropertyMap associated with the given name.
	 * @param propertyName the name of the property to retrieve.
	 * @throws TypeMismatchException if a propertyMap named propertyName
	 * exists but is not an LongPropertyMap.
	 */
	@Override
	public LongPropertyMap getLongPropertyMap(String propertyName) {
		PropertyMapDB<?> pm = propertyMapCache.get(propertyName);
		if (pm == null || pm instanceof LongPropertyMap) {
			return (LongPropertyMap) pm;
		}
		throw new TypeMismatchException("Property " + propertyName + " is not long type");
	}

	/**
	 * Returns the StringPropertyMap associated with the given name.
	 * @param propertyName the name of the property to retrieve.
	 * @throws TypeMismatchException if a propertyMap named propertyName
	 * exists but is not a StringPropertyMap.
	 */
	@Override
	public StringPropertyMap getStringPropertyMap(String propertyName) {
		PropertyMapDB<?> pm = propertyMapCache.get(propertyName);
		if (pm == null || pm instanceof StringPropertyMap) {
			return (StringPropertyMap) pm;
		}
		throw new TypeMismatchException("Property " + propertyName + " is not String type");
	}

	/**
	 * Returns the ObjectPropertyMap associated with the given name.
	 * @param propertyName the name of the property to retrieve.
	 * @throws TypeMismatchException if a propertyMap named propertyName
	 * exists but is not an ObjectPropertyMap.
	 */
	@Override
	public ObjectPropertyMap<?> getObjectPropertyMap(String propertyName) {
		PropertyMapDB<?> pm = propertyMapCache.get(propertyName);
		if (pm == null || pm instanceof ObjectPropertyMap) {
			return (ObjectPropertyMap<?>) pm;
		}
		throw new TypeMismatchException("Property " + propertyName + " is not object type");
	}

	/**
	 * Returns the VoidPropertyMap associated with the given name.
	 * @param propertyName the name of the property to retrieve.
	 * @throws TypeMismatchException if a propertyMap named propertyName
	 * exists but is not a VoidPropertyMap.
	 */
	@Override
	public VoidPropertyMap getVoidPropertyMap(String propertyName) {
		PropertyMapDB<?> pm = propertyMapCache.get(propertyName);
		if (pm == null || pm instanceof VoidPropertyMap) {
			return (VoidPropertyMap) pm;
		}
		throw new TypeMismatchException("Property " + propertyName + " is not Void type");
	}

	@Override
	public boolean removePropertyMap(String propertyName) {
		lock.acquire();
		try {
			PropertyMapDB<?> pm = propertyMapCache.remove(propertyName);
			if (pm != null) {
				pm.delete();
				propertiesDBAdapter.removeRecord(propertyName);
				propertyMapCache.remove(propertyName);
				changeMgr.setObjChanged(ProgramEvent.CODE_UNIT_PROPERTY_ALL_REMOVED, propertyName,
					null, null);
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

	@Override
	public Iterator<String> propertyManagers() {
		lock.acquire();
		try {
			// NOTE: infrequent use expected
			return propertyMapCache.keySet()
					.stream()
					.sorted() // Sort keys in natural order
					.iterator();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void removeAll(Address addr) {
		lock.acquire();
		try {
			for (PropertyMapDB<?> pm : propertyMapCache.values()) {
				pm.remove(addr);
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void removeAll(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		AddressRange.checkValidRange(startAddr, endAddr);
		lock.acquire();
		try {
			for (PropertyMapDB<?> pm : propertyMapCache.values()) {
				monitor.checkCancelled();
				pm.removeRange(startAddr, endAddr);
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException {
		lock.acquire();
		try {
			for (PropertyMapDB<?> pm : propertyMapCache.values()) {
				monitor.checkCancelled();
				pm.moveRange(fromAddr, fromAddr.add(length - 1), toAddr);
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		removeAll(startAddr, endAddr, monitor);
	}

}
