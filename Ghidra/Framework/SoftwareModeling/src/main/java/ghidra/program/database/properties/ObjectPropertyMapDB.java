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

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.program.util.ChangeManager;
import ghidra.util.Msg;
import ghidra.util.Saveable;
import ghidra.util.classfinder.ClassTranslator;
import ghidra.util.exception.*;
import ghidra.util.prop.PropertyVisitor;
import ghidra.util.task.TaskMonitor;

/**
 * Property manager that deals with properties that are of
 * a Saveable Object type and store within a database table.
 */
public class ObjectPropertyMapDB extends PropertyMapDB implements ObjectPropertyMap {

	private Class<? extends Saveable> saveableObjectClass;
	private int saveableObjectVersion;
	private boolean supportsPrivate;

	/**
	 * Construct an Saveable object property map.
	 * @param dbHandle database handle.
	 * @param openMode the mode that the program was opened in.
	 * @param errHandler database error handler.
	 * @param changeMgr change manager for event notification
	 * @param addrMap address map.
	 * @param name property name.
	 * @param monitor progress monitor that is only used when upgrading
	 * @throws CancelledException if the user cancels the upgrade operation.
	 * @throws IOException if a database io error occurs.
	 * @throws VersionException the map version is incompatible with
	 * the current Saveable object class version.  This will never be thrown
	 * if upgrade is true.
	 */
	public ObjectPropertyMapDB(DBHandle dbHandle, int openMode, ErrorHandler errHandler,
			ChangeManager changeMgr, AddressMap addrMap, String name,
			Class<? extends Saveable> saveableObjectClass, TaskMonitor monitor,
			boolean supportsPrivate) throws VersionException, CancelledException, IOException {
		super(dbHandle, errHandler, changeMgr, addrMap, name);
		this.saveableObjectClass = saveableObjectClass;
		this.supportsPrivate = supportsPrivate;
		Saveable tokenInstance = null;
		try {
			if (saveableObjectClass == GenericSaveable.class) {
				tokenInstance = new GenericSaveable(null, null);
			}
			else {
				tokenInstance = saveableObjectClass.newInstance();
			}
		}
		catch (InstantiationException e) {
			throw new RuntimeException(
				saveableObjectClass.getName() + " must provide public default constructor");
		}
		catch (IllegalAccessException e) {
			throw new RuntimeException(
				saveableObjectClass.getName() + " must provide public default constructor");
		}
		saveableObjectVersion = tokenInstance.getSchemaVersion();
		checkMapVersion(openMode, tokenInstance, monitor);
	}

	/**
	 * Returns the class for the indicated class path name.
	 * If the class can't be determined,
	 * the GenericSaveable class is returned.
	 * @param classPath the class path name of the desired class.
	 * @return the class or a GenericSaveable.
	 */
	@SuppressWarnings("unchecked")
	public static Class<? extends Saveable> getSaveableClassForName(String classPath) {
		Class<?> c = null;
		try {
			c = Class.forName(classPath);
		}
		catch (ClassNotFoundException e) {
			// Check the classNameMap.
			String newClassPath = ClassTranslator.get(classPath);
			if (newClassPath != null) {
				classPath = newClassPath;
				try {
					c = Class.forName(newClassPath);
				}
				catch (ClassNotFoundException e1) {

					// Since we can't get the class, at least handle it generically.
				}
			}
		}
		if (c == null) {
			Msg.error(ObjectPropertyMapDB.class, "Object property class not found: " + classPath);
		}
		else if (!Saveable.class.isAssignableFrom(c)) {
			Msg.error(ObjectPropertyMapDB.class,
				"Object property class does not implement Saveable interface: " + classPath);
		}
		// If unable to get valid Saveable class use generic implementation
		return (c != null) ? (Class<? extends Saveable>) c : GenericSaveable.class;
	}

	/**
	 * Verify that the storage schema has not changed.
	 * @param upgrade
	 * @param tokenInstance
	 * @throws VersionException
	 */
	private void checkMapVersion(int openMode, Saveable tokenInstance, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		if (propertyTable == null) {
			return;
		}
		int schemaVersion = schema.getVersion();
		if (schemaVersion > saveableObjectVersion) {
			// A newer version was used to create the database
			Msg.warn(this,
				"Program properties utilize a newer version of: " + saveableObjectClass.getName() +
					"(" + schemaVersion + ", " + saveableObjectVersion + ")");
			throw new VersionException(VersionException.NEWER_VERSION, false);
		}
		else if (addrMap.isUpgraded() || schemaVersion < saveableObjectVersion) {
			// An older version was used to create the database
			if (openMode != DBConstants.UPGRADE) {
				throw new VersionException(true);
			}
			if (!upgradeTable(tokenInstance, monitor)) {
				Msg.showError(this, null, "Properties Removed on Upgrade",
					"Warning! unable to upgrade properties for " + saveableObjectClass.getName() +
						"\nThese properties have been removed.");

			}
		}
	}

	/**
	 * Attempt to upgrade the map table records to the current schema.
	 * If unable to upgrade any of the map records, the table is removed.
	 * @param tokenInstance
	 * @return true if all records were successfully upgrade.  A false
	 * value indicates that one or more entries were dropped.
	 */
	private boolean upgradeTable(Saveable tokenInstance, TaskMonitor monitor)
			throws CancelledException, IOException {

		boolean allRecordsUpgraded = true;
		AddressMap oldAddressMap = addrMap.getOldAddressMap();

		monitor.initialize(propertyTable.getRecordCount() * 2);
		int count = 0;

		// Remove map table if upgrade not supported
		if (!tokenInstance.isUpgradeable(schema.getVersion())) {
			dbHandle.deleteTable(getTableName());
			propertyTable = null;
			schema = null;
			return false;
		}

		DBHandle tmpDb = new DBHandle();
		try {
			tmpDb.startTransaction();

			Schema newSchema = null;
			Table tempTable = null;

			// Upgrade map entries into temporary database
			RecordIterator iter = propertyTable.iterator();
			while (iter.hasNext()) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				DBRecord rec = iter.next();
				ObjectStorageAdapterDB oldObjStorage = new ObjectStorageAdapterDB(rec);
				ObjectStorageAdapterDB newObjStorage = new ObjectStorageAdapterDB();
				if (!tokenInstance.upgrade(oldObjStorage, schema.getVersion(), newObjStorage)) {
					allRecordsUpgraded = false;
					continue; // skip
				}
				if (newSchema == null) {
					// Create table on first entry upgrade
					newSchema = newObjStorage.getSchema(saveableObjectVersion);
					tempTable = tmpDb.createTable(getTableName(), newSchema);
				}
				Address addr = oldAddressMap.decodeAddress(rec.getKey());
				DBRecord newRecord = newSchema.createRecord(addrMap.getKey(addr, true));
				newObjStorage.save(newRecord);
				if (tempTable != null) {
					tempTable.putRecord(newRecord);
				}
				monitor.setProgress(++count);
			}

			// Remove old table
			dbHandle.deleteTable(getTableName());
			propertyTable = null;
			schema = null;

			if (tempTable == null) {
				return false;
			}

			// Create new map table
			propertyTable = dbHandle.createTable(getTableName(), newSchema);
			schema = newSchema;

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
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			tmpDb.close();
		}
		return allRecordsUpgraded;
	}

	@Override
	public void add(Address addr, Saveable value) {
		lock.acquire();
		try {
			if (!saveableObjectClass.isAssignableFrom(value.getClass())) {
				throw new IllegalArgumentException();
			}
			long key = addrMap.getKey(addr, true);
			Saveable oldValue = (Saveable) getObject(addr);

			String tableName = getTableName();
			Schema s;
			DBRecord rec;
			if (saveableObjectClass != GenericSaveable.class) {
				ObjectStorageAdapterDB objStorage = new ObjectStorageAdapterDB();
				value.save(objStorage);
				s = objStorage.getSchema(value.getSchemaVersion());
				checkSchema(s);
				createPropertyTable(tableName, s);
				rec = schema.createRecord(key);
				objStorage.save(rec);
			}
			else { // GenericSaveable
				GenericSaveable genericSaveable = ((GenericSaveable) value);
				DBRecord originalRec = genericSaveable.record;
				s = genericSaveable.schema;
				checkSchema(s);
				createPropertyTable(tableName, s);
				rec = originalRec.copy();
				rec.setKey(key);
			}

			propertyTable.putRecord(rec);
			cache.put(key, value);

			if (!isPrivate(value)) {
				changeMgr.setPropertyChanged(name, addr, oldValue, value);
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}

	}

	private boolean isPrivate(Saveable value) {
		if (!supportsPrivate) {
			return false;
		}
		return value.isPrivate();
	}

	private void createPropertyTable(String tableName, Schema s) throws IOException {
		if (propertyTable == null) {
			schema = s;
			propertyTable = dbHandle.createTable(tableName, schema);
		}
	}

	private void checkSchema(Schema s) {
		if (schema != null && !schema.equals(s)) {
			throw new RuntimeException("incompatible property storage: class=" +
				saveableObjectClass.getName() + " tableName=" + getTableName());
		}
	}

	@Override
	public Class<?> getObjectClass() {
		return saveableObjectClass;
	}

	@Override
	public Object getObject(Address addr) {
		if (propertyTable == null) {
			return null;
		}

		Saveable obj = null;

		lock.acquire();
		try {
			long key = addrMap.getKey(addr, false);
			if (key == AddressMap.INVALID_ADDRESS_KEY) {
				return null;
			}
			obj = (Saveable) cache.get(key);
			if (obj != null) {
				return obj;
			}

			DBRecord rec = propertyTable.getRecord(key);
			if (rec == null) {
				return null;
			}
			ObjectStorageAdapterDB objStorage = new ObjectStorageAdapterDB(rec);
			if (saveableObjectClass == GenericSaveable.class) {
				obj = new GenericSaveable(rec, propertyTable.getSchema());
			}
			else {
				obj = saveableObjectClass.newInstance();
				obj.restore(objStorage);
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		catch (RuntimeException e) {
			throw e;
		}
		catch (InstantiationException e) {
			errHandler.dbError(new IOException("Could not instantiate " + e.getMessage()));
		}
		catch (Exception e) {
			errHandler.dbError(new IOException(e.getMessage()));

		}
		finally {
			lock.release();
		}

		return obj;
	}

	@Override
	public void applyValue(PropertyVisitor visitor, Address addr) {
		Saveable obj = (Saveable) getObject(addr);
		if (obj != null) {
			visitor.visit(obj);
		}
	}

	// @see PropertyMapDB#getPropertyFieldClass() <- doesn't exist
	/**
	 * NOTE: Custom schema is utilized.
	 */
	protected Class<?> getPropertyFieldClass() {
		throw new AssertException();
	}

	/**
	 * Create the necessary table(s) to support this property.
	 * Schema will vary depending upon Saveable object.
	 */
	protected void createTable() {
		throw new AssertException();
	}

	/**
	 * Attempt to upgrade the specified object map.
	 * @param dbHandle
	 * @param errHandler
	 * @param changeMgr
	 * @param addrMap
	 * @param name
	 * @param saveableObjectClass
	 * @param version
	 * @return upgraded map instance or null if unable to upgrade.
	 */
	static ObjectPropertyMapDB upgradeMap(DBHandle dbHandle, ErrorHandler errHandler,
			ChangeManager changeMgr, AddressMap addrMap, String name, Class<?> saveableObjectClass,
			int version) {

// TODO Fill-in stuff here....

		return null;
	}
}
