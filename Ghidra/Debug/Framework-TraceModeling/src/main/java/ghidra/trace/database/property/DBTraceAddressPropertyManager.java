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
package ghidra.trace.database.property;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;

import db.DBHandle;
import db.DBRecord;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.program.model.util.TypeMismatchException;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceManager;
import ghidra.trace.database.map.AbstractDBTracePropertyMap;
import ghidra.trace.database.map.AbstractDBTracePropertyMap.*;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.map.TracePropertyMap;
import ghidra.trace.model.property.TraceAddressPropertyManager;
import ghidra.util.*;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Document me
 * 
 * TODO: This is public for user properties, i.e., {@link ProgramUserData}, but encapsulated for
 * trace properties
 */
public class DBTraceAddressPropertyManager implements TraceAddressPropertyManager, DBTraceManager {
	@DBAnnotatedObjectInfo(version = 0)
	protected static class DBTraceAddressPropertyEntry extends DBAnnotatedObject {
		static final String TABLE_NAME = "AddressProperties";

		static final String NAME_COLUMN_NAME = "Name";
		static final String TYPE_COLUMN_NAME = "Type";
		// TODO: Version? That should be in the schema of the property's table, no?

		@DBAnnotatedColumn(NAME_COLUMN_NAME)
		static DBObjectColumn NAME_COLUMN;

		@DBAnnotatedColumn(TYPE_COLUMN_NAME)
		static DBObjectColumn TYPE_COLUMN;

		@DBAnnotatedField(column = NAME_COLUMN_NAME)
		String name;
		@DBAnnotatedField(column = TYPE_COLUMN_NAME)
		String type;

		AbstractDBTracePropertyMap<?, ?> map;

		public DBTraceAddressPropertyEntry(DBCachedObjectStore<?> store, DBRecord record) {
			super(store, record);
		}

		void set(String name, Class<?> valueClass) {
			this.name = name;
			this.type = valueClass.getName();
			update(NAME_COLUMN, TYPE_COLUMN);
		}

		Class<?> getValueClass() throws ClassNotFoundException {
			return this.getClass().getClassLoader().loadClass(type);
		}
	}

	protected final DBHandle dbh;
	protected final ReadWriteLock lock;
	protected final Language baseLanguage;
	protected final DBTrace trace;
	protected final DBTraceThreadManager threadManager;

	protected final DBCachedObjectStore<DBTraceAddressPropertyEntry> propertyStore;
	protected final Map<String, AbstractDBTracePropertyMap<?, ?>> propertyMapsByName =
		new HashMap<>();
	protected final Map<String, TracePropertyMap<?>> propertyMapsView =
		Collections.unmodifiableMap(propertyMapsByName);

	public DBTraceAddressPropertyManager(DBHandle dbh, DBOpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, Language baseLanguage, DBTrace trace,
			DBTraceThreadManager threadManager) throws VersionException, IOException {
		this.dbh = dbh;
		this.lock = lock;
		this.baseLanguage = baseLanguage;
		this.trace = trace;
		this.threadManager = threadManager;

		DBCachedObjectStoreFactory factory = trace.getStoreFactory();

		propertyStore = factory.getOrCreateCachedStore(DBTraceAddressPropertyEntry.TABLE_NAME,
			DBTraceAddressPropertyEntry.class, DBTraceAddressPropertyEntry::new, true);

		loadPropertyMaps(monitor);
	}

	private void loadPropertyMaps(TaskMonitor monitor) {
		for (DBTraceAddressPropertyEntry ent : propertyStore.asMap().values()) {
			if (ent.map == null) {
				try {
					propertyMapsByName.put(ent.name,
						ent.map = doCreateMap(ent.name, DBOpenMode.UPDATE, ent.getValueClass()));
				}
				catch (Exception e) {
					Msg.error(this, "Cannot load address property " + ent.name, e);
				}
			}
			else {
				propertyMapsByName.put(ent.name, ent.map);
			}
		}
	}

	@SuppressWarnings("unchecked")
	protected <T> AbstractDBTracePropertyMap<T, ?> doCreateMap(String name, DBOpenMode openMode,
			Class<T> valueClass) {
		String tableName = "AddressProperty: " + name;
		try {
			if (valueClass == Integer.class) {
				return (AbstractDBTracePropertyMap<T, ?>) new DBTraceIntPropertyMap(tableName, dbh,
					openMode, lock, TaskMonitor.DUMMY, baseLanguage, trace, threadManager);
			}
			if (valueClass == Long.class) {
				return (AbstractDBTracePropertyMap<T, ?>) new DBTraceLongPropertyMap(tableName, dbh,
					openMode, lock, TaskMonitor.DUMMY, baseLanguage, trace, threadManager);
			}
			if (valueClass == String.class) {
				return (AbstractDBTracePropertyMap<T, ?>) new DBTraceStringPropertyMap(tableName,
					dbh, openMode, lock, TaskMonitor.DUMMY, baseLanguage, trace, threadManager);
			}
			if (valueClass == Void.class) {
				return (AbstractDBTracePropertyMap<T, ?>) new DBTraceVoidPropertyMap(tableName, dbh,
					openMode, lock, TaskMonitor.DUMMY, baseLanguage, trace, threadManager);
			}
			if (Saveable.class.isAssignableFrom(valueClass)) {
				Class<? extends Saveable> saveableClass = valueClass.asSubclass(Saveable.class);
				return (AbstractDBTracePropertyMap<T, ?>) new DBTraceSaveablePropertyMap<>(
					tableName, dbh, openMode, lock, TaskMonitor.DUMMY, baseLanguage, trace,
					threadManager, saveableClass);
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		catch (VersionException e) {
			throw new AssertionError(e);
		}
		throw new IllegalArgumentException("Unsupported value class: " + valueClass);
	}

	@Override
	public <T> AbstractDBTracePropertyMap<T, ?> createPropertyMap(String name, Class<T> valueClass)
			throws DuplicateNameException {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			if (propertyMapsByName.containsKey(name)) {
				throw new DuplicateNameException(name);
			}
			DBTraceAddressPropertyEntry ent = propertyStore.create();
			ent.set(name, valueClass);
			AbstractDBTracePropertyMap<T, ?> map = doCreateMap(name, DBOpenMode.CREATE, valueClass);
			ent.map = map;
			propertyMapsByName.put(name, map);
			return map;
		}
	}

	@Override
	@SuppressWarnings("unchecked")
	public <T> AbstractDBTracePropertyMap<T, ?> getPropertyMap(String name, Class<T> valueClass) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			AbstractDBTracePropertyMap<?, ?> map = propertyMapsByName.get(name);
			if (map == null) {
				return null;
			}
			if (valueClass != map.getValueClass()) {
				throw new TypeMismatchException("Property " + name + " has type " +
					map.getValueClass() + ", not " + valueClass);
			}
			return (AbstractDBTracePropertyMap<T, ?>) map;
		}
	}

	@Override
	public <T> AbstractDBTracePropertyMap<T, ?> getOrCreatePropertyMap(String name,
			Class<T> valueClass) {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			AbstractDBTracePropertyMap<T, ?> map = getPropertyMap(name, valueClass);
			if (map != null) {
				return map;
			}
			try {
				return createPropertyMap(name, valueClass);
			}
			catch (DuplicateNameException e) {
				throw new AssertionError(); // It cannot exist here
			}
		}
	}

	@Override
	@SuppressWarnings("unchecked")
	public <T> TracePropertyMap<? extends T> getPropertyGetter(String name, Class<T> valueClass) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			AbstractDBTracePropertyMap<?, ?> map = propertyMapsByName.get(name);
			if (map == null) {
				return null;
			}
			if (!valueClass.isAssignableFrom(map.getValueClass())) {
				throw new TypeMismatchException("Property " + name + " has type " +
					map.getValueClass() + ", which does not extend " + valueClass);
			}
			return (TracePropertyMap<? extends T>) map;
		}
	}

	@Override
	@SuppressWarnings("unchecked")
	public <T> TracePropertyMap<? super T> getOrCreatePropertySetter(String name,
			Class<T> valueClass) {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			AbstractDBTracePropertyMap<?, ?> map = propertyMapsByName.get(name);
			if (map == null) {
				try {
					// TODO: This is not ideal
					return createPropertyMap(name, valueClass);
				}
				catch (DuplicateNameException e) {
					throw new AssertionError(e); // It cannot exist here
				}
			}
			if (!map.getValueClass().isAssignableFrom(valueClass)) {
				throw new TypeMismatchException("Property " + name + " has type " +
					map.getValueClass() + ", which is not a super-type of " + valueClass);
			}
			return (TracePropertyMap<T>) map;
		}
	}

	@Override
	public TracePropertyMap<?> getPropertyMap(String name) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return propertyMapsByName.get(name);
		}
	}

	@Override
	public Map<String, TracePropertyMap<?>> getAllProperties() {
		return propertyMapsView;
	}

	@Override
	public void dbError(IOException e) {
		trace.dbError(e);
	}

	@Override
	public void invalidateCache(boolean all) {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			propertyStore.invalidateCache();
			propertyMapsByName.clear();
			loadPropertyMaps(TaskMonitor.DUMMY);
		}
	}
}
