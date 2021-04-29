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
package ghidra.trace.database.map;

import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.Map.Entry;
import java.util.concurrent.locks.ReadWriteLock;

import com.google.common.collect.Range;

import db.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.lang.Language;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.map.TracePropertyMap;
import ghidra.util.*;
import ghidra.util.database.*;
import ghidra.util.database.DBCachedObjectStoreFactory.AbstractDBFieldCodec;
import ghidra.util.database.annot.*;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractDBTracePropertyMap<T, DR extends AbstractDBTraceAddressSnapRangePropertyMapData<T>>
		extends DBTraceAddressSnapRangePropertyMap<T, DR> implements TracePropertyMap<T> {

	public AbstractDBTracePropertyMap(String name, DBHandle dbh, DBOpenMode openMode,
			ReadWriteLock lock, TaskMonitor monitor, Language baseLanguage, DBTrace trace,
			DBTraceThreadManager threadManager, Class<DR> dataType,
			DBTraceAddressSnapRangePropertyMapDataFactory<T, DR> dataFactory)
			throws IOException, VersionException {
		super(name, dbh, openMode, lock, monitor, baseLanguage, trace, threadManager, dataType,
			dataFactory);
	}

	@SuppressWarnings("unchecked")
	protected void makeWay(Entry<TraceAddressSnapRange, T> entry, Range<Long> span) {
		// TODO: Would rather not rely on implementation knowledge here
		// The shape is the database record in AbstracctDBTraceAddressSnapRangePropertyMapData
		makeWay((DR) entry.getKey(), span);
	}

	protected void makeWay(DR data, Range<Long> span) {
		DBTraceUtils.makeWay(data, span, (d, s) -> d.doSetLifespan(s), d -> deleteData(d));
		// TODO: Any events?
	}

	@Override
	public void set(Range<Long> lifespan, Address address, T value) {
		// NOTE: No null -> clear, so that Void properties make sense
		put(address, lifespan, value);
	}

	@Override
	public T get(long snap, Address address) {
		return reduce(TraceAddressSnapRangeQuery.at(address, snap)).firstValue();
	}

	@Override
	public void clear(Range<Long> span, AddressRange range) {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			for (Entry<TraceAddressSnapRange, T> entry : reduce(
				TraceAddressSnapRangeQuery.intersecting(range, span)).entries()) {
				makeWay(entry, span);
			}
		}
	}

	@Override
	public T put(TraceAddressSnapRange shape, T value) {
		assert shape.getRange().getLength() == 1;
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			for (Entry<TraceAddressSnapRange, T> entry : reduce(
				TraceAddressSnapRangeQuery.intersecting(shape)).entries()) {
				makeWay(entry, shape.getLifespan());
			}
			return super.put(shape, value);
		}
	}

	public static class DBTraceIntPropertyMap
			extends AbstractDBTracePropertyMap<Integer, DBTraceIntPropertyMapEntry> {

		public DBTraceIntPropertyMap(String name, DBHandle dbh, DBOpenMode openMode,
				ReadWriteLock lock, TaskMonitor monitor, Language baseLanguage, DBTrace trace,
				DBTraceThreadManager threadManager) throws IOException, VersionException {
			super(name, dbh, openMode, lock, monitor, baseLanguage, trace, threadManager,
				DBTraceIntPropertyMapEntry.class, DBTraceIntPropertyMapEntry::new);
		}

		@Override
		public Class<Integer> getValueClass() {
			return Integer.class;
		}
	}

	@DBAnnotatedObjectInfo(version = 0)
	public static class DBTraceIntPropertyMapEntry
			extends AbstractDBTraceAddressSnapRangePropertyMapData<Integer> {
		static final String VALUE_COLUMN_NAME = "Value";

		@DBAnnotatedColumn(VALUE_COLUMN_NAME)
		static DBObjectColumn VALUE_COLUMN;

		@DBAnnotatedField(column = VALUE_COLUMN_NAME)
		int value;

		public DBTraceIntPropertyMapEntry(DBTraceAddressSnapRangePropertyMapTree<Integer, ?> tree,
				DBCachedObjectStore<?> store, DBRecord record) {
			super(tree, store, record);
		}

		@Override
		protected void setRecordValue(Integer value) {
			assert value != null;
			this.value = value;
			update(VALUE_COLUMN);
		}

		@Override
		protected Integer getRecordValue() {
			return value;
		}
	}

	public static class DBTraceLongPropertyMap
			extends AbstractDBTracePropertyMap<Long, DBTraceLongPropertyMapEntry> {

		public DBTraceLongPropertyMap(String name, DBHandle dbh, DBOpenMode openMode,
				ReadWriteLock lock, TaskMonitor monitor, Language baseLanguage, DBTrace trace,
				DBTraceThreadManager threadManager) throws IOException, VersionException {
			super(name, dbh, openMode, lock, monitor, baseLanguage, trace, threadManager,
				DBTraceLongPropertyMapEntry.class, DBTraceLongPropertyMapEntry::new);
		}

		@Override
		public Class<Long> getValueClass() {
			return Long.class;
		}
	}

	@DBAnnotatedObjectInfo(version = 0)
	public static class DBTraceLongPropertyMapEntry
			extends AbstractDBTraceAddressSnapRangePropertyMapData<Long> {
		static final String VALUE_COLUMN_NAME = "Value";

		@DBAnnotatedColumn(VALUE_COLUMN_NAME)
		static DBObjectColumn VALUE_COLUMN;

		@DBAnnotatedField(column = VALUE_COLUMN_NAME)
		long value;

		public DBTraceLongPropertyMapEntry(DBTraceAddressSnapRangePropertyMapTree<Long, ?> tree,
				DBCachedObjectStore<?> store, DBRecord record) {
			super(tree, store, record);
		}

		@Override
		protected void setRecordValue(Long value) {
			assert value != null;
			this.value = value;
			update(VALUE_COLUMN);
		}

		@Override
		protected Long getRecordValue() {
			return value;
		}
	}

	public static class DBTraceSaveablePropertyMap<T extends Saveable>
			extends AbstractDBTracePropertyMap<T, DBTraceSaveablePropertyMapEntry<T>> {

		protected final Class<T> valueClass;

		@SuppressWarnings({ "rawtypes", "unchecked" })
		protected static <T extends Saveable> Class<DBTraceSaveablePropertyMapEntry<T>> getEntryClass(
				Class<T> valueClass) {
			return (Class) DBTraceSaveablePropertyMapEntry.class;
		}

		public DBTraceSaveablePropertyMap(String name, DBHandle dbh, DBOpenMode openMode,
				ReadWriteLock lock, TaskMonitor monitor, Language baseLanguage, DBTrace trace,
				DBTraceThreadManager threadManager, Class<T> valueClass)
				throws IOException, VersionException {
			super(name, dbh, openMode, lock, monitor, baseLanguage, trace, threadManager,
				getEntryClass(valueClass),
				(t, s, r) -> new DBTraceSaveablePropertyMapEntry<>(t, s, r, valueClass));
			this.valueClass = valueClass;
		}

		@Override
		public Class<T> getValueClass() {
			return valueClass;
		}
	}

	@DBAnnotatedObjectInfo(version = 0)
	public static class DBTraceSaveablePropertyMapEntry<T extends Saveable>
			extends AbstractDBTraceAddressSnapRangePropertyMapData<T> {
		static final String VALUE_COLUMN_NAME = "Value";

		@DBAnnotatedColumn(VALUE_COLUMN_NAME)
		static DBObjectColumn VALUE_COLUMN;

		@DBAnnotatedField(column = VALUE_COLUMN_NAME, codec = SaveableDBFieldCodec.class)
		T value;

		protected Class<T> valueClass;

		public DBTraceSaveablePropertyMapEntry(DBTraceAddressSnapRangePropertyMapTree<T, ?> tree,
				DBCachedObjectStore<?> store, DBRecord record, Class<T> valueClass) {
			super(tree, store, record);
			this.valueClass = valueClass;
		}

		@Override
		protected void setRecordValue(T value) {
			assert value != null;
			this.value = value;
			update(VALUE_COLUMN);
		}

		@Override
		protected T getRecordValue() {
			return value;
		}
	}

	public static class SaveableDBFieldCodec extends
			AbstractDBFieldCodec<Saveable, DBTraceSaveablePropertyMapEntry<?>, BinaryField> {

		public SaveableDBFieldCodec(Class<DBTraceSaveablePropertyMapEntry<?>> objectType,
				Field field, int column) {
			super(Saveable.class, objectType, BinaryField.class, field, column);
		}

		private byte[] encode(Saveable value) throws AssertionError {
			if (value == null) {
				return null;
			}
			try {
				ByteArrayOutputStream os = new ByteArrayOutputStream();
				ObjectStorage objStorage =
					new ObjectStorageStreamAdapter(new ObjectOutputStream(os));
				value.save(objStorage);
				return os.toByteArray();
			}
			catch (IOException e) {
				throw new AssertionError(e); // For a ByteArrayOutputStream?
			}
		}

		@Override
		public void store(Saveable value, BinaryField f) {
			f.setBinaryData(encode(value));
		}

		@Override
		protected void doStore(DBTraceSaveablePropertyMapEntry<?> obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			record.setBinaryData(column, encode(getValue(obj)));
		}

		@Override
		protected void doLoad(DBTraceSaveablePropertyMapEntry<?> obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			byte[] enc = record.getBinaryData(column);
			if (enc == null) {
				setValue(obj, null);
			}
			try {
				Saveable value = getValue(obj);
				if (value == null) {
					value = obj.valueClass.getConstructor().newInstance();
					setValue(obj, value);
				}
				ObjectStorage objStorage = new ObjectStorageStreamAdapter(
					new ObjectInputStream(new ByteArrayInputStream(enc)));
				value.restore(objStorage);
			}
			catch (IOException e) {
				throw new AssertionError(e);
			}
			catch (InstantiationException | InvocationTargetException | SecurityException e) {
				throw new RuntimeException(
					"Could not instantiate saveable of type " + obj.valueClass);
			}
			catch (NoSuchMethodException e) {
				throw new RuntimeException("Saveable must have a default constructor");
			}
		}
	}

	public static class DBTraceStringPropertyMap
			extends AbstractDBTracePropertyMap<String, DBTraceStringPropertyMapEntry> {

		public DBTraceStringPropertyMap(String name, DBHandle dbh, DBOpenMode openMode,
				ReadWriteLock lock, TaskMonitor monitor, Language baseLanguage, DBTrace trace,
				DBTraceThreadManager threadManager) throws IOException, VersionException {
			super(name, dbh, openMode, lock, monitor, baseLanguage, trace, threadManager,
				DBTraceStringPropertyMapEntry.class, DBTraceStringPropertyMapEntry::new);
		}

		@Override
		public Class<String> getValueClass() {
			return String.class;
		}
	}

	@DBAnnotatedObjectInfo(version = 0)
	public static class DBTraceStringPropertyMapEntry
			extends AbstractDBTraceAddressSnapRangePropertyMapData<String> {
		static final String VALUE_COLUMN_NAME = "Value";

		@DBAnnotatedColumn(VALUE_COLUMN_NAME)
		static DBObjectColumn VALUE_COLUMN;

		@DBAnnotatedField(column = VALUE_COLUMN_NAME)
		String value;

		public DBTraceStringPropertyMapEntry(DBTraceAddressSnapRangePropertyMapTree<String, ?> tree,
				DBCachedObjectStore<?> store, DBRecord record) {
			super(tree, store, record);
		}

		@Override
		protected void setRecordValue(String value) {
			assert value != null;
			this.value = value;
			update(VALUE_COLUMN);
		}

		@Override
		protected String getRecordValue() {
			return value;
		}
	}

	public static class DBTraceVoidPropertyMap
			extends AbstractDBTracePropertyMap<Void, DBTraceVoidPropertyMapEntry> {

		public DBTraceVoidPropertyMap(String name, DBHandle dbh, DBOpenMode openMode,
				ReadWriteLock lock, TaskMonitor monitor, Language baseLanguage, DBTrace trace,
				DBTraceThreadManager threadManager) throws IOException, VersionException {
			super(name, dbh, openMode, lock, monitor, baseLanguage, trace, threadManager,
				DBTraceVoidPropertyMapEntry.class, DBTraceVoidPropertyMapEntry::new);
		}

		@Override
		public Class<Void> getValueClass() {
			return Void.class;
		}
	}

	@DBAnnotatedObjectInfo(version = 0)
	public static class DBTraceVoidPropertyMapEntry
			extends AbstractDBTraceAddressSnapRangePropertyMapData<Void> {

		public DBTraceVoidPropertyMapEntry(DBTraceAddressSnapRangePropertyMapTree<Void, ?> tree,
				DBCachedObjectStore<?> store, DBRecord record) {
			super(tree, store, record);
		}

		@Override
		protected void setRecordValue(Void value) {
			// Nothing to do
		}

		@Override
		protected Void getRecordValue() {
			return null;
		}
	}
}
