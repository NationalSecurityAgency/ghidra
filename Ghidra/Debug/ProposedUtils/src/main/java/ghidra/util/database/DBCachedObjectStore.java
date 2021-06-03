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
package ghidra.util.database;

import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;

import com.google.common.collect.BoundType;
import com.google.common.collect.Range;

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.DBObjectCache;
import ghidra.program.model.address.KeyRange;
import ghidra.util.LockHold;
import ghidra.util.database.DBCachedObjectStoreFactory.DBFieldCodec;
import ghidra.util.database.DirectedIterator.Direction;

public class DBCachedObjectStore<T extends DBAnnotatedObject> implements ErrorHandler {
	private static final Comparator<? super Long> KEY_COMPARATOR = Long::compare;

	static <T extends Comparable<T>> Range<T> toRange(T from, boolean fromInclusive, T to,
			boolean toInclusive, Direction direction) {
		if (direction == Direction.FORWARD) {
			return Range.range(from, fromInclusive ? BoundType.CLOSED : BoundType.OPEN, to,
				toInclusive ? BoundType.CLOSED : BoundType.OPEN);
		}
		return Range.range(to, toInclusive ? BoundType.CLOSED : BoundType.OPEN, from,
			fromInclusive ? BoundType.CLOSED : BoundType.OPEN);
	}

	static <T extends Comparable<T>> Range<T> toRangeHead(T to, boolean toInclusive,
			Direction direction) {
		if (direction == Direction.FORWARD) {
			return Range.upTo(to, toInclusive ? BoundType.CLOSED : BoundType.OPEN);
		}
		return Range.downTo(to, toInclusive ? BoundType.CLOSED : BoundType.OPEN);
	}

	static <T extends Comparable<T>> Range<T> toRangeTail(T from, boolean fromInclusive,
			Direction direction) {
		if (direction == Direction.FORWARD) {
			return Range.downTo(from, fromInclusive ? BoundType.CLOSED : BoundType.OPEN);
		}
		return Range.upTo(from, fromInclusive ? BoundType.CLOSED : BoundType.OPEN);
	}

	protected abstract class BoundedStuff<U, V> {
		abstract U fromRecord(DBRecord record) throws IOException;

		abstract U fromObject(T value);

		abstract Long getKey(U of);

		U getMax() throws IOException {
			long max = table.getMaxKey();
			if (max == Long.MIN_VALUE) {
				return null;
			}
			return get(max);
		}

		U getBefore(long key) throws IOException {
			return fromRecord(table.getRecordBefore(key));
		}

		U getBefore(long key, Range<Long> keyRange) throws IOException {
			if (!keyRange.hasUpperBound() || key <= keyRange.upperEndpoint()) {
				return filter(getBefore(key), keyRange);
			}
			else if (keyRange.upperBoundType() == BoundType.CLOSED) {
				return filter(getAtOrBefore(keyRange.upperEndpoint()), keyRange);
			}
			else {
				return filter(getBefore(keyRange.upperEndpoint()), keyRange);
			}
		}

		U getAtOrBefore(long key) throws IOException {
			return fromRecord(table.getRecordAtOrBefore(key));
		}

		U getAtOrBefore(long key, Range<Long> keyRange) throws IOException {
			if (!keyRange.hasUpperBound() || key < keyRange.upperEndpoint()) {
				return filter(getAtOrBefore(key), keyRange);
			}
			else if (keyRange.upperBoundType() == BoundType.CLOSED) {
				return filter(getAtOrBefore(keyRange.upperEndpoint()), keyRange);
			}
			else {
				return filter(getBefore(keyRange.upperEndpoint()), keyRange);
			}
		}

		U get(long key) throws IOException {
			T cached = cache.get(key);
			if (cached != null) {
				return fromObject(cached);
			}
			return fromRecord(table.getRecord(key));
		}

		U getAtOrAfter(long key) throws IOException {
			return fromRecord(table.getRecordAtOrAfter(key));
		}

		U getAtOrAfter(long key, Range<Long> keyRange) throws IOException {
			if (!keyRange.hasLowerBound() || key > keyRange.lowerEndpoint()) {
				return filter(getAtOrAfter(key), keyRange);
			}
			else if (keyRange.lowerBoundType() == BoundType.CLOSED) {
				return filter(getAtOrAfter(keyRange.lowerEndpoint()), keyRange);
			}
			else {
				return filter(getAfter(keyRange.lowerEndpoint()), keyRange);
			}
		}

		U getAfter(long key) throws IOException {
			return fromRecord(table.getRecordAfter(key));
		}

		U getAfter(long key, Range<Long> keyRange) throws IOException {
			if (!keyRange.hasLowerBound() || key >= keyRange.lowerEndpoint()) {
				return filter(getAfter(key), keyRange);
			}
			else if (keyRange.lowerBoundType() == BoundType.CLOSED) {
				return filter(getAtOrAfter(keyRange.lowerEndpoint()), keyRange);
			}
			else {
				return filter(getAfter(keyRange.lowerEndpoint()), keyRange);
			}
		}

		abstract U checkAndConvert(Object o);

		abstract boolean typedContains(U u) throws IOException;

		boolean contains(Object o) throws IOException {
			U u = checkAndConvert(o);
			if (u == null) {
				return false;
			}
			return typedContains(u);
		}

		boolean contains(Object o, Range<Long> keyRange) throws IOException {
			U u = checkAndConvert(o);
			if (u == null) {
				return false;
			}
			if (!keyRange.contains(getKey(u))) {
				return false;
			}
			return typedContains(u);
		}

		boolean containsAll(Collection<?> c) throws IOException {
			for (Object o : c) {
				if (!contains(o)) {
					return false;
				}
			}
			return true;
		}

		boolean containsAll(Collection<?> c, Range<Long> keyRange) throws IOException {
			for (Object o : c) {
				if (!contains(o, keyRange)) {
					return false;
				}
			}
			return true;
		}

		abstract T typedRemove(U u) throws IOException;

		boolean remove(Object o) throws IOException {
			U u = checkAndConvert(o);
			if (u == null) {
				return false;
			}
			return typedRemove(u) != null;
		}

		boolean remove(Object o, Range<Long> keyRange) throws IOException {
			U u = checkAndConvert(o);
			if (u == null) {
				return false;
			}
			if (!keyRange.contains(getKey(u))) {
				return false;
			}
			return typedRemove(u) != null;
		}

		boolean removeAll(Collection<?> c) throws IOException {
			boolean result = false;
			for (Object o : c) {
				result |= remove(o);
			}
			return result;
		}

		boolean removeAll(Collection<?> c, Range<Long> keyRange) throws IOException {
			boolean result = false;
			for (Object o : c) {
				result |= remove(o, keyRange);
			}
			return result;
		}

		U filter(U candidate, Range<Long> keyRange) {
			if (candidate == null || !keyRange.contains(getKey(candidate))) {
				return null;
			}
			return candidate;
		}

		U first() throws IOException {
			return getAtOrAfter(Long.MIN_VALUE);
		}

		U first(Range<Long> keyRange) throws IOException {
			if (!keyRange.hasLowerBound()) {
				return filter(first(), keyRange);
			}
			else if (keyRange.lowerBoundType() == BoundType.CLOSED) {
				return filter(getAtOrAfter(keyRange.lowerEndpoint()), keyRange);
			}
			else {
				return filter(getAfter(keyRange.lowerEndpoint()), keyRange);
			}
		}

		U first(Direction direction) throws IOException {
			if (direction == Direction.FORWARD) {
				return first();
			}
			return last();
		}

		U first(Direction direction, Range<Long> keyRange) throws IOException {
			if (direction == Direction.FORWARD) {
				return first(keyRange);
			}
			return last(keyRange);
		}

		U last() throws IOException {
			return getMax();
		}

		U last(Range<Long> keyRange) throws IOException {
			if (!keyRange.hasUpperBound()) {
				return filter(last(), keyRange);
			}
			else if (keyRange.upperBoundType() == BoundType.CLOSED) {
				return filter(getAtOrBefore(keyRange.upperEndpoint()), keyRange);
			}
			else {
				return filter(getBefore(keyRange.upperEndpoint()), keyRange);
			}
		}

		U last(Direction direction) throws IOException {
			if (direction == Direction.FORWARD) {
				return last();
			}
			return first();
		}

		U last(Direction direction, Range<Long> keyRange) throws IOException {
			if (direction == Direction.FORWARD) {
				return last(keyRange);
			}
			return first(keyRange);
		}

		U lower(Direction direction, long key) throws IOException {
			if (direction == Direction.FORWARD) {
				return getBefore(key);
			}
			return getAfter(key);
		}

		U lower(Direction direction, long key, Range<Long> keyRange) throws IOException {
			if (direction == Direction.FORWARD) {
				return getBefore(key, keyRange);
			}
			return getAfter(key, keyRange);
		}

		U floor(Direction direction, long key) throws IOException {
			if (direction == Direction.FORWARD) {
				return getAtOrBefore(key);
			}
			return getAtOrAfter(key);
		}

		U floor(Direction direction, long key, Range<Long> keyRange) throws IOException {
			if (direction == Direction.FORWARD) {
				return getAtOrBefore(key, keyRange);
			}
			return getAtOrAfter(key, keyRange);
		}

		U ceiling(Direction direction, long key) throws IOException {
			if (direction == Direction.FORWARD) {
				return getAtOrAfter(key);
			}
			return getAtOrBefore(key);
		}

		U ceiling(Direction direction, long key, Range<Long> keyRange) throws IOException {
			if (direction == Direction.FORWARD) {
				return getAtOrAfter(key, keyRange);
			}
			return getAtOrBefore(key, keyRange);
		}

		U higher(Direction direction, long key) throws IOException {
			if (direction == Direction.FORWARD) {
				return getAfter(key);
			}
			return getBefore(key);
		}

		U higher(Direction direction, long key, Range<Long> keyRange) throws IOException {
			if (direction == Direction.FORWARD) {
				return getAfter(key, keyRange);
			}
			return getBefore(key, keyRange);
		}

		abstract DirectedIterator<V> rawIterator(Direction direction, Range<Long> keyRange)
				throws IOException;

		abstract U fromRaw(V raw) throws IOException;

		Iterator<U> iterator(DirectedIterator<V> it) {
			return new Iterator<>() {
				@Override
				public boolean hasNext() {
					try (LockHold hold = LockHold.lock(lock.readLock())) {
						return it.hasNext();
					}
					catch (IOException e) {
						adapter.dbError(e);
						return false;
					}
				}

				@Override
				public U next() {
					try (LockHold hold = LockHold.lock(lock.readLock())) {
						return fromRaw(it.next());
					}
					catch (IOException e) {
						adapter.dbError(e);
						return null;
					}
				}

				@Override
				public void remove() {
					try (LockHold hold = LockHold.lock(lock.writeLock())) {
						it.delete();
					}
					catch (IOException e) {
						adapter.dbError(e);
					}
				}
			};
		}

		Iterator<U> iterator(Direction direction, Range<Long> keyRange) {
			if (keyRange != null && keyRange.isEmpty()) {
				return Collections.emptyIterator();
			}
			try (LockHold hold = LockHold.lock(lock.readLock())) {
				return iterator(rawIterator(direction, keyRange));
			}
			catch (IOException e) {
				adapter.dbError(e);
				return null;
			}
		}

		void intoArray(U[] arr, Direction direction, Range<Long> keyRange) {
			if (keyRange != null && keyRange.isEmpty()) {
				return;
			}
			try (LockHold hold = LockHold.lock(lock.readLock())) {
				DirectedIterator<V> it = rawIterator(direction, keyRange);
				for (int i = 0; it.hasNext(); i++) {
					arr[i] = fromRaw(it.next());
				}
			}
			catch (IOException e) {
				adapter.dbError(e);
			}
		}

		void toList(List<? super U> list, Direction direction, Range<Long> keyRange) {
			if (keyRange != null && keyRange.isEmpty()) {
				return;
			}
			try (LockHold hold = LockHold.lock(lock.readLock())) {
				DirectedIterator<V> it = rawIterator(direction, keyRange);
				while (it.hasNext()) {
					list.add(fromRaw(it.next()));
				}
			}
			catch (IOException e) {
				adapter.dbError(e);
			}
		}

		Object[] toArray(Direction direction, Range<Long> keyRange) {
			ArrayList<U> list = new ArrayList<>();
			toList(list, direction, keyRange);
			return list.toArray();
		}

		/*
		 * Not the most efficient implementation. Computing size may require a full iteration before
		 * the actual copy iterator.
		 */
		@SuppressWarnings("unchecked")
		public <W> W[] toArray(Direction direction, Range<Long> keyRange, W[] a, int size) {
			final List<Object> list;
			if (a.length < size) {
				list = new ArrayList<>();
				toList(list, direction, keyRange);
				return list.toArray(a);
			}
			intoArray((U[]) a, direction, keyRange);
			for (int i = size; i < a.length; i++) {
				a[i] = null;
			}
			return a;
		}

		boolean retain(Collection<?> c, Range<Long> keyRange) {
			if (keyRange != null && keyRange.isEmpty()) {
				return false;
			}
			boolean result = false;
			try (LockHold hold = LockHold.lock(lock.writeLock())) {
				DirectedIterator<V> it = rawIterator(Direction.FORWARD, keyRange);
				while (it.hasNext()) {
					U u = fromRaw(it.next());
					if (!c.contains(u)) {
						it.delete();
						cache.delete(getKey(u));
						result = true;
					}
				}
			}
			catch (IOException e) {
				adapter.dbError(e);
			}
			return result;
		}
	}

	protected final BoundedStuff<Long, Long> keys = new BoundedStuff<>() {
		@Override
		Long fromRecord(DBRecord record) {
			if (record == null) {
				return null;
			}
			return record.getKey();
		}

		@Override
		Long fromObject(T value) {
			throw new AssertionError(); // Only used by get, overridden here
		}

		@Override
		Long getKey(Long of) {
			return of;
		}

		@Override
		Long getMax() {
			long max = table.getMaxKey();
			if (max == Long.MIN_VALUE) {
				return null;
			}
			return max;
		}

		@Override
		Long get(long key) {
			throw new AssertionError();
		}

		@Override
		Long checkAndConvert(Object o) {
			if (!(o instanceof Long)) {
				return null;
			}
			return (Long) o;
		}

		@Override
		boolean typedContains(Long u) throws IOException {
			if (cache.get(u) != null) {
				return true;
			}
			return table.hasRecord(u);
		}

		@Override
		T typedRemove(Long u) throws IOException {
			T in = objects.get(u);
			if (in == null) {
				return null;
			}
			table.deleteRecord(u);
			cache.delete(u);
			return in;
		}

		@Override
		DirectedIterator<Long> rawIterator(Direction direction, Range<Long> keyRange)
				throws IOException {
			return DirectedLongKeyIterator.getIterator(table, keyRange, direction);
		}

		@Override
		Long fromRaw(Long raw) {
			return raw;
		}
	};

	protected final BoundedStuff<T, DBRecord> objects = new BoundedStuff<>() {
		@Override
		T fromRecord(DBRecord record) throws IOException {
			if (record == null) {
				return null;
			}
			T cached = cache.get(record);
			if (cached != null) {
				return cached;
			}
			T found = factory.create(DBCachedObjectStore.this, record);
			found.doRefresh(record);
			return found;
		}

		@Override
		T fromObject(T value) {
			return value;
		}

		@Override
		Long getKey(T of) {
			return of.getKey();
		}

		@Override
		T checkAndConvert(Object o) {
			if (!objectType.isInstance(o)) {
				return null;
			}
			return objectType.cast(o);
		}

		@Override
		boolean typedContains(T u) throws IOException {
			T in = objects.get(u.getKey());
			return u == in; // NOTE: Using object identity on purpose
		}

		@Override
		T typedRemove(T u) throws IOException {
			long key = u.getKey();
			T in = get(key);
			if (u != in) {
				return null;
			}
			table.deleteRecord(key);
			cache.delete(key);
			return in;
		}

		@Override
		DirectedIterator<DBRecord> rawIterator(Direction direction, Range<Long> keyRange)
				throws IOException {
			return DirectedRecordIterator.getIterator(table, keyRange, direction);
		}

		@Override
		T fromRaw(DBRecord raw) throws IOException {
			return fromRecord(raw);
		}
	};

	protected final BoundedStuff<Entry<Long, T>, DBRecord> entries = new BoundedStuff<>() {
		@Override
		Entry<Long, T> fromRecord(DBRecord record) throws IOException {
			if (record == null) {
				return null;
			}
			return ImmutablePair.of(record.getKey(), objects.fromRecord(record));
		}

		@Override
		Entry<Long, T> fromObject(T value) {
			return ImmutablePair.of(value.getKey(), value);
		}

		@Override
		Long getKey(Entry<Long, T> of) {
			return of.getKey();
		}

		@Override
		@SuppressWarnings("unchecked")
		Entry<Long, T> checkAndConvert(Object o) {
			if (!(o instanceof Entry)) {
				return null;
			}
			Entry<?, ?> ent = (Entry<?, ?>) o;
			Object ko = ent.getKey();
			if (!(ko instanceof Long)) {
				return null;
			}
			T val = objects.checkAndConvert(ent.getValue());
			if (val == null) {
				return null;
			}
			return (Entry<Long, T>) ent;
		}

		@Override
		boolean typedContains(Entry<Long, T> u) throws IOException {
			if (u.getKey() != u.getValue().getKey()) {
				return false;
			}
			return objects.typedContains(u.getValue());
		}

		@Override
		T typedRemove(Entry<Long, T> u) throws IOException {
			if (u.getKey() != u.getValue().getKey()) {
				return null;
			}
			return objects.typedRemove(u.getValue());
		}

		@Override
		DirectedIterator<DBRecord> rawIterator(Direction direction, Range<Long> keyRange)
				throws IOException {
			return DirectedRecordIterator.getIterator(table, keyRange, direction);
		}

		@Override
		Entry<Long, T> fromRaw(DBRecord raw) throws IOException {
			return fromRecord(raw);
		}
	};

	final DBCachedDomainObjectAdapter adapter;
	final DBHandle dbh;
	final DBObjectCache<T> cache;
	private final Class<T> objectType;
	private final DBAnnotatedObjectFactory<T> factory;
	private final String tableName;
	private final Schema schema;
	private final ReadWriteLock lock;

	protected final DBCachedObjectStoreMap<T> asForwardMap;
	protected final DBCachedObjectStoreKeySet asForwardKeySet;
	protected final DBCachedObjectStoreValueCollection<T> asForwardValueCollection;
	protected final DBCachedObjectStoreEntrySet<T> asForwardEntrySet;
	protected final List<DBFieldCodec<?, T, ?>> codecs;

	Table table;

	public DBCachedObjectStore(DBCachedDomainObjectAdapter adapter, Class<T> objectType,
			DBAnnotatedObjectFactory<T> factory, Table table) {
		this.adapter = adapter;
		this.dbh = adapter.getDBHandle();
		this.objectType = objectType;
		this.factory = factory;
		this.table = table;
		this.tableName = table.getName();
		this.schema = table.getSchema();
		this.cache = new DBObjectCache<>(1000); // TODO: Parameterize this?
		this.lock = adapter.getReadWriteLock();
		this.codecs = DBCachedObjectStoreFactory.getCodecs(objectType);

		this.asForwardMap = new DBCachedObjectStoreMap<>(this, adapter, lock, Direction.FORWARD);
		this.asForwardKeySet =
			new DBCachedObjectStoreKeySet(this, adapter, lock, Direction.FORWARD);
		this.asForwardValueCollection =
			new DBCachedObjectStoreValueCollection<>(this, adapter, lock, Direction.FORWARD);
		this.asForwardEntrySet =
			new DBCachedObjectStoreEntrySet<>(this, adapter, lock, Direction.FORWARD);
	}

	/**
	 * Get the number of objects (records) in this store
	 * 
	 * @return the record count
	 */
	public int getRecordCount() {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return table.getRecordCount();
		}
	}

	/**
	 * Get the maximum key which has ever existed in this store
	 * 
	 * Note, the key need not actually be present
	 * 
	 * @return the maximum, or null if the store is unused
	 */
	public Long getMaxKey() {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			long max = table.getMaxKey();
			if (max == Long.MIN_VALUE) {
				return null;
			}
			return max;
		}
	}

	/**
	 * Count the number of keys in a given range.
	 * 
	 * This implementation is not very efficient. It must visit at least every record in the range.
	 * 
	 * @param keyRange the range of keys
	 * @return the count of records whose keys fall within the range
	 */
	protected int getKeyCount(Range<Long> keyRange) {
		if (keyRange.isEmpty()) {
			return 0;
		}
		int i = 0;
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			if (!keyRange.hasLowerBound() && !keyRange.hasUpperBound()) {
				throw new AssertionError(); // keyRange should never be "all"
			}
			DirectedLongKeyIterator it =
				DirectedLongKeyIterator.getIterator(table, keyRange, Direction.FORWARD);
			while (it.hasNext()) {
				it.next();
				i++;
			}
		}
		catch (IOException e) {
			adapter.dbError(e);
		}
		return i;
	}

	/**
	 * Check if any keys exist within the given range.
	 * 
	 * This implementation is more efficient than using {@link #getKeyCount(Range)} and comparing to
	 * 0, since there's no need to visit more than one record in the range.
	 * 
	 * @param keyRange the range of keys
	 * @return true if at least one record has a key within the range
	 */
	protected boolean getKeysExist(Range<Long> keyRange) {
		if (keyRange.isEmpty()) {
			return false;
		}
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			if (!keyRange.hasLowerBound() && !keyRange.hasUpperBound()) {
				throw new AssertionError(); // keyRange should never be "all"
			}
			final DBRecord rec;
			if (!keyRange.hasLowerBound()) {
				rec = table.getRecordAtOrAfter(Long.MIN_VALUE);
			}
			else if (keyRange.lowerBoundType() == BoundType.CLOSED) {
				rec = table.getRecordAtOrAfter(keyRange.lowerEndpoint());
			}
			else {
				rec = table.getRecordAfter(keyRange.lowerEndpoint());
			}
			if (rec == null) {
				return false;
			}
			return keyRange.contains(rec.getKey());
		}
		catch (IOException e) {
			adapter.dbError(e);
			return false;
		}
	}

	public boolean containsKey(long key) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return keys.typedContains(key);
		}
		catch (IOException e) {
			adapter.dbError(e);
			return false;
		}
	}

	public boolean contains(T obj) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return objects.typedContains(obj);
		}
		catch (IOException e) {
			adapter.dbError(e);
			return false;
		}
	}

	protected T doCreate(long key) throws IOException {
		DBRecord rec = schema.createRecord(key);
		table.putRecord(rec);
		T created = factory.create(this, rec);
		created.fresh(true);
		created.doUpdateAll();
		return created;
	}

	/**
	 * Create a new object with the given key.
	 * 
	 * If the key already exists in the table, the existing record is overwritten.
	 * 
	 * @param key the key for the new object
	 * @return the new object
	 */
	public T create(long key) {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			return doCreate(key);
		}
		catch (IOException e) {
			adapter.dbError(e);
			return null;
		}
	}

	/**
	 * Create a new object with the next available key.
	 * 
	 * @return the new object
	 */
	public T create() {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			return doCreate(table.getKey());
		}
		catch (IOException e) {
			adapter.dbError(e);
			return null;
		}
	}

	protected int getColumnByName(String name) {
		int index = ArrayUtils.indexOf(schema.getFieldNames(), name);
		if (index < 0) {
			throw new NoSuchElementException(name);
		}
		return index;
	}

	protected <K> DBCachedObjectIndex<K, T> getIndex(Class<K> valueType, int columnIndex) {
		if (!ArrayUtils.contains(table.getIndexedColumns(), columnIndex)) {
			throw new IllegalArgumentException(
				"Column " + schema.getFieldNames()[columnIndex] + " is not indexed");
		}

		DBFieldCodec<?, T, ?> codec = codecs.get(columnIndex);
		Class<?> exp = codec.getValueType();
		if (valueType != exp) {
			throw new IllegalArgumentException("Column " + schema.getFieldNames()[columnIndex] +
				" is not of type " + valueType + "! It is " + exp);
		}
		@SuppressWarnings("unchecked")
		DBFieldCodec<K, T, ?> castCodec = (DBFieldCodec<K, T, ?>) codec;
		return new DBCachedObjectIndex<>(this, adapter, castCodec, columnIndex, Range.all(),
			Direction.FORWARD);
	}

	public <K> DBCachedObjectIndex<K, T> getIndex(Class<K> fieldClass, DBObjectColumn column) {
		return getIndex(fieldClass, column.columnNumber);
	}

	public <K> DBCachedObjectIndex<K, T> getIndex(Class<K> fieldClass, String columnName) {
		int columnIndex = getColumnByName(columnName);
		return getIndex(fieldClass, columnIndex);
	}

	public boolean delete(T obj) {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			return objects.typedRemove(obj) != null;
		}
		catch (IOException e) {
			adapter.dbError(e);
			return false;
		}
	}

	public T deleteKey(long key) {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			return keys.typedRemove(key);
		}
		catch (IOException e) {
			adapter.dbError(e);
			return null;
		}
	}

	public void deleteAll() {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			table.deleteAll();
			cache.invalidate();
		}
		catch (IOException e) {
			adapter.dbError(e);
		}
	}

	/**
	 * TODO: Consider using {@link KeyRange} internally, instead of {@link Range}, esp., as we break
	 * our dependency on guava.
	 */
	protected void deleteKeys(Range<Long> keyRange) {
		if (keyRange.isEmpty()) {
			return;
		}
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			long min = DirectedIterator.toIteratorMin(keyRange);
			long max = DirectedIterator.toIteratorMax(keyRange);
			table.deleteRecords(min, max);
			cache.delete(List.of(new KeyRange(min, max)));
		}
		catch (IOException e) {
			adapter.dbError(e);
		}
	}

	protected interface SupplierAllowsIOException<U> {
		U get() throws IOException;
	}

	protected <U> U safe(Lock l, SupplierAllowsIOException<U> supplier) {
		try (LockHold hold = LockHold.lock(l)) {
			return supplier.get();
		}
		catch (IOException e) {
			adapter.dbError(e);
			return null;
		}
	}

	public T getObjectAt(long key) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return objects.get(key);
		}
		catch (IOException e) {
			adapter.dbError(e);
			return null;
		}
	}

	protected Comparator<? super Long> keyComparator() {
		return KEY_COMPARATOR;
	}

	public DBCachedObjectStoreMap<T> asMap() {
		return asForwardMap;
	}

	protected T findOneObject(int columnIndex, Field field) throws IOException {
		// TODO: Support non-long keys, eventually.
		Field[] found = table.findRecords(field, columnIndex);
		if (found.length == 0) {
			return null;
		}
		if (found.length != 1) {
			throw new IllegalStateException("More than one match");
		}
		return getObjectAt(found[0].getLongValue());
	}

	protected DBCachedObjectStoreFoundKeysValueCollection<T> findObjects(int columnIndex,
			Field field) throws IOException {
		Field[] found = table.findRecords(field, columnIndex);
		return new DBCachedObjectStoreFoundKeysValueCollection<>(this, adapter, lock, found);
	}

	protected Iterator<T> iterator(int columnIndex, Range<Field> fieldRange, Direction direction)
			throws IOException {
		DirectedRecordIterator it =
			DirectedRecordIterator.getIndexIterator(table, columnIndex, fieldRange, direction);
		return objects.iterator(it);
	}

	boolean isCached(long key) {
		return cache.get(key) != null;
	}

	public Lock readLock() {
		return lock.readLock();
	}

	public Lock writeLock() {
		return lock.writeLock();
	}

	public ReadWriteLock getLock() {
		return lock;
	}

	@Override
	public void dbError(IOException e) {
		adapter.dbError(e);
	}

	/**
	 * Display useful information about this cached store
	 * 
	 * Please avoid calling this except for debugging.
	 * 
	 * @return a string representation of the store's cache
	 */
	@Override
	public String toString() {
		StringBuilder builder =
			new StringBuilder("DBCachedObjectStore of " + objectType + ". Cache: ");
		builder.append(StringUtils.join(cache.getCachedObjects(), ", "));
		return builder.toString();
	}

	public void invalidateCache() {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			cache.invalidate();
			table = dbh.getTable(tableName);
			assert schema.equals(table.getSchema());
		}
	}
}
