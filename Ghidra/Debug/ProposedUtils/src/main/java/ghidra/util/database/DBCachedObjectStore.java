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
import java.util.function.Supplier;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.DBObjectCache;
import ghidra.program.model.address.KeyRange;
import ghidra.util.LockHold;
import ghidra.util.database.DBCachedObjectStoreFactory.DBFieldCodec;
import ghidra.util.database.DirectedIterator.Direction;
import ghidra.util.database.annot.DBAnnotatedField;

/**
 * An object store backed by a {@link db.Table}
 *
 * <p>
 * Essentially, this provides object-based accessed to records in the table via DAOs. See
 * {@link DBAnnotatedObject} for further documentation including an example object definition. The
 * store keeps a cache of objects using {@link DBObjectCache}. See
 * {@link DBCachedObjectStoreFactory} for documentation describing how to create a store, including
 * for the example object definition.
 * 
 * <p>
 * The store provides views for locating, iterating, and retrieving its objects in a variety of
 * fashions. This includes the primary key (object id), or any indexed column (see
 * {@link DBAnnotatedField#indexed()}). These views generally implement an interface from Java's
 * Collections API, providing for familiar semantics. A notable exception is that none of the
 * interfaces support mutation, aside from deletion. The store is populated only via the
 * {@link #create()} methods.
 * 
 * @param <T> the type of objects stored
 */
public class DBCachedObjectStore<T extends DBAnnotatedObject> implements ErrorHandler {
	private static final Comparator<? super Long> KEY_COMPARATOR = Long::compare;

	/**
	 * Abstractions for navigating within a given view
	 * 
	 * <p>
	 * Generally, these are all methods that facilitate implementation of a {@link Collection} or
	 * {@link NavigableMap}. The idea is that the abstract methods are required to translate from
	 * various object types and to facilitate table access. This class then provides all the methods
	 * needed to navigate the table with respect to a desired element type. These types will be
	 * those typically exposed as collections by the {@link Map} interface: keys, values, and
	 * entries. The implementations of those collections can then call those methods as needed.
	 *
	 * <p>
	 * The methods are implemented in various groups and with a variety of parameters. The first
	 * group is the abstract methods. The next simply wraps the table's navigations methods to
	 * retrieve elements of the view. Many of these accept an optional range to limit the search or
	 * effect. This is to facilitate the implementation of sub-maps. The next are named after their
	 * counterparts in the navigable interfaces. In addition to the optional range, many of these
	 * take a direction. This is to facilitate the implementation of reversed collections. To best
	 * understand the methods, examine the callers-to tree and see the relevant documentation,
	 * probably in the Java Collections API.
	 *
	 * @param <E> the type of elements exposed by the view
	 * @param <R> the type used to navigate the view's backing
	 */
	protected abstract class BoundedStuff<E, R> {
		/**
		 * Get the element from a given record
		 * 
		 * @param record the table record
		 * @return the element
		 * @throws IOException if there's an issue reading the record
		 */
		abstract E fromRecord(DBRecord record) throws IOException;

		/**
		 * Get the element from a given store object
		 * 
		 * @param value the store object
		 * @return the element
		 */
		abstract E fromObject(T value);

		/**
		 * Get the key of the record backing the given element
		 * 
		 * @param of the element
		 * @return the key
		 */
		abstract Long getKey(E of);

		/**
		 * Check that the object is the expected element type and return it or null
		 * 
		 * <p>
		 * This is needed to implement {@link Collection#contains(Object)} and similar, because its
		 * signature accepts any object. The first step is to type check it. Note that if {@link E}
		 * is parameterized, it's fields may also require type checking.
		 * 
		 * @param o the object whose type to check
		 * @return the object if its type matches an element, or null
		 */
		abstract E checkAndConvert(Object o);

		/**
		 * Check if the given element is contained in the view
		 * 
		 * @param e the element
		 * @return true if contained in the view
		 * @throws IOException if there's an issue reading the table
		 */
		abstract boolean typedContains(E e) throws IOException;

		/**
		 * Remove the given element from the view
		 * 
		 * @param e the element
		 * @return the store object removed or null if no effect
		 * @throws IOException if there's an issue accessing the table
		 */
		abstract T typedRemove(E e) throws IOException;

		/**
		 * Get an iterator over the raw components of the table for the given range
		 * 
		 * @param direction the direction of iteration
		 * @param keySpan the range of keys
		 * @return the iterator
		 * @throws IOException if there's an issue reading the table
		 */
		abstract DirectedIterator<R> rawIterator(Direction direction, KeySpan keySpan)
				throws IOException;

		/**
		 * Convert the raw component to an element
		 * 
		 * @param raw the raw component
		 * @return the element
		 * @throws IOException if there's an issue reading the table
		 */
		abstract E fromRaw(R raw) throws IOException;

		// Utilities

		E filter(E candidate, KeySpan keySpan) {
			if (candidate == null || !keySpan.contains(getKey(candidate))) {
				return null;
			}
			return candidate;
		}

		// Methods which wrap the table's navigation methods

		E getMax() throws IOException {
			long max = table.getMaxKey();
			if (max == Long.MIN_VALUE) {
				return null;
			}
			return get(max);
		}

		E getBefore(long key) throws IOException {
			return fromRecord(table.getRecordBefore(key));
		}

		E getBefore(long key, KeySpan keySpan) throws IOException {
			if (KeySpan.DOMAIN.min() == key) {
				return null;
			}
			long max = KeySpan.DOMAIN.min(keySpan.max(), KeySpan.DOMAIN.dec(key));
			return filter(getAtOrBefore(max), keySpan);
		}

		E getAtOrBefore(long key) throws IOException {
			return fromRecord(table.getRecordAtOrBefore(key));
		}

		E getAtOrBefore(long key, KeySpan keySpan) throws IOException {
			long max = KeySpan.DOMAIN.min(keySpan.max(), key);
			return filter(getAtOrBefore(max), keySpan);
		}

		E get(long key) throws IOException {
			T cached = cache.get(key);
			if (cached != null) {
				return fromObject(cached);
			}
			return fromRecord(table.getRecord(key));
		}

		E getAtOrAfter(long key) throws IOException {
			return fromRecord(table.getRecordAtOrAfter(key));
		}

		E getAtOrAfter(long key, KeySpan keySpan) throws IOException {
			long min = KeySpan.DOMAIN.max(keySpan.min(), key);
			return filter(getAtOrAfter(min), keySpan);
		}

		E getAfter(long key) throws IOException {
			return fromRecord(table.getRecordAfter(key));
		}

		E getAfter(long key, KeySpan keySpan) throws IOException {
			if (KeySpan.DOMAIN.max() == key) {
				return null;
			}
			long min = KeySpan.DOMAIN.max(keySpan.min(), KeySpan.DOMAIN.inc(key));
			return filter(getAtOrAfter(min), keySpan);
		}

		boolean contains(Object o) throws IOException {
			E u = checkAndConvert(o);
			if (u == null) {
				return false;
			}
			return typedContains(u);
		}

		boolean contains(Object o, KeySpan keySpan) throws IOException {
			E u = checkAndConvert(o);
			if (u == null) {
				return false;
			}
			if (!keySpan.contains(getKey(u))) {
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

		boolean containsAll(Collection<?> c, KeySpan keySpan) throws IOException {
			for (Object o : c) {
				if (!contains(o, keySpan)) {
					return false;
				}
			}
			return true;
		}

		boolean remove(Object o) throws IOException {
			E u = checkAndConvert(o);
			if (u == null) {
				return false;
			}
			return typedRemove(u) != null;
		}

		boolean remove(Object o, KeySpan keySpan) throws IOException {
			E u = checkAndConvert(o);
			if (u == null) {
				return false;
			}
			if (!keySpan.contains(getKey(u))) {
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

		boolean removeAll(Collection<?> c, KeySpan keySpan) throws IOException {
			boolean result = false;
			for (Object o : c) {
				result |= remove(o, keySpan);
			}
			return result;
		}

		// Methods for implementing navigable maps and collections

		E first() throws IOException {
			return getAtOrAfter(Long.MIN_VALUE);
		}

		E first(KeySpan keySpan) throws IOException {
			return filter(getAtOrAfter(keySpan.min()), keySpan);
		}

		E first(Direction direction) throws IOException {
			if (direction == Direction.FORWARD) {
				return first();
			}
			return last();
		}

		E first(Direction direction, KeySpan keySpan) throws IOException {
			if (direction == Direction.FORWARD) {
				return first(keySpan);
			}
			return last(keySpan);
		}

		E last() throws IOException {
			return getMax();
		}

		E last(KeySpan keySpan) throws IOException {
			return filter(getAtOrBefore(keySpan.max()), keySpan);
		}

		E last(Direction direction) throws IOException {
			if (direction == Direction.FORWARD) {
				return last();
			}
			return first();
		}

		E last(Direction direction, KeySpan keySpan) throws IOException {
			if (direction == Direction.FORWARD) {
				return last(keySpan);
			}
			return first(keySpan);
		}

		E lower(Direction direction, long key) throws IOException {
			if (direction == Direction.FORWARD) {
				return getBefore(key);
			}
			return getAfter(key);
		}

		E lower(Direction direction, long key, KeySpan keySpan) throws IOException {
			if (direction == Direction.FORWARD) {
				return getBefore(key, keySpan);
			}
			return getAfter(key, keySpan);
		}

		E floor(Direction direction, long key) throws IOException {
			if (direction == Direction.FORWARD) {
				return getAtOrBefore(key);
			}
			return getAtOrAfter(key);
		}

		E floor(Direction direction, long key, KeySpan keySpan) throws IOException {
			if (direction == Direction.FORWARD) {
				return getAtOrBefore(key, keySpan);
			}
			return getAtOrAfter(key, keySpan);
		}

		E ceiling(Direction direction, long key) throws IOException {
			if (direction == Direction.FORWARD) {
				return getAtOrAfter(key);
			}
			return getAtOrBefore(key);
		}

		E ceiling(Direction direction, long key, KeySpan keySpan) throws IOException {
			if (direction == Direction.FORWARD) {
				return getAtOrAfter(key, keySpan);
			}
			return getAtOrBefore(key, keySpan);
		}

		E higher(Direction direction, long key) throws IOException {
			if (direction == Direction.FORWARD) {
				return getAfter(key);
			}
			return getBefore(key);
		}

		E higher(Direction direction, long key, KeySpan keySpan) throws IOException {
			if (direction == Direction.FORWARD) {
				return getAfter(key, keySpan);
			}
			return getBefore(key, keySpan);
		}

		Iterator<E> iterator(DirectedIterator<R> it) {
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
				public E next() {
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

		Iterator<E> iterator(Direction direction, KeySpan keySpan) {
			if (keySpan != null && keySpan.isEmpty()) {
				return Collections.emptyIterator();
			}
			try (LockHold hold = LockHold.lock(lock.readLock())) {
				return iterator(rawIterator(direction, keySpan));
			}
			catch (IOException e) {
				adapter.dbError(e);
				return null;
			}
		}

		void intoArray(E[] arr, Direction direction, KeySpan keySpan) {
			if (keySpan != null && keySpan.isEmpty()) {
				return;
			}
			try (LockHold hold = LockHold.lock(lock.readLock())) {
				DirectedIterator<R> it = rawIterator(direction, keySpan);
				for (int i = 0; it.hasNext(); i++) {
					arr[i] = fromRaw(it.next());
				}
			}
			catch (IOException e) {
				adapter.dbError(e);
			}
		}

		void toList(List<? super E> list, Direction direction, KeySpan keySpan) {
			if (keySpan != null && keySpan.isEmpty()) {
				return;
			}
			try (LockHold hold = LockHold.lock(lock.readLock())) {
				DirectedIterator<R> it = rawIterator(direction, keySpan);
				while (it.hasNext()) {
					list.add(fromRaw(it.next()));
				}
			}
			catch (IOException e) {
				adapter.dbError(e);
			}
		}

		Object[] toArray(Direction direction, KeySpan keySpan) {
			ArrayList<E> list = new ArrayList<>();
			toList(list, direction, keySpan);
			return list.toArray();
		}

		/*
		 * Not the most efficient implementation. Computing size may require a full iteration before
		 * the actual copy iterator.
		 */
		@SuppressWarnings("unchecked")
		public <W> W[] toArray(Direction direction, KeySpan keySpan, W[] a, int size) {
			final List<Object> list;
			if (a.length < size) {
				list = new ArrayList<>();
				toList(list, direction, keySpan);
				return list.toArray(a);
			}
			intoArray((E[]) a, direction, keySpan);
			for (int i = size; i < a.length; i++) {
				a[i] = null;
			}
			return a;
		}

		boolean retain(Collection<?> c, KeySpan keySpan) {
			if (keySpan != null && keySpan.isEmpty()) {
				return false;
			}
			boolean result = false;
			try (LockHold hold = LockHold.lock(lock.writeLock())) {
				DirectedIterator<R> it = rawIterator(Direction.FORWARD, keySpan);
				while (it.hasNext()) {
					E u = fromRaw(it.next());
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

	/**
	 * The implementation of {@link BoundedStuff} to facilitate the implementation of
	 * {@link Map#keySet()}.
	 * 
	 * <p>
	 * Because tables let us navigate keys directly, we use the key as the raw component here
	 * instead of the full record.
	 */
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
		DirectedIterator<Long> rawIterator(Direction direction, KeySpan keySpan)
				throws IOException {
			return DirectedLongKeyIterator.getIterator(table, keySpan, direction);
		}

		@Override
		Long fromRaw(Long raw) {
			return raw;
		}
	};

	/**
	 * The implementation of {@link BoundedStuff} to facilitate the implementation of
	 * {@link Map#values()}.
	 */
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
		DirectedIterator<DBRecord> rawIterator(Direction direction, KeySpan keySpan)
				throws IOException {
			return DirectedRecordIterator.getIterator(table, keySpan, direction);
		}

		@Override
		T fromRaw(DBRecord raw) throws IOException {
			return fromRecord(raw);
		}
	};

	/**
	 * The implementation of {@link BoundedStuff} to facilitate the implementation of
	 * {@link Map#entrySet()}.
	 */
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
		DirectedIterator<DBRecord> rawIterator(Direction direction, KeySpan keySpan)
				throws IOException {
			return DirectedRecordIterator.getIterator(table, keySpan, direction);
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

	/**
	 * Construct a store
	 * 
	 * <p>
	 * Users should instead construct stores using
	 * {@link DBCachedObjectStoreFactory#getOrCreateCachedStore(String, Class, DBAnnotatedObjectFactory, boolean)}.
	 * 
	 * @param adapter the domain object backed by the same database as this store
	 * @param objectType the type of objects stored
	 * @param factory the factory creating this store
	 * @param table the table backing this store
	 */
	protected DBCachedObjectStore(DBCachedDomainObjectAdapter adapter, Class<T> objectType,
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
	 * <p>
	 * Note, the returned key may not actually be present
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
	 * <p>
	 * This implementation is not very efficient. It must visit at least every record in the range.
	 * 
	 * @param keySpan the range of keys
	 * @return the count of records whose keys fall within the range
	 */
	protected int getKeyCount(KeySpan keySpan) {
		if (keySpan.isEmpty()) {
			return 0;
		}
		int i = 0;
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			if (KeySpan.ALL.equals(keySpan)) {
				throw new AssertionError();
			}
			DirectedLongKeyIterator it =
				DirectedLongKeyIterator.getIterator(table, keySpan, Direction.FORWARD);
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
	 * <p>
	 * This implementation is more efficient than using {@link #getKeyCount(KeySpan)} and comparing
	 * to 0, since there's no need to visit more than one record in the range.
	 * 
	 * @param keySpan the range of keys
	 * @return true if at least one record has a key within the range
	 */
	protected boolean getKeysExist(KeySpan keySpan) {
		if (keySpan.isEmpty()) {
			return false;
		}
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			if (KeySpan.ALL.equals(keySpan)) {
				throw new AssertionError();
			}
			final DBRecord rec = table.getRecordAtOrAfter(keySpan.min());
			return rec != null && keySpan.contains(rec.getKey());
		}
		catch (IOException e) {
			adapter.dbError(e);
			return false;
		}
	}

	/**
	 * Check if an object with the given key exists in the store
	 * 
	 * <p>
	 * Using this is preferred to {@link #getObjectAt(long)} and checking for null, if that object
	 * does not actually need to be retrieved.
	 * 
	 * @param key the key
	 * @return true if it exists
	 */
	public boolean containsKey(long key) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return keys.typedContains(key);
		}
		catch (IOException e) {
			adapter.dbError(e);
			return false;
		}
	}

	/**
	 * Check if the given object exists in the store
	 * 
	 * <p>
	 * No matter the definition of {@link T#equals(Object)}, this requires the identical object to
	 * be present.
	 * 
	 * @param obj the object
	 * @return
	 */
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
	 * <p>
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

	/**
	 * Get the column number given a column name
	 * 
	 * @param name the name
	 * @return the number (0-up index) for the column
	 * @throws NoSuchElementException if no column with the given name exists
	 */
	protected int getColumnByName(String name) {
		int index = ArrayUtils.indexOf(schema.getFieldNames(), name);
		if (index < 0) {
			throw new NoSuchElementException(name);
		}
		return index;
	}

	/**
	 * Get the table index for the given column number
	 * 
	 * @param <K> the type of the object field for the indexed column
	 * @param fieldClass the class specifying {@link K}
	 * @param columnIndex the column number
	 * @return the index
	 * @throws IllegalArgumentException if the column has a different type than {@link K}
	 */
	protected <K> DBCachedObjectIndex<K, T> getIndex(Class<K> fieldClass, int columnIndex) {
		if (!ArrayUtils.contains(table.getIndexedColumns(), columnIndex)) {
			throw new IllegalArgumentException(
				"Column " + schema.getFieldNames()[columnIndex] + " is not indexed");
		}

		DBFieldCodec<?, T, ?> codec = codecs.get(columnIndex);
		Class<?> exp = codec.getValueType();
		if (fieldClass != exp) {
			throw new IllegalArgumentException("Column " + schema.getFieldNames()[columnIndex] +
				" is not of type " + fieldClass + "! It is " + exp);
		}
		@SuppressWarnings("unchecked")
		DBFieldCodec<K, T, ?> castCodec = (DBFieldCodec<K, T, ?>) codec;
		return new DBCachedObjectIndex<>(this, adapter, castCodec, columnIndex, FieldSpan.ALL,
			Direction.FORWARD);
	}

	/**
	 * Get the index for a given column
	 * 
	 * <p>
	 * See {@link DBCachedObjectStoreFactory} for an example that includes use of an index
	 * 
	 * @param <K> the type of the object field for the indexed column
	 * @param fieldClass the class specifying {@link K}
	 * @param column the indexed column
	 * @return the index
	 * @throws IllegalArgumentException if the column has a different type than {@link K}
	 */
	public <K> DBCachedObjectIndex<K, T> getIndex(Class<K> fieldClass, DBObjectColumn column) {
		return getIndex(fieldClass, column.columnNumber);
	}

	/**
	 * Get the index for a given column by name
	 * 
	 * <p>
	 * See {@link DBCachedObjectStoreFactory} for an example that includes use of an index
	 * 
	 * @param <K> the type of the object field for the indexed column
	 * @param fieldClass the class specifying {@link K}
	 * @param columnName the name of the indexed column
	 * @return the index
	 * @throws IllegalArgumentException if the given column is not indexed
	 */
	public <K> DBCachedObjectIndex<K, T> getIndex(Class<K> fieldClass, String columnName) {
		int columnIndex = getColumnByName(columnName);
		return getIndex(fieldClass, columnIndex);
	}

	/**
	 * Delete the given object
	 * 
	 * @param obj the object
	 * @return true if the object was removed, false for no effect
	 */
	public boolean delete(T obj) {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			return objects.typedRemove(obj) != null;
		}
		catch (IOException e) {
			adapter.dbError(e);
			return false;
		}
	}

	/**
	 * Delete the object with the given key
	 * 
	 * @param key the key
	 * @return true if the key was removed, false for no effect
	 */
	public T deleteKey(long key) {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			return keys.typedRemove(key);
		}
		catch (IOException e) {
			adapter.dbError(e);
			return null;
		}
	}

	/**
	 * Clear the entire table
	 */
	public void deleteAll() {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			table.deleteAll();
			cache.invalidate();
		}
		catch (IOException e) {
			adapter.dbError(e);
		}
	}

	protected void deleteKeys(KeySpan keySpan) {
		if (keySpan.isEmpty()) {
			return;
		}
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			long min = keySpan.min();
			long max = keySpan.max();
			table.deleteRecords(min, max);
			cache.delete(List.of(new KeyRange(min, max)));
		}
		catch (IOException e) {
			adapter.dbError(e);
		}
	}

	/**
	 * A variation of {@link Supplier} that allows {@link IOException} to pass through
	 *
	 * @param <U> the type of object supplied
	 */
	protected interface SupplierAllowsIOException<U> {
		U get() throws IOException;
	}

	/**
	 * Invoke the given supplier with a lock, directing {@link IOException}s to the domain object
	 * adapter
	 * 
	 * @param <U> the type of the result
	 * @param l the lock to hold during invocation
	 * @param supplier the supplier to invoke
	 * @return the result
	 */
	protected <U> U safe(Lock l, SupplierAllowsIOException<U> supplier) {
		try (LockHold hold = LockHold.lock(l)) {
			return supplier.get();
		}
		catch (IOException e) {
			adapter.dbError(e);
			return null;
		}
	}

	/**
	 * Get the object having the given key
	 * 
	 * @param key the key
	 * @return the object, or null
	 */
	public T getObjectAt(long key) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return objects.get(key);
		}
		catch (IOException e) {
			adapter.dbError(e);
			return null;
		}
	}

	/**
	 * Get the key comparator
	 * 
	 * @implNote this is probably vestigial, left from when we attempted to allow customization of
	 *           the primary key. This currently just gives the natural ordering of longs.
	 * 
	 * @return the comparator
	 */
	protected Comparator<? super Long> keyComparator() {
		return KEY_COMPARATOR;
	}

	/**
	 * Provides access to the store as a {@link NavigableMap}.
	 * 
	 * @return the map
	 */
	public DBCachedObjectStoreMap<T> asMap() {
		return asForwardMap;
	}

	/**
	 * Search a column index for a single object having the given value
	 * 
	 * @param columnIndex the indexed column's number
	 * @param field a field holding the value to seek
	 * @return the object, if found, or null
	 * @throws IOException if there's an issue reading the table
	 * @throws IllegalStateException if the object is not unique
	 */
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

	/**
	 * Search a column index for all objects having the given value
	 * 
	 * @param columnIndex the indexed column's number
	 * @param field a field holding the value to seek
	 * @return the collection of objects found, possibly empty but never null
	 * @throws IOException if there's an issue reading the table
	 */
	protected DBCachedObjectStoreFoundKeysValueCollection<T> findObjects(int columnIndex,
			Field field) throws IOException {
		Field[] found = table.findRecords(field, columnIndex);
		return new DBCachedObjectStoreFoundKeysValueCollection<>(this, adapter, lock, found);
	}

	/**
	 * Search a column index and iterate over objects having the given value
	 * 
	 * @param columnIndex the indexed column's number
	 * @param fieldSpan required: the range to consider
	 * @param direction the direction of iteration
	 * @return the iterator, possibly empty but never null
	 * @throws IOException if there's an issue reading the table
	 */
	protected Iterator<T> iterator(int columnIndex, FieldSpan fieldSpan, Direction direction)
			throws IOException {
		DirectedRecordIterator it =
			DirectedRecordIterator.getIndexIterator(table, columnIndex, fieldSpan, direction);
		return objects.iterator(it);
	}

	/**
	 * For testing: check if the given key is in the cache
	 * 
	 * @param key the key
	 * @return true if cached
	 */
	boolean isCached(long key) {
		return cache.get(key) != null;
	}

	/**
	 * Get the read lock
	 * 
	 * @return the lock
	 */
	public Lock readLock() {
		return lock.readLock();
	}

	/**
	 * Get the write lock
	 * 
	 * @return the lock
	 */
	public Lock writeLock() {
		return lock.writeLock();
	}

	/**
	 * Get the read-write lock
	 * 
	 * @return the lock
	 */
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
	 * <p>
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

	/**
	 * Invalidate this store's cache
	 * 
	 * <p>
	 * This should be called whenever the table may have changed in a way not caused by the store
	 * itself, e.g., whenever {@link DBHandle#undo()} is called.
	 */
	public void invalidateCache() {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			cache.invalidate();
			table = dbh.getTable(tableName);
			assert schema.equals(table.getSchema());
		}
	}
}
