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

import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;

import org.apache.commons.collections4.ComparatorUtils;

import com.google.common.collect.Range;

import db.util.ErrorHandler;
import ghidra.util.database.DirectedIterator.Direction;

public class DBCachedObjectStoreMap<T extends DBAnnotatedObject> implements NavigableMap<Long, T> {
	protected final DBCachedObjectStore<T> store;
	protected final ErrorHandler errHandler;
	protected final ReadWriteLock lock;
	protected final Direction direction;

	private final Comparator<? super Long> COMPARATOR;
	private final Comparator<? super Long> REVERSE_COMPARATOR;

	public DBCachedObjectStoreMap(DBCachedObjectStore<T> store, ErrorHandler errHandler,
			ReadWriteLock lock, Direction direction) {
		this.store = store;
		this.errHandler = errHandler;
		this.lock = lock;
		this.direction = direction;

		this.COMPARATOR = store.keyComparator();
		this.REVERSE_COMPARATOR = ComparatorUtils.reversedComparator(COMPARATOR);
	}

	@Override
	public int size() {
		return store.getRecordCount();
	}

	@Override
	public boolean isEmpty() {
		return store.getRecordCount() == 0;
	}

	@Override
	public boolean containsKey(Object key) {
		return store.safe(lock.readLock(), () -> store.keys.contains(key));
	}

	@Override
	public boolean containsValue(Object value) {
		return store.safe(lock.readLock(), () -> store.objects.contains(value));
	}

	@Override
	public T get(Object key) {
		if (!(key instanceof Long)) {
			return null;
		}
		return store.getObjectAt((Long) key);
	}

	@Override
	public T put(Long key, T value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public T remove(Object key) {
		if (!(key instanceof Long)) {
			return null;
		}
		return store.deleteKey((Long) key);
	}

	@Override
	public void putAll(Map<? extends Long, ? extends T> m) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void clear() {
		store.deleteAll();
	}

	@Override
	public Comparator<? super Long> comparator() {
		if (direction == Direction.FORWARD) {
			return COMPARATOR;
		}
		return REVERSE_COMPARATOR;
	}

	@Override
	public Entry<Long, T> firstEntry() {
		return store.safe(lock.readLock(), () -> store.entries.first(direction));
	}

	@Override
	public Long firstKey() {
		return store.safe(lock.readLock(), () -> store.keys.first(direction));
	}

	@Override
	public Entry<Long, T> lastEntry() {
		return store.safe(lock.readLock(), () -> store.entries.last(direction));
	}

	@Override
	public Long lastKey() {
		return store.safe(lock.readLock(), () -> store.keys.last(direction));
	}

	@Override
	public Entry<Long, T> lowerEntry(Long key) {
		return store.safe(lock.readLock(), () -> store.entries.lower(direction, key));
	}

	@Override
	public Long lowerKey(Long key) {
		return store.safe(lock.readLock(), () -> store.keys.lower(direction, key));
	}

	@Override
	public Entry<Long, T> floorEntry(Long key) {
		return store.safe(lock.readLock(), () -> store.entries.floor(direction, key));
	}

	@Override
	public Long floorKey(Long key) {
		return store.safe(lock.readLock(), () -> store.keys.floor(direction, key));
	}

	@Override
	public Entry<Long, T> ceilingEntry(Long key) {
		return store.safe(lock.readLock(), () -> store.entries.ceiling(direction, key));
	}

	@Override
	public Long ceilingKey(Long key) {
		return store.safe(lock.readLock(), () -> store.keys.ceiling(direction, key));
	}

	@Override
	public Entry<Long, T> higherEntry(Long key) {
		return store.safe(lock.readLock(), () -> store.entries.higher(direction, key));
	}

	@Override
	public Long higherKey(Long key) {
		return store.safe(lock.readLock(), () -> store.keys.higher(direction, key));
	}

	@Override
	public Entry<Long, T> pollFirstEntry() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Entry<Long, T> pollLastEntry() {
		throw new UnsupportedOperationException();
	}

	@Override
	public DBCachedObjectStoreKeySet keySet() {
		return navigableKeySet();
	}

	@Override
	public DBCachedObjectStoreValueCollection<T> values() {
		if (direction == Direction.FORWARD) {
			return store.asForwardValueCollection;
		}
		return new DBCachedObjectStoreValueCollection<>(store, errHandler, lock, direction);
	}

	@Override
	public DBCachedObjectStoreEntrySet<T> entrySet() {
		if (direction == Direction.FORWARD) {
			return store.asForwardEntrySet;
		}
		return new DBCachedObjectStoreEntrySet<>(store, errHandler, lock, direction);
	}

	@Override
	public DBCachedObjectStoreMap<T> descendingMap() {
		return new DBCachedObjectStoreMap<>(store, errHandler, lock, Direction.reverse(direction));
	}

	@Override
	public DBCachedObjectStoreKeySet navigableKeySet() {
		if (direction == Direction.FORWARD) {
			return store.asForwardKeySet;
		}
		return new DBCachedObjectStoreKeySet(store, errHandler, lock, direction);
	}

	@Override
	public DBCachedObjectStoreKeySet descendingKeySet() {
		return new DBCachedObjectStoreKeySet(store, errHandler, lock, Direction.reverse(direction));
	}

	@Override
	public DBCachedObjectStoreSubMap<T> subMap(Long fromKey, boolean fromInclusive, Long toKey,
			boolean toInclusive) {
		Range<Long> rng =
			DBCachedObjectStore.toRange(fromKey, fromInclusive, toKey, toInclusive, direction);
		return new DBCachedObjectStoreSubMap<>(store, errHandler, lock, direction, rng);
	}

	@Override
	public DBCachedObjectStoreSubMap<T> headMap(Long toKey, boolean inclusive) {
		Range<Long> rng = DBCachedObjectStore.toRangeHead(toKey, inclusive, direction);
		return new DBCachedObjectStoreSubMap<>(store, errHandler, lock, direction, rng);
	}

	@Override
	public DBCachedObjectStoreSubMap<T> tailMap(Long fromKey, boolean inclusive) {
		Range<Long> rng = DBCachedObjectStore.toRangeTail(fromKey, inclusive, direction);
		return new DBCachedObjectStoreSubMap<>(store, errHandler, lock, direction, rng);
	}

	@Override
	public DBCachedObjectStoreSubMap<T> subMap(Long fromKey, Long toKey) {
		return subMap(fromKey, true, toKey, false);
	}

	@Override
	public DBCachedObjectStoreSubMap<T> headMap(Long toKey) {
		return headMap(toKey, false);
	}

	@Override
	public DBCachedObjectStoreSubMap<T> tailMap(Long fromKey) {
		return tailMap(fromKey, true);
	}
}
