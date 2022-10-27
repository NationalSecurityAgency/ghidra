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

import java.util.concurrent.locks.ReadWriteLock;

import db.util.ErrorHandler;
import ghidra.util.database.DirectedIterator.Direction;

/**
 * This is the sub-ranged form of {@link DBCachedObjectStoreMap}
 *
 * <p>
 * For example, this can be obtained via {@code store.asMap().subMap(...)}.
 *
 * @param <T> the type of objects in the store
 */
public class DBCachedObjectStoreSubMap<T extends DBAnnotatedObject>
		extends DBCachedObjectStoreMap<T> {
	protected final KeySpan keySpan;

	public DBCachedObjectStoreSubMap(DBCachedObjectStore<T> store, ErrorHandler errHandler,
			ReadWriteLock lock, Direction direction, KeySpan keySpan) {
		super(store, errHandler, lock, direction);
		this.keySpan = keySpan;
	}

	@Override
	public int size() {
		return store.getKeyCount(keySpan);
	}

	@Override
	public boolean isEmpty() {
		return !store.getKeysExist(keySpan);
	}

	@Override
	public boolean containsKey(Object key) {
		return store.safe(lock.readLock(), () -> store.keys.contains(key, keySpan));
	}

	@Override
	public boolean containsValue(Object value) {
		return store.safe(lock.readLock(), () -> store.objects.contains(value, keySpan));
	}

	@Override
	public T get(Object key) {
		if (!(key instanceof Long)) {
			return null;
		}
		long kl = (Long) key;
		if (!keySpan.contains(kl)) {
			return null;
		}
		return store.getObjectAt(kl);
	}

	@Override
	public T remove(Object key) {
		if (!(key instanceof Long)) {
			return null;
		}
		long kl = (Long) key;
		if (!keySpan.contains(kl)) {
			return null;
		}
		return store.deleteKey(kl);
	}

	@Override
	public void clear() {
		store.deleteKeys(keySpan);
	}

	@Override
	public Entry<Long, T> firstEntry() {
		return store.safe(lock.readLock(), () -> store.entries.first(direction, keySpan));
	}

	@Override
	public Long firstKey() {
		return store.safe(lock.readLock(), () -> store.keys.first(direction, keySpan));
	}

	@Override
	public Entry<Long, T> lastEntry() {
		return store.safe(lock.readLock(), () -> store.entries.last(direction, keySpan));
	}

	@Override
	public Long lastKey() {
		return store.safe(lock.readLock(), () -> store.keys.last(direction, keySpan));
	}

	@Override
	public Entry<Long, T> lowerEntry(Long key) {
		return store.safe(lock.readLock(), () -> store.entries.lower(direction, key, keySpan));
	}

	@Override
	public Long lowerKey(Long key) {
		return store.safe(lock.readLock(), () -> store.keys.lower(direction, key, keySpan));
	}

	@Override
	public Entry<Long, T> floorEntry(Long key) {
		return store.safe(lock.readLock(), () -> store.entries.floor(direction, key, keySpan));
	}

	@Override
	public Long floorKey(Long key) {
		return store.safe(lock.readLock(), () -> store.keys.floor(direction, key, keySpan));
	}

	@Override
	public Entry<Long, T> ceilingEntry(Long key) {
		return store.safe(lock.readLock(), () -> store.entries.ceiling(direction, key, keySpan));
	}

	@Override
	public Long ceilingKey(Long key) {
		return store.safe(lock.readLock(), () -> store.keys.ceiling(direction, key, keySpan));
	}

	@Override
	public Entry<Long, T> higherEntry(Long key) {
		return store.safe(lock.readLock(), () -> store.entries.higher(direction, key, keySpan));
	}

	@Override
	public Long higherKey(Long key) {
		return store.safe(lock.readLock(), () -> store.keys.higher(direction, key, keySpan));
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
	public DBCachedObjectStoreKeySubSet keySet() {
		return navigableKeySet();
	}

	@Override
	public DBCachedObjectStoreValueSubCollection<T> values() {
		return new DBCachedObjectStoreValueSubCollection<>(store, errHandler, lock, direction,
			keySpan);
	}

	@Override
	public DBCachedObjectStoreEntrySubSet<T> entrySet() {
		return new DBCachedObjectStoreEntrySubSet<>(store, errHandler, lock, direction, keySpan);
	}

	@Override
	public DBCachedObjectStoreSubMap<T> descendingMap() {
		return new DBCachedObjectStoreSubMap<>(store, errHandler, lock,
			Direction.reverse(direction), keySpan);
	}

	@Override
	public DBCachedObjectStoreKeySubSet navigableKeySet() {
		return new DBCachedObjectStoreKeySubSet(store, errHandler, lock, direction, keySpan);
	}

	@Override
	public DBCachedObjectStoreKeySubSet descendingKeySet() {
		return new DBCachedObjectStoreKeySubSet(store, errHandler, lock,
			Direction.reverse(direction), keySpan);
	}

	@Override
	public DBCachedObjectStoreSubMap<T> subMap(Long fromKey, boolean fromInclusive, Long toKey,
			boolean toInclusive) {
		KeySpan span = KeySpan.sub(fromKey, fromInclusive, toKey, toInclusive, direction);
		return new DBCachedObjectStoreSubMap<>(store, errHandler, lock, direction,
			keySpan.intersect(span));
	}

	@Override
	public DBCachedObjectStoreSubMap<T> headMap(Long toKey, boolean inclusive) {
		KeySpan span = KeySpan.head(toKey, inclusive, direction);
		return new DBCachedObjectStoreSubMap<>(store, errHandler, lock, direction,
			keySpan.intersect(span));
	}

	@Override
	public DBCachedObjectStoreSubMap<T> tailMap(Long fromKey, boolean inclusive) {
		KeySpan span = KeySpan.tail(fromKey, inclusive, direction);
		return new DBCachedObjectStoreSubMap<>(store, errHandler, lock, direction,
			keySpan.intersect(span));
	}
}
