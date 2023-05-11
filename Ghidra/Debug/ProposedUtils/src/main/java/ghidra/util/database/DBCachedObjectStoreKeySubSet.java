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

import java.util.Collection;
import java.util.Iterator;
import java.util.concurrent.locks.ReadWriteLock;

import db.util.ErrorHandler;
import ghidra.util.database.DirectedIterator.Direction;

/**
 * This is the sub-ranged form of {@link DBCachedObjectStoreKeySubSet}
 *
 * <p>
 * For example, this can be obtained via {@code store.asMap().subMap(...).keySet()} or
 * {@code map.keySet().subSet(...)}.
 */
public class DBCachedObjectStoreKeySubSet extends DBCachedObjectStoreKeySet {
	protected final KeySpan keySpan;

	public DBCachedObjectStoreKeySubSet(DBCachedObjectStore<?> store, ErrorHandler errHandler,
			ReadWriteLock lock, Direction direction, KeySpan keySpan) {
		super(store, errHandler, lock, direction);
		this.keySpan = keySpan;
	}

	@Override
	public Long first() {
		return store.safe(lock.readLock(), () -> store.keys.first(direction, keySpan));
	}

	@Override
	public Long last() {
		return store.safe(lock.readLock(), () -> store.keys.last(direction, keySpan));
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
	public boolean contains(Object o) {
		return store.safe(lock.readLock(), () -> store.keys.contains(o, keySpan));
	}

	@Override
	public Object[] toArray() {
		return store.keys.toArray(direction, keySpan);
	}

	@Override
	public <T> T[] toArray(T[] a) {
		return store.keys.toArray(direction, keySpan, a, store.getKeyCount(keySpan));
	}

	@Override
	public boolean remove(Object o) {
		return store.safe(lock.writeLock(), () -> store.keys.remove(o, keySpan));
	}

	@Override
	public boolean containsAll(Collection<?> c) {
		return store.safe(lock.readLock(), () -> store.keys.containsAll(c, keySpan));
	}

	@Override
	public boolean retainAll(Collection<?> c) {
		return store.keys.retain(c, keySpan);
	}

	@Override
	public boolean removeAll(Collection<?> c) {
		return store.safe(lock.writeLock(), () -> store.keys.removeAll(c, keySpan));
	}

	@Override
	public void clear() {
		store.deleteKeys(keySpan);
	}

	@Override
	public Long lower(Long e) {
		return store.safe(lock.readLock(), () -> store.keys.lower(direction, e, keySpan));
	}

	@Override
	public Long floor(Long e) {
		return store.safe(lock.readLock(), () -> store.keys.floor(direction, e, keySpan));
	}

	@Override
	public Long ceiling(Long e) {
		return store.safe(lock.readLock(), () -> store.keys.ceiling(direction, e, keySpan));
	}

	@Override
	public Long higher(Long e) {
		return store.safe(lock.readLock(), () -> store.keys.higher(direction, e, keySpan));
	}

	@Override
	public Iterator<Long> iterator() {
		return store.keys.iterator(direction, keySpan);
	}

	@Override
	public DBCachedObjectStoreKeySubSet descendingSet() {
		return new DBCachedObjectStoreKeySubSet(store, errHandler, lock,
			Direction.reverse(direction), keySpan);
	}

	@Override
	public Iterator<Long> descendingIterator() {
		return store.keys.iterator(Direction.reverse(direction), keySpan);
	}

	@Override
	public DBCachedObjectStoreKeySubSet subSet(Long fromElement, boolean fromInclusive,
			Long toElement, boolean toInclusive) {
		KeySpan span = KeySpan.sub(fromElement, fromInclusive, toElement, toInclusive, direction);
		return new DBCachedObjectStoreKeySubSet(store, errHandler, lock, direction,
			keySpan.intersect(span));
	}

	@Override
	public DBCachedObjectStoreKeySubSet headSet(Long toElement, boolean inclusive) {
		KeySpan span = KeySpan.head(toElement, inclusive, direction);
		return new DBCachedObjectStoreKeySubSet(store, errHandler, lock, direction,
			keySpan.intersect(span));
	}

	@Override
	public DBCachedObjectStoreKeySubSet tailSet(Long fromElement, boolean inclusive) {
		KeySpan span = KeySpan.tail(fromElement, inclusive, direction);
		return new DBCachedObjectStoreKeySubSet(store, errHandler, lock, direction,
			keySpan.intersect(span));
	}
}
