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

import com.google.common.collect.Range;

import db.util.ErrorHandler;
import ghidra.util.database.DirectedIterator.Direction;

public class DBCachedObjectStoreKeySubSet extends DBCachedObjectStoreKeySet {
	protected final Range<Long> keyRange;

	public DBCachedObjectStoreKeySubSet(DBCachedObjectStore<?> store, ErrorHandler errHandler,
			ReadWriteLock lock, Direction direction, Range<Long> keyRange) {
		super(store, errHandler, lock, direction);
		this.keyRange = keyRange;
	}

	@Override
	public Long first() {
		return store.safe(lock.readLock(), () -> store.keys.first(direction, keyRange));
	}

	@Override
	public Long last() {
		return store.safe(lock.readLock(), () -> store.keys.last(direction, keyRange));
	}

	@Override
	public int size() {
		return store.getKeyCount(keyRange);
	}

	@Override
	public boolean isEmpty() {
		return !store.getKeysExist(keyRange);
	}

	@Override
	public boolean contains(Object o) {
		return store.safe(lock.readLock(), () -> store.keys.contains(o, keyRange));
	}

	@Override
	public Object[] toArray() {
		return store.keys.toArray(direction, keyRange);
	}

	@Override
	public <T> T[] toArray(T[] a) {
		return store.keys.toArray(direction, keyRange, a, store.getKeyCount(keyRange));
	}

	@Override
	public boolean remove(Object o) {
		return store.safe(lock.writeLock(), () -> store.keys.remove(o, keyRange));
	}

	@Override
	public boolean containsAll(Collection<?> c) {
		return store.safe(lock.readLock(), () -> store.keys.containsAll(c, keyRange));
	}

	@Override
	public boolean retainAll(Collection<?> c) {
		return store.keys.retain(c, keyRange);
	}

	@Override
	public boolean removeAll(Collection<?> c) {
		return store.safe(lock.writeLock(), () -> store.keys.removeAll(c, keyRange));
	}

	@Override
	public void clear() {
		store.deleteKeys(keyRange);
	}

	@Override
	public Long lower(Long e) {
		return store.safe(lock.readLock(), () -> store.keys.lower(direction, e, keyRange));
	}

	@Override
	public Long floor(Long e) {
		return store.safe(lock.readLock(), () -> store.keys.floor(direction, e, keyRange));
	}

	@Override
	public Long ceiling(Long e) {
		return store.safe(lock.readLock(), () -> store.keys.ceiling(direction, e, keyRange));
	}

	@Override
	public Long higher(Long e) {
		return store.safe(lock.readLock(), () -> store.keys.higher(direction, e, keyRange));
	}

	@Override
	public Iterator<Long> iterator() {
		return store.keys.iterator(direction, keyRange);
	}

	@Override
	public DBCachedObjectStoreKeySubSet descendingSet() {
		return new DBCachedObjectStoreKeySubSet(store, errHandler, lock,
			Direction.reverse(direction), keyRange);
	}

	@Override
	public Iterator<Long> descendingIterator() {
		return store.keys.iterator(Direction.reverse(direction), keyRange);
	}

	@Override
	public DBCachedObjectStoreKeySubSet subSet(Long fromElement, boolean fromInclusive,
			Long toElement, boolean toInclusive) {
		Range<Long> rng = DBCachedObjectStore.toRange(fromElement, fromInclusive, toElement,
			toInclusive, direction);
		return new DBCachedObjectStoreKeySubSet(store, errHandler, lock, direction,
			keyRange.intersection(rng));
	}

	@Override
	public DBCachedObjectStoreKeySubSet headSet(Long toElement, boolean inclusive) {
		Range<Long> rng = DBCachedObjectStore.toRangeHead(toElement, inclusive, direction);
		return new DBCachedObjectStoreKeySubSet(store, errHandler, lock, direction,
			keyRange.intersection(rng));
	}

	@Override
	public DBCachedObjectStoreKeySubSet tailSet(Long fromElement, boolean inclusive) {
		Range<Long> rng = DBCachedObjectStore.toRangeTail(fromElement, inclusive, direction);
		return new DBCachedObjectStoreKeySubSet(store, errHandler, lock, direction,
			keyRange.intersection(rng));
	}
}
