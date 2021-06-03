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
import java.util.Map.Entry;
import java.util.concurrent.locks.ReadWriteLock;

import com.google.common.collect.Range;

import db.util.ErrorHandler;
import ghidra.util.database.DirectedIterator.Direction;

public class DBCachedObjectStoreEntrySubSet<T extends DBAnnotatedObject>
		extends DBCachedObjectStoreEntrySet<T> {

	protected final Range<Long> keyRange;

	public DBCachedObjectStoreEntrySubSet(DBCachedObjectStore<T> store, ErrorHandler errHandler,
			ReadWriteLock lock, Direction direction, Range<Long> keyRange) {
		super(store, errHandler, lock, direction);
		this.keyRange = keyRange;
	}

	@Override
	public Entry<Long, T> first() {
		return store.safe(lock.readLock(), () -> store.entries.first(direction, keyRange));
	}

	@Override
	public Entry<Long, T> last() {
		return store.safe(lock.readLock(), () -> store.entries.last(direction, keyRange));
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
		return store.safe(lock.readLock(), () -> store.entries.contains(o, keyRange));
	}

	@Override
	public Object[] toArray() {
		return store.entries.toArray(direction, keyRange);
	}

	@Override
	public <U> U[] toArray(U[] a) {
		return store.entries.toArray(direction, keyRange, a, store.getKeyCount(keyRange));
	}

	@Override
	public boolean remove(Object o) {
		return store.safe(lock.writeLock(), () -> store.entries.remove(o, keyRange));
	}

	@Override
	public boolean containsAll(Collection<?> c) {
		return store.safe(lock.readLock(), () -> store.entries.containsAll(c, keyRange));
	}

	@Override
	public boolean retainAll(Collection<?> c) {
		return store.entries.retain(c, keyRange);
	}

	@Override
	public boolean removeAll(Collection<?> c) {
		return store.safe(lock.writeLock(), () -> store.entries.removeAll(c, keyRange));
	}

	@Override
	public void clear() {
		store.deleteKeys(keyRange);
	}

	@Override
	public Entry<Long, T> lower(Entry<Long, T> e) {
		return store.safe(lock.readLock(),
			() -> store.entries.lower(direction, e.getKey(), keyRange));
	}

	@Override
	public Entry<Long, T> floor(Entry<Long, T> e) {
		return store.safe(lock.readLock(),
			() -> store.entries.floor(direction, e.getKey(), keyRange));
	}

	@Override
	public Entry<Long, T> ceiling(Entry<Long, T> e) {
		return store.safe(lock.readLock(),
			() -> store.entries.ceiling(direction, e.getKey(), keyRange));
	}

	@Override
	public Entry<Long, T> higher(Entry<Long, T> e) {
		return store.safe(lock.readLock(),
			() -> store.entries.higher(direction, e.getKey(), keyRange));
	}

	@Override
	public Iterator<Entry<Long, T>> iterator() {
		return store.entries.iterator(direction, keyRange);
	}

	@Override
	public DBCachedObjectStoreEntrySubSet<T> descendingSet() {
		return new DBCachedObjectStoreEntrySubSet<>(store, errHandler, lock,
			Direction.reverse(direction), keyRange);
	}

	@Override
	public Iterator<Entry<Long, T>> descendingIterator() {
		return store.entries.iterator(Direction.reverse(direction), keyRange);
	}

	@Override
	public DBCachedObjectStoreEntrySubSet<T> subSet(Entry<Long, T> fromElement,
			boolean fromInclusive, Entry<Long, T> toElement, boolean toInclusive) {
		Range<Long> rng = DBCachedObjectStore.toRange(fromElement.getKey(), fromInclusive,
			toElement.getKey(), toInclusive, direction);
		return new DBCachedObjectStoreEntrySubSet<>(store, errHandler, lock, direction,
			keyRange.intersection(rng));
	}

	@Override
	public DBCachedObjectStoreEntrySubSet<T> headSet(Entry<Long, T> toElement, boolean inclusive) {
		Range<Long> rng = DBCachedObjectStore.toRangeHead(toElement.getKey(), inclusive, direction);
		return new DBCachedObjectStoreEntrySubSet<>(store, errHandler, lock, direction,
			keyRange.intersection(rng));
	}

	@Override
	public DBCachedObjectStoreEntrySubSet<T> tailSet(Entry<Long, T> fromElement,
			boolean inclusive) {
		Range<Long> rng =
			DBCachedObjectStore.toRangeTail(fromElement.getKey(), inclusive, direction);
		return new DBCachedObjectStoreEntrySubSet<>(store, errHandler, lock, direction,
			keyRange.intersection(rng));
	}
}
