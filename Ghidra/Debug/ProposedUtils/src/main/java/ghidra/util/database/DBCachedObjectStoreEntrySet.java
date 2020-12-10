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
import java.util.Map.Entry;
import java.util.concurrent.locks.ReadWriteLock;

import org.apache.commons.collections4.ComparatorUtils;

import com.google.common.collect.Range;

import db.util.ErrorHandler;
import ghidra.util.database.DirectedIterator.Direction;

public class DBCachedObjectStoreEntrySet<T extends DBAnnotatedObject>
		implements NavigableSet<Entry<Long, T>> {
	protected final DBCachedObjectStore<T> store;
	protected final Direction direction;
	protected final ReadWriteLock lock;
	protected final ErrorHandler errHandler;

	private final Comparator<Entry<Long, ?>> comparator;
	private final Comparator<Entry<Long, ?>> reverseComparator;

	public DBCachedObjectStoreEntrySet(DBCachedObjectStore<T> store, ErrorHandler errHandler,
			ReadWriteLock lock, Direction direction) {
		this.store = store;
		this.errHandler = errHandler;
		this.lock = lock;
		this.direction = direction;

		this.comparator = Comparator.comparing(Entry::getKey, store.keyComparator());
		this.reverseComparator = ComparatorUtils.reversedComparator(comparator);
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
	public boolean contains(Object o) {
		return store.safe(lock.readLock(), () -> store.entries.contains(o));
	}

	@Override
	public Iterator<Entry<Long, T>> iterator() {
		return store.entries.iterator(direction, null);
	}

	@Override
	public Object[] toArray() {
		return store.entries.toArray(direction, null);
	}

	@Override
	public <U> U[] toArray(U[] a) {
		return store.entries.toArray(direction, null, a, store.getRecordCount());
	}

	@Override
	public boolean add(Entry<Long, T> o) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean remove(Object o) {
		return store.safe(lock.writeLock(), () -> store.entries.remove(o));
	}

	@Override
	public boolean containsAll(Collection<?> c) {
		return store.safe(lock.readLock(), () -> store.entries.containsAll(c));
	}

	@Override
	public boolean addAll(Collection<? extends Entry<Long, T>> c) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean retainAll(Collection<?> c) {
		return store.entries.retain(c, null);
	}

	@Override
	public boolean removeAll(Collection<?> c) {
		return store.safe(lock.writeLock(), () -> store.entries.removeAll(c));
	}

	@Override
	public void clear() {
		store.deleteAll();
	}

	@Override
	public Comparator<? super Entry<Long, T>> comparator() {
		if (direction == Direction.FORWARD) {
			return comparator;
		}
		return reverseComparator;
	}

	@Override
	public Entry<Long, T> first() {
		return store.safe(lock.readLock(), () -> store.entries.first(direction));
	}

	@Override
	public Entry<Long, T> last() {
		return store.safe(lock.readLock(), () -> store.entries.last(direction));
	}

	@Override
	public Entry<Long, T> lower(Entry<Long, T> e) {
		return store.safe(lock.readLock(), () -> store.entries.lower(direction, e.getKey()));
	}

	@Override
	public Entry<Long, T> floor(Entry<Long, T> e) {
		return store.safe(lock.readLock(), () -> store.entries.floor(direction, e.getKey()));
	}

	@Override
	public Entry<Long, T> ceiling(Entry<Long, T> e) {
		return store.safe(lock.readLock(), () -> store.entries.ceiling(direction, e.getKey()));
	}

	@Override
	public Entry<Long, T> higher(Entry<Long, T> e) {
		return store.safe(lock.readLock(), () -> store.entries.higher(direction, e.getKey()));
	}

	@Override
	public Entry<Long, T> pollFirst() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Entry<Long, T> pollLast() {
		throw new UnsupportedOperationException();
	}

	@Override
	public DBCachedObjectStoreEntrySet<T> descendingSet() {
		return new DBCachedObjectStoreEntrySet<>(store, errHandler, lock,
			Direction.reverse(direction));
	}

	@Override
	public Iterator<Entry<Long, T>> descendingIterator() {
		return store.entries.iterator(Direction.reverse(direction), null);
	}

	@Override
	public DBCachedObjectStoreEntrySubSet<T> subSet(Entry<Long, T> fromElement,
			boolean fromInclusive, Entry<Long, T> toElement, boolean toInclusive) {
		Range<Long> rng = DBCachedObjectStore.toRange(fromElement.getKey(), fromInclusive,
			toElement.getKey(), toInclusive, direction);
		return new DBCachedObjectStoreEntrySubSet<>(store, errHandler, lock, direction, rng);
	}

	@Override
	public DBCachedObjectStoreEntrySubSet<T> headSet(Entry<Long, T> toElement, boolean inclusive) {
		Range<Long> rng = DBCachedObjectStore.toRangeHead(toElement.getKey(), inclusive, direction);
		return new DBCachedObjectStoreEntrySubSet<>(store, errHandler, lock, direction, rng);
	}

	@Override
	public DBCachedObjectStoreEntrySubSet<T> tailSet(Entry<Long, T> fromElement,
			boolean inclusive) {
		Range<Long> rng =
			DBCachedObjectStore.toRangeTail(fromElement.getKey(), inclusive, direction);
		return new DBCachedObjectStoreEntrySubSet<>(store, errHandler, lock, direction, rng);
	}

	@Override
	public DBCachedObjectStoreEntrySubSet<T> subSet(Entry<Long, T> fromElement,
			Entry<Long, T> toElement) {
		return subSet(fromElement, true, toElement, false);
	}

	@Override
	public DBCachedObjectStoreEntrySubSet<T> headSet(Entry<Long, T> toElement) {
		return headSet(toElement, false);
	}

	@Override
	public DBCachedObjectStoreEntrySubSet<T> tailSet(Entry<Long, T> fromElement) {
		return tailSet(fromElement, true);
	}
}
