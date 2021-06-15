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

public class DBCachedObjectStoreKeySet implements NavigableSet<Long> {
	protected final DBCachedObjectStore<?> store;
	protected final ErrorHandler errHandler;
	protected final ReadWriteLock lock;
	protected final Direction direction;

	private final Comparator<? super Long> comparator;
	private final Comparator<? super Long> reverseComparator;

	public DBCachedObjectStoreKeySet(DBCachedObjectStore<?> store, ErrorHandler errHandler,
			ReadWriteLock lock, Direction direction) {
		this.store = store;
		this.errHandler = errHandler;
		this.lock = lock;
		this.direction = direction;

		this.comparator = store.keyComparator();
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
		return store.safe(lock.readLock(), () -> store.keys.contains(o));
	}

	@Override
	public Iterator<Long> iterator() {
		return store.keys.iterator(direction, null);
	}

	@Override
	public Object[] toArray() {
		return store.keys.toArray(direction, null);
	}

	@Override
	public <T> T[] toArray(T[] a) {
		return store.keys.toArray(direction, null, a, store.getRecordCount());
	}

	@Override
	public boolean add(Long e) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean remove(Object o) {
		return store.safe(lock.writeLock(), () -> store.keys.remove(o));
	}

	@Override
	public boolean containsAll(Collection<?> c) {
		return store.safe(lock.readLock(), () -> store.keys.containsAll(c));
	}

	@Override
	public boolean addAll(Collection<? extends Long> c) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean retainAll(Collection<?> c) {
		return store.keys.retain(c, null);
	}

	@Override
	public boolean removeAll(Collection<?> c) {
		return store.safe(lock.writeLock(), () -> store.keys.removeAll(c));
	}

	@Override
	public void clear() {
		store.deleteAll();
	}

	@Override
	public Comparator<? super Long> comparator() {
		if (direction == Direction.FORWARD) {
			return comparator;
		}
		return reverseComparator;
	}

	@Override
	public Long first() {
		return store.safe(lock.readLock(), () -> store.keys.first(direction));
	}

	@Override
	public Long last() {
		return store.safe(lock.readLock(), () -> store.keys.last(direction));
	}

	@Override
	public Long lower(Long e) {
		return store.safe(lock.readLock(), () -> store.keys.lower(direction, e));
	}

	@Override
	public Long floor(Long e) {
		return store.safe(lock.readLock(), () -> store.keys.floor(direction, e));
	}

	@Override
	public Long ceiling(Long e) {
		return store.safe(lock.readLock(), () -> store.keys.ceiling(direction, e));
	}

	@Override
	public Long higher(Long e) {
		return store.safe(lock.readLock(), () -> store.keys.higher(direction, e));
	}

	@Override
	public Long pollFirst() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Long pollLast() {
		throw new UnsupportedOperationException();
	}

	@Override
	public DBCachedObjectStoreKeySet descendingSet() {
		return new DBCachedObjectStoreKeySet(store, errHandler, lock, Direction.reverse(direction));
	}

	@Override
	public Iterator<Long> descendingIterator() {
		return store.keys.iterator(Direction.reverse(direction), null);
	}

	@Override
	public DBCachedObjectStoreKeySubSet subSet(Long fromElement, boolean fromInclusive,
			Long toElement, boolean toInclusive) {
		Range<Long> rng = DBCachedObjectStore.toRange(fromElement, fromInclusive, toElement,
			toInclusive, direction);
		return new DBCachedObjectStoreKeySubSet(store, errHandler, lock, direction, rng);
	}

	@Override
	public DBCachedObjectStoreKeySubSet headSet(Long toElement, boolean inclusive) {
		Range<Long> rng = DBCachedObjectStore.toRangeHead(toElement, inclusive, direction);
		return new DBCachedObjectStoreKeySubSet(store, errHandler, lock, direction, rng);
	}

	@Override
	public DBCachedObjectStoreKeySubSet tailSet(Long fromElement, boolean inclusive) {
		Range<Long> rng = DBCachedObjectStore.toRangeTail(fromElement, inclusive, direction);
		return new DBCachedObjectStoreKeySubSet(store, errHandler, lock, direction, rng);
	}

	@Override
	public DBCachedObjectStoreKeySubSet subSet(Long fromElement, Long toElement) {
		return subSet(fromElement, true, toElement, false);
	}

	@Override
	public DBCachedObjectStoreKeySubSet headSet(Long toElement) {
		return headSet(toElement, false);
	}

	@Override
	public DBCachedObjectStoreKeySubSet tailSet(Long fromElement) {
		return tailSet(fromElement, true);
	}
}
