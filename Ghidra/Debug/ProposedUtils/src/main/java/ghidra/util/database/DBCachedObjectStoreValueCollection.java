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

public class DBCachedObjectStoreValueCollection<T extends DBAnnotatedObject>
		implements Collection<T> {
	protected final DBCachedObjectStore<T> store;
	protected final ErrorHandler errHandler;
	protected final ReadWriteLock lock;
	protected final Direction direction;

	public DBCachedObjectStoreValueCollection(DBCachedObjectStore<T> store, ErrorHandler errHandler,
			ReadWriteLock lock, Direction direction) {
		this.store = store;
		this.errHandler = errHandler;
		this.lock = lock;
		this.direction = direction;
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
		return store.safe(lock.readLock(), () -> store.objects.contains(o));
	}

	@Override
	public Iterator<T> iterator() {
		return store.objects.iterator(direction, null);
	}

	@Override
	public Object[] toArray() {
		return store.objects.toArray(direction, null);
	}

	@Override
	public <U> U[] toArray(U[] a) {
		return store.objects.toArray(direction, null, a, store.getRecordCount());
	}

	@Override
	public boolean add(T e) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean remove(Object o) {
		return store.safe(lock.writeLock(), () -> store.objects.remove(o));
	}

	@Override
	public boolean containsAll(Collection<?> c) {
		return store.safe(lock.readLock(), () -> store.objects.containsAll(c));
	}

	@Override
	public boolean addAll(Collection<? extends T> c) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean removeAll(Collection<?> c) {
		return store.safe(lock.writeLock(), () -> store.objects.removeAll(c));
	}

	@Override
	public boolean retainAll(Collection<?> c) {
		return store.objects.retain(c, null);
	}

	@Override
	public void clear() {
		store.deleteAll();
	}
}
