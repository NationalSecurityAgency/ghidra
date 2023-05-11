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
 * This is the sub-ranged form of {@link DBCachedObjectStoreValueCollection}
 *
 * <p>
 * For example, this can be obtained via {@code store.asMap().subMap(...).values()}.
 */
public class DBCachedObjectStoreValueSubCollection<T extends DBAnnotatedObject>
		extends DBCachedObjectStoreValueCollection<T> {
	protected final KeySpan keySpan;

	public DBCachedObjectStoreValueSubCollection(DBCachedObjectStore<T> store,
			ErrorHandler errHandler, ReadWriteLock lock, Direction direction,
			KeySpan keySpan) {
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
	public boolean contains(Object o) {
		return store.safe(lock.readLock(), () -> store.objects.contains(o, keySpan));
	}

	@Override
	public Iterator<T> iterator() {
		return store.objects.iterator(direction, keySpan);
	}

	@Override
	public Object[] toArray() {
		return store.objects.toArray(direction, keySpan);
	}

	@Override
	public <U> U[] toArray(U[] a) {
		return store.objects.toArray(direction, keySpan, a, store.getKeyCount(keySpan));
	}

	@Override
	public boolean remove(Object o) {
		return store.safe(lock.writeLock(), () -> store.objects.remove(o, keySpan));
	}

	@Override
	public boolean containsAll(Collection<?> c) {
		return store.safe(lock.readLock(), () -> store.objects.containsAll(c, keySpan));
	}

	@Override
	public boolean removeAll(Collection<?> c) {
		return store.safe(lock.writeLock(), () -> store.objects.removeAll(c, keySpan));
	}

	@Override
	public boolean retainAll(Collection<?> c) {
		return store.objects.retain(c, keySpan);
	}

	@Override
	public void clear() {
		store.deleteKeys(keySpan);
	}
}
