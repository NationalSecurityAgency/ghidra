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

public class DBCachedObjectStoreValueSubCollection<T extends DBAnnotatedObject>
		extends DBCachedObjectStoreValueCollection<T> {
	protected final Range<Long> keyRange;

	public DBCachedObjectStoreValueSubCollection(DBCachedObjectStore<T> store,
			ErrorHandler errHandler, ReadWriteLock lock, Direction direction,
			Range<Long> keyRange) {
		super(store, errHandler, lock, direction);
		this.keyRange = keyRange;
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
		return store.safe(lock.readLock(), () -> store.objects.contains(o, keyRange));
	}

	@Override
	public Iterator<T> iterator() {
		return store.objects.iterator(direction, keyRange);
	}

	@Override
	public Object[] toArray() {
		return store.objects.toArray(direction, keyRange);
	}

	@Override
	public <U> U[] toArray(U[] a) {
		return store.objects.toArray(direction, keyRange, a, store.getKeyCount(keyRange));
	}

	@Override
	public boolean remove(Object o) {
		return store.safe(lock.writeLock(), () -> store.objects.remove(o, keyRange));
	}

	@Override
	public boolean containsAll(Collection<?> c) {
		return store.safe(lock.readLock(), () -> store.objects.containsAll(c, keyRange));
	}

	@Override
	public boolean removeAll(Collection<?> c) {
		return store.safe(lock.writeLock(), () -> store.objects.removeAll(c, keyRange));
	}

	@Override
	public boolean retainAll(Collection<?> c) {
		return store.objects.retain(c, keyRange);
	}

	@Override
	public void clear() {
		store.deleteKeys(keyRange);
	}
}
