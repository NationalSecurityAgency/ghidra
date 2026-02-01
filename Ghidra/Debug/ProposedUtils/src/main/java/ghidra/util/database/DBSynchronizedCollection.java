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

import ghidra.util.LockHold;

public class DBSynchronizedCollection<E> implements Collection<E> {
	private final Collection<E> delegate;
	private final ReadWriteLock lock;

	public DBSynchronizedCollection(Collection<E> delegate, ReadWriteLock lock) {
		this.delegate = delegate;
		this.lock = lock;
	}

	@Override
	public int size() {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return delegate.size();
		}
	}

	@Override
	public boolean isEmpty() {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return delegate.isEmpty();
		}
	}

	@Override
	public boolean contains(Object o) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return delegate.contains(o);
		}
	}

	@Override
	public Iterator<E> iterator() {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return new DBSynchronizedIterator<>(delegate.iterator(), lock);
		}
	}

	@Override
	public Object[] toArray() {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return delegate.toArray();
		}
	}

	@Override
	public <T> T[] toArray(T[] a) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return delegate.toArray(a);
		}
	}

	@Override
	public boolean add(E e) {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			return delegate.add(e);
		}
	}

	@Override
	public boolean remove(Object o) {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			return delegate.remove(o);
		}
	}

	@Override
	public boolean containsAll(Collection<?> c) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return delegate.containsAll(c);
		}
	}

	@Override
	public boolean addAll(Collection<? extends E> c) {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			return delegate.addAll(c);
		}
	}

	@Override
	public boolean removeAll(Collection<?> c) {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			return delegate.removeAll(c);
		}
	}

	@Override
	public boolean retainAll(Collection<?> c) {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			return delegate.retainAll(c);
		}
	}

	@Override
	public void clear() {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			delegate.clear();
		}
	}
}
