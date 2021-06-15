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

import java.io.IOException;
import java.lang.reflect.Array;
import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import db.Field;
import db.util.ErrorHandler;
import ghidra.util.LockHold;

public class DBCachedObjectStoreFoundKeysValueCollection<T extends DBAnnotatedObject>
		implements Collection<T> {
	protected final DBCachedObjectStore<T> store;
	protected final ErrorHandler errHandler;
	protected final ReadWriteLock lock;
	protected final Set<Long> keys;

	public DBCachedObjectStoreFoundKeysValueCollection(DBCachedObjectStore<T> store,
			ErrorHandler errHandler, ReadWriteLock lock, Field[] keys) {
		this.store = store;
		this.errHandler = errHandler;
		this.lock = lock;
		this.keys = Stream.of(keys).map(Field::getLongValue).collect(Collectors.toSet());
	}

	@Override
	public int size() {
		return keys.size();
	}

	@Override
	public boolean isEmpty() {
		return keys.isEmpty();
	}

	@Override
	public boolean contains(Object o) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			T t = store.objects.checkAndConvert(o);
			if (t == null) {
				return false;
			}
			if (!keys.contains(t.getKey())) {
				return false;
			}
			return store.objects.typedContains(t);
		}
		catch (IOException e) {
			errHandler.dbError(e);
			return false;
		}
	}

	@Override
	public Iterator<T> iterator() {
		return keys.stream().map(store::getObjectAt).iterator();
	}

	@Override
	public Object[] toArray() {
		Object[] array = new Object[keys.size()];
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			int i = 0;
			for (long k : keys) {
				array[i++] = store.objects.get(k);
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return array;
	}

	@Override
	@SuppressWarnings("unchecked")
	public <U> U[] toArray(U[] a) {
		if (a.length < keys.size()) {
			a = (U[]) Array.newInstance(a.getClass().getComponentType(), keys.size());
		}
		int i = 0;
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			for (long k : keys) {
				a[i++] = (U) store.objects.get(k);
			}
			while (i < a.length) {
				a[i++] = null;
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return a;
	}

	@Override
	public boolean add(T e) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean remove(Object o) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean containsAll(Collection<?> c) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			for (Object o : c) {
				T t = store.objects.checkAndConvert(o);
				if (t == null) {
					return false;
				}
				if (!keys.contains(t.getKey())) {
					return false;
				}
				if (!store.objects.typedContains(t)) {
					return false;
				}
			}
			return true;
		}
		catch (IOException e) {
			errHandler.dbError(e);
			return false;
		}
	}

	@Override
	public boolean addAll(Collection<? extends T> c) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean retainAll(Collection<?> c) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean removeAll(Collection<?> c) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void clear() {
		throw new UnsupportedOperationException();
	}
}
