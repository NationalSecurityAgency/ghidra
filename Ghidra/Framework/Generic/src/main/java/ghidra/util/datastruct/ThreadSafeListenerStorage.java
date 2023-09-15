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
package ghidra.util.datastruct;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import generic.cache.Factory;

/**
 * A very specific data structure that provides 'copy on write' behavior while the client is
 * iterating the elements.
 * <p>
 * This class is meant for a very narrow and specific use case that includes: having a relatively
 * small number of listeners and the need for only basic adding, removing and iterating.
 * <p>
 * This class will create a new copy of its internal storage for any write operation, but only if
 * that happens while the elements in this class are being iterated.  This avoids unnecessary
 * copying.
 *
 * @param <T> the storage type
 */
class ThreadSafeListenerStorage<T> {

	// Creates a new set and adds all values from the optional set argument
	private Factory<Set<T>, Set<T>> factory;
	private Set<T> storage;
	private AtomicInteger iteratorCount = new AtomicInteger();

	ThreadSafeListenerStorage(boolean isWeak) {
		this(createFactory(isWeak));
	}

	ThreadSafeListenerStorage(Factory<Set<T>, Set<T>> factory) {
		this.factory = factory;
		this.storage = factory.get(null);
	}

	void forEach(Consumer<T> c) {

		Set<T> toIterate = getSet();

		try {
			for (T t : toIterate) {
				c.accept(t);
			}
		}
		finally {
			iteratorCount.decrementAndGet();
		}
	}

	private synchronized Set<T> getSet() {
		iteratorCount.incrementAndGet();
		return storage;
	}

	synchronized boolean add(T t) {
		if (iteratorCount.get() != 0) {
			storage = factory.get(storage);
		}
		return storage.add(t);
	}

	synchronized boolean remove(Object t) {
		if (iteratorCount.get() != 0) {
			storage = factory.get(storage);
		}
		return storage.remove(t);
	}

	synchronized void clear() {
		storage = factory.get(null);
	}

	synchronized int size() {
		return storage.size();
	}

	private static <T> Factory<Set<T>, Set<T>> createFactory(boolean isWeak) {
		if (isWeak) {
			return new WeakSetFactory<T>();
		}
		return new StrongSetFactory<T>();
	}

	private static class WeakSetFactory<T> implements Factory<Set<T>, Set<T>> {

		@Override
		public Set<T> get(Set<T> set) {
			Set<T> newSet = new ThreadUnsafeWeakSet<>();
			if (set != null) {
				newSet.addAll(set);
			}
			return newSet;
		}

	}

	private static class StrongSetFactory<T> implements Factory<Set<T>, Set<T>> {
		@Override
		public Set<T> get(Set<T> set) {
			Set<T> newSet = new HashSet<>();
			if (set != null) {
				newSet.addAll(set);
			}
			return newSet;
		}
	}

}
