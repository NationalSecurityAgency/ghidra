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
package ghidra.trace.util;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import ghidra.util.datastruct.AbstractWeakValueMap;

public interface CopyOnWrite {
	abstract class AbstractCowMap<K, V> implements Map<K, V> {
		private final AtomicReference<Map<K, V>> map;

		public AbstractCowMap() {
			map = new AtomicReference<>(copyMap(Map.of()));
		}

		/**
		 * Extension point: Create a mutable copy of the given map
		 * 
		 * @param map the map to copy
		 * @return the mutable copy
		 */
		protected abstract Map<K, V> copyMap(Map<K, V> map);

		@Override
		public int size() {
			return map.get().size();
		}

		@Override
		public boolean isEmpty() {
			return map.get().isEmpty();
		}

		@Override
		public boolean containsKey(Object key) {
			return map.get().containsKey(key);
		}

		@Override
		public boolean containsValue(Object value) {
			return map.get().containsValue(value);
		}

		@Override
		public V get(Object key) {
			return map.get().get(key);
		}

		@Override
		public V put(K key, V value) {
			return map.getAndUpdate(m -> {
				Map<K, V> withPut = copyMap(m);
				withPut.put(key, value);
				return withPut;
			}).get(key);
		}

		@Override
		public V remove(Object key) {
			return map.getAndUpdate(m -> {
				Map<K, V> withRemove = copyMap(m);
				withRemove.remove(key);
				return withRemove;
			}).get(key);
		}

		@Override
		public void putAll(Map<? extends K, ? extends V> from) {
			map.getAndUpdate(m -> {
				Map<K, V> withPutAll = copyMap(m);
				withPutAll.putAll(from);
				return withPutAll;
			});
		}

		@Override
		public void clear() {
			map.set(copyMap(Map.of()));
		}

		@Override
		public Set<K> keySet() {
			return Collections.unmodifiableSet(map.get().keySet());
		}

		@Override
		public Collection<V> values() {
			return Collections.unmodifiableCollection(map.get().values());
		}

		@Override
		public Set<Entry<K, V>> entrySet() {
			return Collections.unmodifiableSet(map.get().entrySet());
		}

		@Override
		public V computeIfAbsent(K key, Function<? super K, ? extends V> mappingFunction) {
			return map.getAndUpdate(m -> {
				if (m.containsKey(key)) {
					return m;
				}
				Map<K, V> withComputeIfAbsent = copyMap(m);
				withComputeIfAbsent.put(key, mappingFunction.apply(key));
				return withComputeIfAbsent;
			}).get(key);
		}
	}

	class HashCowMap<K, V> extends AbstractCowMap<K, V> {
		@Override
		protected Map<K, V> copyMap(Map<K, V> map) {
			return new HashMap<>(map);
		}
	}

	abstract class WeakValueAbstractCowMap<K, V> extends AbstractWeakValueMap<K, V> {
		private final AbstractCowMap<K, WeakValueRef<K, V>> refMap = newCowMap();

		protected abstract AbstractCowMap<K, WeakValueRef<K, V>> newCowMap();

		@Override
		protected Map<K, WeakValueRef<K, V>> getRefMap() {
			return refMap;
		}
	}

	class WeakValueHashCowMap<K, V> extends WeakValueAbstractCowMap<K, V> {
		@Override
		protected AbstractCowMap<K, WeakValueRef<K, V>> newCowMap() {
			return new HashCowMap<>();
		}
	}

	/**
	 * Assumes elements use system hash equality, i.e., {@link E#equals()} is ignored
	 *
	 * @param <E> the type of element in the weak set
	 */
	abstract class WeakAbstractCowSet<E> extends AbstractSet<E> {
		private final WeakValueAbstractCowMap<Integer, E> map = newWeakValueCowMap();

		protected abstract WeakValueAbstractCowMap<Integer, E> newWeakValueCowMap();

		@Override
		public Iterator<E> iterator() {
			return map.values().iterator();
		}

		@Override
		public int size() {
			return map.size();
		}

		@Override
		public boolean isEmpty() {
			return map.isEmpty();
		}

		@Override
		public boolean contains(Object o) {
			return map.get(System.identityHashCode(o)) == o;
		}

		@Override
		public boolean add(E e) {
			return map.put(System.identityHashCode(e), e) != e;
		}

		@Override
		public boolean remove(Object o) {
			return map.remove(System.identityHashCode(o)) == o;
		}

		@Override
		public void clear() {
			map.clear();
		}

		@Override
		public Object[] toArray() {
			return map.values().toArray();
		}

		@Override
		public <T> T[] toArray(T[] a) {
			return map.values().toArray(a);
		}
	}

	class WeakHashCowSet<E> extends WeakAbstractCowSet<E> {
		@Override
		protected WeakValueAbstractCowMap<Integer, E> newWeakValueCowMap() {
			return new WeakValueHashCowMap<>();
		}
	}
}
