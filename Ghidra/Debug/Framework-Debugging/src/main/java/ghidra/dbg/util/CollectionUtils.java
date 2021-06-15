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
package ghidra.dbg.util;

import java.util.*;
import java.util.function.*;

public enum CollectionUtils {
	;

	public abstract static class AbstractImmutableList<T> extends AbstractList<T> {
		@Override
		public void add(int index, T element) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean add(T e) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean addAll(Collection<? extends T> c) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean addAll(int index, Collection<? extends T> c) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean remove(Object o) {
			throw new UnsupportedOperationException();
		}

		@Override
		public T remove(int index) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean removeAll(Collection<?> c) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean removeIf(Predicate<? super T> filter) {
			throw new UnsupportedOperationException();
		}

		@Override
		protected void removeRange(int fromIndex, int toIndex) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean retainAll(Collection<?> c) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void clear() {
			throw new UnsupportedOperationException();
		}

		@Override
		public void replaceAll(UnaryOperator<T> operator) {
			throw new UnsupportedOperationException();
		}

		@Override
		public T set(int index, T element) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void sort(Comparator<? super T> c) {
			throw new UnsupportedOperationException();
		}
	}

	public abstract static class AbstractImmutableSet<T> extends AbstractSet<T> {
		@Override
		public boolean add(T e) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean addAll(Collection<? extends T> c) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void clear() {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean remove(Object o) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean retainAll(Collection<?> c) {
			throw new UnsupportedOperationException();
		}
	}

	public abstract static class AbstractImmutableMap<K, V> extends AbstractMap<K, V> {
	}

	public static class AbstractEmptyMap<K, V> extends AbstractMap<K, V> {
		@Override
		public Set<Entry<K, V>> entrySet() {
			return Set.of();
		}
	}

	public static class AbstractEmptyList<T> extends AbstractList<T> {
		@Override
		public T get(int index) {
			throw new ArrayIndexOutOfBoundsException(index);
		}

		@Override
		public int size() {
			return 0;
		}
	}

	public static class AbstractEmptySet<T> extends AbstractImmutableSet<T> {
		@Override
		public Iterator<T> iterator() {
			return Collections.emptyIterator();
		}

		@Override
		public int size() {
			return 0;
		}
	}

	public static class AbstractNList<T> extends AbstractImmutableList<T> {
		protected final List<T> wrapped;

		@SafeVarargs
		public AbstractNList(T... elems) {
			this.wrapped = List.of(elems);
		}

		public AbstractNList(Collection<T> col) {
			this.wrapped = List.copyOf(col);
		}

		@Override
		public T get(int index) {
			return wrapped.get(index);
		}

		@Override
		public int size() {
			return wrapped.size();
		}
	}

	public static class AbstractNSet<T> extends AbstractImmutableSet<T> {
		protected final Set<T> wrapped;

		@SafeVarargs
		public AbstractNSet(T... elems) {
			this.wrapped = Set.of(elems);
		}

		public AbstractNSet(Collection<T> col) {
			this.wrapped = Set.copyOf(col);
		}

		@Override
		public Iterator<T> iterator() {
			return wrapped.iterator();
		}

		@Override
		public int size() {
			return wrapped.size();
		}
	}

	public static class AbstractNMap<K, V> extends AbstractImmutableMap<K, V> {
		protected final Map<K, V> wrapped;

		public AbstractNMap(Map<K, V> map) {
			this.wrapped = Collections.unmodifiableMap(new LinkedHashMap<>(map));
		}

		@Override
		public Set<Entry<K, V>> entrySet() {
			return wrapped.entrySet();
		}
	}

	public static <K, V> Collection<V> getAllExisting(Map<K, V> map, Collection<K> keys) {
		List<V> result = new ArrayList<>();
		for (K k : keys) {
			if (map.containsKey(k)) {
				result.add(map.get(k));
			}
		}
		return result;
	}

	public static class Delta<T, U extends T> {
		public static final Delta<?, ?> EMPTY = new Delta<>(Map.of(), Map.of());
		public static final BiPredicate<Object, Object> SAME = (a, b) -> a == b;
		public static final BiPredicate<Object, Object> EQUAL = Objects::equals;

		@SuppressWarnings("unchecked")
		public static final <T, U extends T> Delta<T, U> empty() {
			return (Delta<T, U>) EMPTY;
		}

		public static final <T, U extends T> Delta<T, U> create(Map<String, T> removed,
				Map<String, U> added) {
			return new Delta<>(removed, added);
		}

		public static final <T, U extends T> Delta<T, U> create(Collection<String> removedKeys,
				Map<String, U> added) {
			Map<String, T> removedNull = new HashMap<>();
			for (String key : removedKeys) {
				removedNull.put(key, null);
			}
			return new Delta<>(removedNull, added);
		}

		protected static final <T> void retainKeys(Map<String, T> mutable, Collection<String> keys,
				Map<String, T> removed) {
			for (Iterator<Map.Entry<String, T>> eit = mutable.entrySet().iterator(); eit
					.hasNext();) {
				Map.Entry<String, T> oldEnt = eit.next();
				if (!keys.contains(oldEnt.getKey())) {
					removed.put(oldEnt.getKey(), oldEnt.getValue());
					eit.remove();
				}
			}
		}

		protected static final <T> void removeKeys(Map<String, T> mutable, Collection<String> keys,
				Map<String, T> removed) {
			for (String r : keys) {
				if (mutable.containsKey(r)) {
					removed.put(r, mutable.remove(r));
				}
			}
		}

		protected static final <T, U extends T> void putEntries(Map<String, T> mutable,
				Map<String, U> entries, Map<String, T> removed, Map<String, U> added,
				BiPredicate<? super T, ? super U> equals) {
			for (Map.Entry<String, U> e : entries.entrySet()) {
				String key = e.getKey();
				U newVal = e.getValue();
				if (!mutable.containsKey(key)) {
					mutable.put(key, newVal);
					added.put(key, newVal);
					continue;
				}
				T oldVal = mutable.get(key);
				if (!equals.test(oldVal, newVal)) {
					mutable.put(key, newVal);
					removed.put(key, oldVal);
					added.put(key, newVal);
				}
			}
		}

		public static final <T, U extends T> Delta<T, U> computeAndSet(Map<String, T> mutable,
				Map<String, U> desired, BiPredicate<? super T, ? super U> equals) {
			Map<String, T> removed = new LinkedHashMap<>();
			Map<String, U> added = new LinkedHashMap<>();
			retainKeys(mutable, desired.keySet(), removed);
			putEntries(mutable, desired, removed, added, equals);
			return create(removed, added);
		}

		/*public static final <T, U extends T> Delta<T, U> computeAndSet(Map<String, T> mutable,
				Map<String, U> desired) {
			return computeAndSet(mutable, desired, SAME);
		}*/

		public static final <T, U extends T> Delta<T, U> apply(Map<String, T> mutable,
				Collection<String> removed, Map<String, U> added,
				BiPredicate<? super T, ? super U> equals) {
			if (removed.isEmpty() && added.isEmpty()) {
				return empty();
			}

			Map<String, T> fRemoved = new LinkedHashMap<>();
			Map<String, U> fAdded = new LinkedHashMap<>();
			removeKeys(mutable, removed, fRemoved);
			putEntries(mutable, added, fRemoved, fAdded, equals);
			return create(fRemoved, fAdded);
		}

		/*public static final <T, U extends T> Delta<T, U> apply(Map<String, T> mutable,
				Collection<String> removed, Map<String, U> added) {
			return apply(mutable, removed, added, SAME);
		}*/

		public static final void applyToKeys(Set<String> mutable, Collection<String> removed,
				Map<String, ?> added) {
			mutable.removeAll(removed);
			mutable.addAll(added.keySet());
		}

		public final Map<String, T> removed;
		public final Map<String, U> added;
		private volatile Set<String> keysRemoved;
		// TODO: Moved?

		protected Delta(Map<String, T> removed, Map<String, U> added) {
			this.removed = removed;
			this.added = added;
		}

		@Override
		public String toString() {
			return "<Delta removed=" + removed + ", added=" + added + ">";
		}

		public boolean isEmpty() {
			return removed.isEmpty() && added.isEmpty();
		}

		public Delta<T, U> apply(Map<String, T> mutable,
				BiPredicate<Object, Object> equals) {
			return apply(mutable, removed.keySet(), added, equals);
		}

		public Delta<T, U> apply(Map<String, T> mutable) {
			return apply(mutable, SAME);
		}

		public void applyToKeys(Set<String> mutable) {
			applyToKeys(mutable, removed.keySet(), added);
		}

		public Set<String> getKeysRemoved() {
			if (keysRemoved != null) {
				return keysRemoved;
			}
			Set<String> temp = new LinkedHashSet<>(removed.keySet());
			temp.removeAll(added.keySet());
			keysRemoved = temp;
			return keysRemoved;
		}
	}
}
