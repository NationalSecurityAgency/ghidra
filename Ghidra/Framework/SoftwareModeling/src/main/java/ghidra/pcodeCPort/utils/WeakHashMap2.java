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
package ghidra.pcodeCPort.utils;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.*;

/**
 * A hashtable-based <code>Map</code> implementation with <em>weak values</em>.
 * 
 * <P>This implementation uses two maps internally, which nearly doubles the memory requirements
 * over a traditional map.
 */
public class WeakHashMap2<K, V> extends AbstractMap<K, V> {

	static private class WeakValue<Z> extends WeakReference<Z> {
		private int hash; /* Hashcode of value, stored here since the value
							may be tossed by the GC */

		private WeakValue(Z z, ReferenceQueue<Z> q) {
			super(z, q);
			hash = z.hashCode();
		}

		private static <Z> WeakValue<Z> create(Z z, ReferenceQueue<Z> q) {
			if (z == null) {
				return null;
			}
			return new WeakValue<>(z, q);
		}

		/* A WeakValue is equal to another WeakValue only if they refer to the same instance */
		@Override
		public boolean equals(Object o) {
			if (this == o) {
				return true;
			}

			if (o == null) {
				return false;
			}

			if (o.getClass() != getClass()) {
				return false;
			}

			WeakValue other = (WeakValue) o;
			return get() == other.get();
		}

		@Override
		public int hashCode() {
			return hash;
		}

	}

	/* Hash table mapping keys to WeakValues */
	private Map<K, WeakValue<V>> hash;

	/* Hash table mapping WeakValues to keys */
	private Map<WeakValue<V>, K> reverseHash;

	/* Reference queue for cleared WeakValues */
	private ReferenceQueue<V> queue = new ReferenceQueue<>();

	/* Remove all invalidated entries from the map, that is, remove all entries
	   whose values have been discarded.  This method should be invoked once by
	   each public mutator in this class.  We don't invoke this method in
	   public accessors because that can lead to surprising
	   ConcurrentModificationExceptions. */
	private void processQueue() {
		WeakValue<? extends V> wk;
		while ((wk = (WeakValue<? extends V>) queue.poll()) != null) {
			Object k = reverseHash.remove(wk);
			if (k != null) {
				hash.remove(k);
			}
		}
	}

	/* -- Constructors -- */

	/**
	 * Constructs a new, empty <code>WeakHashMap2</code> with the given
	 * initial capacity and the given load factor.
	 *
	 * @param  initialCapacity  The initial capacity of the
	 *                          <code>WeakHashMap2</code>
	 *
	 * @param  loadFactor       The load factor of the <code>WeakHashMap2</code>
	 *
	 * @throws IllegalArgumentException  If the initial capacity is less than
	 *                                   zero, or if the load factor is
	 *                                   nonpositive
	 */
	public WeakHashMap2(int initialCapacity, float loadFactor) {
		hash = new HashMap<>(initialCapacity, loadFactor);
		reverseHash = new HashMap<>(initialCapacity, loadFactor);
	}

	/**
	 * Constructs a new, empty <code>WeakHashMap2</code> with the given
	 * initial capacity and the default load factor, which is
	 * <code>0.75</code>.
	 *
	 * @param  initialCapacity  The initial capacity of the
	 *                          <code>WeakHashMap2</code>
	 *
	 * @throws IllegalArgumentException  If the initial capacity is less than
	 *                                   zero
	 */
	public WeakHashMap2(int initialCapacity) {
		hash = new HashMap<>(initialCapacity);
		reverseHash = new HashMap<>(initialCapacity);
	}

	/**
	 * Constructs a new, empty <code>WeakHashMap2</code> with the default
	 * initial capacity and the default load factor, which is
	 * <code>0.75</code>.
	 */
	public WeakHashMap2() {
		hash = new HashMap<>();
		reverseHash = new HashMap<>();
	}

	/**
	 * Constructs a new <code>WeakHashMap2</code> with the same mappings as the
	 * specified <tt>Map</tt>.  The <code>WeakHashMap2</code> is created with an
	 * initial capacity of twice the number of mappings in the specified map
	 * or 11 (whichever is greater), and a default load factor, which is
	 * <tt>0.75</tt>.
	 *
	 * @param   t the map whose mappings are to be placed in this map.
	 * @since	1.3
	 */
	public WeakHashMap2(Map<K, V> t) {
		this(Math.max(2 * t.size(), 11), 0.75f);
		putAll(t);
	}

	/* -- Simple queries -- */

	/**
	 * Returns the number of key-value mappings in this map.
	 * <strong>Note:</strong> <em>In contrast with most implementations of the
	 * <code>Map</code> interface, the time required by this operation is
	 * linear in the size of the map.</em>
	 */
	@Override
	public int size() {
		return entrySet().size();
	}

	/**
	 * Returns <code>true</code> if this map contains no key-value mappings.
	 */
	@Override
	public boolean isEmpty() {
		return entrySet().isEmpty();
	}

	/**
	 * Returns <code>true</code> if this map contains a mapping for the
	 * specified key.
	 *
	 * @param   key   The key whose presence in this map is to be tested
	 */
	@Override
	public boolean containsKey(Object key) {
		return hash.containsKey(key);
	}

	/* -- Lookup and modification operations -- */

	/**
	 * Returns the value to which this map maps the specified <code>key</code>.
	 * If this map does not contain a value for this key, then return
	 * <code>null</code>.
	 *
	 * @param  key  The key whose associated value, if any, is to be returned
	 */
	@Override
	public V get(Object key) {
		WeakValue<V> v = hash.get(key);
		return v != null ? v.get() : null;
	}

	/**
	 * Updates this map so that the given <code>key</code> maps to the given
	 * <code>value</code>.  If the map previously contained a mapping for
	 * <code>key</code> then that mapping is replaced and the previous value is
	 * returned.
	 *
	 * @param  key    The key that is to be mapped to the given
	 *                <code>value</code> 
	 * @param  value  The value to which the given <code>key</code> is to be
	 *                mapped
	 *
	 * @return  The previous value to which this key was mapped, or
	 *          <code>null</code> if if there was no mapping for the key
	 */
	@Override
	public V put(K key, V value) {
		processQueue();
		WeakValue<V> v = hash.get(key);
		V oldValue = null;
		if (v != null) {
			reverseHash.remove(v);
			oldValue = v.get();
		}
		v = WeakValue.create(value, queue);
		reverseHash.put(v, key);
		hash.put(key, v);
		return oldValue;
	}

	public K reverseGet(V value) {
		WeakValue v = WeakValue.create(value, queue);
		return reverseHash.get(v);
	}

	/**
	 * Removes the mapping for the given <code>key</code> from this map, if
	 * present.
	 *
	 * @param  key  The key whose mapping is to be removed
	 *
	 * @return  The value to which this key was mapped, or <code>null</code> if
	 *          there was no mapping for the key
	 */
	@Override
	public V remove(Object key) {
		processQueue();
		WeakValue<V> v = hash.get(key);
		V oldValue = null;
		if (v != null) {
			reverseHash.remove(v);
			hash.remove(key);
			oldValue = v.get();
		}
		return oldValue;
	}

	/**
	 * Removes all mappings from this map.
	 */
	@Override
	public void clear() {
		processQueue();
		reverseHash.clear();
		hash.clear();
	}

	/* -- Views -- */

	/* Internal class for entries */
	static private class Entry<K, V> implements Map.Entry<K, V> {
		private K key;
		private V value; /* Strong reference to value, so that the GC
							will leave it alone as long as this Entry
							exists */

		Entry(K key, V value) {
			this.key = key;
			this.value = value;
		}

		@Override
		public K getKey() {
			return key;
		}

		@Override
		public V getValue() {
			return value;
		}

		@Override
		public V setValue(V value) {
			V oldValue = this.value;
			this.value = value;
			return oldValue;
		}

		@Override
		public boolean equals(Object o) {
			if (!(o instanceof Map.Entry)) {
				return false;
			}
			Map.Entry<?, ?> e = (Map.Entry<?, ?>) o;

			return (key == null ? e.getKey() == null : key.equals(e.getKey())) &&
				(value == null ? e.getValue() == null : value.equals(e.getValue()));
		}

		@Override
		public int hashCode() {
			Object v;
			return (((key == null) ? 0 : key.hashCode()) ^
				(((v = getValue()) == null) ? 0 : v.hashCode()));
		}

	}

	/* Internal class for entry sets */
	private class EntrySet extends AbstractSet<Map.Entry<K, V>> {

		private Set<Map.Entry<K, WeakValue<V>>> hashEntrySet;

		public EntrySet() {
			hashEntrySet = hash.entrySet();
		}

		@Override
		public Iterator<Map.Entry<K, V>> iterator() {
			return new Iterator<Map.Entry<K, V>>() {
				Iterator<Map.Entry<K, WeakValue<V>>> hashIterator = hashEntrySet.iterator();
				Entry<K, V> next = null;

				@Override
				public boolean hasNext() {
					while (hashIterator.hasNext()) {
						Map.Entry<K, WeakValue<V>> ent = hashIterator.next();

						WeakValue<V> wv = ent.getValue();
						V v = null;
						if ((wv != null) && ((v = wv.get()) == null)) {
							/* Weak value has been cleared by GC */
							continue;
						}

						next = new Entry<>(ent.getKey(), v);
						return true;
					}
					return false;
				}

				@Override
				public Entry<K, V> next() {
					if ((next == null) && !hasNext()) {
						throw new NoSuchElementException();
					}
					Entry<K, V> e = next;
					next = null;
					return e;
				}

				@Override
				public void remove() {
					hashIterator.remove();
				}

			};
		}

		@Override
		public boolean isEmpty() {
			return !(iterator().hasNext());
		}

		@Override
		public int size() {
			int j = 0;
			for (Iterator<Map.Entry<K, V>> i = iterator(); i.hasNext(); i.next()) {
				j++;
			}
			return j;
		}

		@Override
		public boolean remove(Object o) {
			processQueue();
			if (!(o instanceof Map.Entry)) {
				return false;
			}
			Entry<?, ?> e = (Entry<?, ?>) o;

			Object key = e.getKey();
			WeakValue<?> v = hash.get(key);
			if (v != null) {
				reverseHash.remove(v);
				hash.remove(key);
				return true;
			}
			return false;
		}

		@Override
		public int hashCode() {
			int h = 0;
			for (java.util.Map.Entry<K, WeakValue<V>> ent : hashEntrySet) {
				Object v;
				h += (ent.getKey().hashCode() ^
					(((v = ent.getValue()) == null) ? 0 : v.hashCode()));
			}
			return h;
		}

	}

	private Set<Map.Entry<K, V>> entrySet = null;

	/**
	 * Returns a <code>Set</code> view of the mappings in this map.
	 */
	@Override
	public Set<Map.Entry<K, V>> entrySet() {
		if (entrySet == null) {
			entrySet = new EntrySet();
		}
		return entrySet;
	}

}
