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

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.*;

/**
 * Class to provide a map with weak values, backed by a given map
 *
 * @param <K> the type of keys
 * @param <V> the type of values
 */
public abstract class AbstractWeakValueMap<K, V> implements Map<K, V> {
	protected ReferenceQueue<V> refQueue;

	/**
	 * Constructs a new weak map
	 */
	protected AbstractWeakValueMap() {
		refQueue = new ReferenceQueue<>();
	}

	/**
	 * Returns the backing map
	 * 
	 * @return the map
	 */
	protected abstract Map<K, WeakValueRef<K, V>> getRefMap();

	@Override
	public V put(K key, V value) {
		processQueue();
		WeakValueRef<K, V> ref = new WeakValueRef<>(key, value, refQueue);
		WeakValueRef<K, V> oldRef = getRefMap().put(key, ref);
		if (oldRef != null) {
			return oldRef.get();
		}
		return null;
	}

	@Override
	public V get(Object key) {
		processQueue();
		WeakValueRef<K, V> ref = getRefMap().get(key);
		if (ref != null) {
			return ref.get();
		}
		return null;
	}

	@Override
	public int size() {
		processQueue();
		return getRefMap().size();
	}

	@Override
	public void clear() {
		getRefMap().clear();
		refQueue = new ReferenceQueue<>();
	}

	@Override
	public boolean isEmpty() {
		processQueue();
		return getRefMap().isEmpty();
	}

	@Override
	public boolean containsKey(Object key) {
		processQueue();
		return getRefMap().containsKey(key);
	}

	@Override
	public boolean containsValue(Object value) {
		processQueue();
		Iterator<WeakValueRef<K, V>> it = getRefMap().values().iterator();
		while (it.hasNext()) {
			WeakValueRef<K, V> ref = it.next();
			if (value.equals(ref.get())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns a {@link Collection} view of the values contained in this map.
	 * The collection is backed by the map, so changes to the map are
	 * reflected in the collection, and vice-versa. However, since values in this map
	 * are held via weak references, the collection returned is effectively weak in that
	 * any time, values may disappear from the collection. To get a static view of the values
	 * in this map, you should construct another collection class (List, Set, etc.) and pass
	 * this collection to it in its constructor.
	 */
	@Override
	public Collection<V> values() {
		processQueue();
		return new WeakValuesCollection();
	}

	@Override
	public void putAll(Map<? extends K, ? extends V> map) {
		Iterator<? extends K> it = map.keySet().iterator();
		while (it.hasNext()) {
			K key = it.next();
			V value = map.get(key);
			if (value != null) {
				put(key, value);
			}
		}
	}

	@Override
	public Set<Map.Entry<K, V>> entrySet() {
		return new EntrySet();
	}

	@Override
	public Set<K> keySet() {
		processQueue();
		return getRefMap().keySet();
	}

	@Override
	public V remove(Object key) {
		WeakValueRef<K, V> ref = getRefMap().remove(key);
		if (ref != null) {
			return ref.get();
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	protected void processQueue() {
		WeakValueRef<K, V> ref;
		while ((ref = (WeakValueRef<K, V>) refQueue.poll()) != null) {
			getRefMap().remove(ref.key);
		}
	}

	/**
	 * An entry for the "entrySet" method, since internally, entries are of weak-referenced values.
	 */
	protected class GeneratedEntry implements Map.Entry<K, V> {
		K key;
		V value;

		GeneratedEntry(K key, V value) {
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
			throw new UnsupportedOperationException();
		}

	}

	/**
	 * A weak value ref that also knows its key in the map.
	 * 
	 * <p>
	 * Used for processing the reference queue, so we know which keys to remove.
	 * 
	 * @param <K> the type of key
	 * @param <V> the type of value
	 */
	protected static class WeakValueRef<K, V> extends WeakReference<V> {
		K key;

		WeakValueRef(K key, V value, ReferenceQueue<V> refQueue) {
			super(value, refQueue);
			this.key = key;
		}
	}

	/**
	 * Wrapper that provides a Collection view of the values in this map. 
	 * The collection is backed by the map, so changes to the map are
	 * reflected in the collection, and vice-versa. This collection has
	 * weak values and all the magic to handle that is in the {@link WeakValuesIterator}
	 * implementation.
	 */
	private class WeakValuesCollection extends AbstractCollection<V> {

		@Override
		public Iterator<V> iterator() {
			return new WeakValuesIterator();
		}

		@Override
		public int size() {
			return AbstractWeakValueMap.this.size();
		}
	}

	/**
	 * Iterator that handles iterating over weak values. This iterator will find the next 
	 * non-null value by checking each WeakReference to find a value that has not been garbage
	 * collected. The next non-null value is found during the {@link #hasNext()} call and is
	 * held onto via a strong reference to guarantee that if hasNext returns true, you will get
	 * a non-null value on the call to {@link #next()}.
	 * 
	 */
	private class WeakValuesIterator implements Iterator<V> {

		private Iterator<Entry<K, WeakValueRef<K, V>>> refMapIterator;
		private V nextValue;

		public WeakValuesIterator() {
			refMapIterator = getRefMap().entrySet().iterator();
		}

		@Override
		public boolean hasNext() {
			while (nextValue == null && refMapIterator.hasNext()) {
				Entry<K, WeakValueRef<K, V>> next = refMapIterator.next();
				nextValue = next.getValue().get();
			}
			return nextValue != null;
		}

		@Override
		public V next() {
			if (!hasNext()) {
				throw new NoSuchElementException();
			}
			V returnValue = nextValue;
			nextValue = null;
			return returnValue;
		}

		@Override
		public void remove() {
			refMapIterator.remove();
		}
	}

	/**
	 * This iterator works much like the {@link WeakValuesIterator}, except that this iterator
	 * works on Map Entry objects.
	 */
	private class EntryIterator implements Iterator<Map.Entry<K, V>> {

		private Iterator<Entry<K, WeakValueRef<K, V>>> refMapIterator;
		private K nextKey;
		private V nextValue;

		public EntryIterator() {
			refMapIterator = getRefMap().entrySet().iterator();
		}

		@Override
		public boolean hasNext() {
			while (nextValue == null && refMapIterator.hasNext()) {
				Entry<K, WeakValueRef<K, V>> next = refMapIterator.next();
				nextKey = next.getKey();
				nextValue = next.getValue().get();
			}
			return nextValue != null;
		}

		@Override
		public Map.Entry<K, V> next() {
			if (!hasNext()) {
				throw new NoSuchElementException();
			}
			Map.Entry<K, V> result = new GeneratedEntry(nextKey, nextValue);
			nextKey = null;
			nextValue = null;
			return result;
		}

		@Override
		public void remove() {
			refMapIterator.remove();
		}

	}

	/**
	 * Class that provides a {@link Set} view of the entry set of this map that is backed live
	 * by this map. Its main job is to translate from Map.Entry<K, WeakValueRef<V>> to 
	 * Map.Entry<K,V>. The heavy lifting is done by the EntryIterator. The super class implements
	 * all the rest of the methods by leveraging the iterator. We implement
	 * contains, remove, and clear as they can be implemented much more efficiently than the 
	 * default implementation which iterates over all the values to do those operations.
	 */
	private class EntrySet extends AbstractSet<Map.Entry<K, V>> {
		public Iterator<Map.Entry<K, V>> iterator() {
			return new EntryIterator();
		}

		public boolean contains(Object o) {
			if (o instanceof Map.Entry<?, ?> e) {
				Object key = e.getKey();
				Object v = get(key);
				return Objects.equals(v, e.getValue());
			}
			return false;
		}

		public boolean remove(Object o) {
			if (o instanceof Map.Entry<?, ?> e) {
				Object key = e.getKey();
				Object v = get(key);
				if (Objects.equals(v, e.getValue())) {
					remove(key);
					return true;
				}
			}
			return false;

		}

		public int size() {
			return AbstractWeakValueMap.this.size();
		}

		public void clear() {
			AbstractWeakValueMap.this.clear();
		}

	}

}
