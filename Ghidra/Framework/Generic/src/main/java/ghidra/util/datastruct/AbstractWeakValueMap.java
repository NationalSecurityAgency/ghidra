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

	@Override
	public Collection<V> values() {
		ArrayList<V> list = new ArrayList<>(getRefMap().size());
		Iterator<WeakValueRef<K, V>> it = getRefMap().values().iterator();
		while (it.hasNext()) {
			WeakValueRef<K, V> ref = it.next();
			V value = ref.get();
			if (value != null) {
				list.add(value);
			}
		}
		return list;
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
		processQueue();
		Set<Map.Entry<K, V>> list = new HashSet<>();
		Set<Map.Entry<K, WeakValueRef<K, V>>> entrySet = getRefMap().entrySet();
		Iterator<Map.Entry<K, WeakValueRef<K, V>>> it = entrySet.iterator();
		while (it.hasNext()) {
			Map.Entry<K, WeakValueRef<K, V>> next = it.next();
			WeakValueRef<K, V> valueRef = next.getValue();
			V value = valueRef.get();
			if (value != null) {
				list.add(new GeneratedEntry(next.getKey(), value));
			}
		}
		return list;
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
			this.value = value;
			return put(key, value);
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
}
