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
import java.lang.ref.SoftReference;
import java.util.*;
import java.util.AbstractMap.SimpleImmutableEntry;

/**
 * Class to manage a "soft" HaspMap that keeps its keys as soft references so
 * they can be reclaimed if needed. Useful for caching.
 */

public class SoftCacheMap<K, V> implements Map<K, V> {
	private int cacheSize;
	private LinkedHashMap<K, MySoftReference> map;
	private ReferenceQueue<? super V> refQueue;

	/**
	 * Constructs a new SoftCacheMap that has at most cacheSize entries.
	 * @param cacheSize the max number of entries to cache.
	 */
	public SoftCacheMap(int cacheSize) {
		this.cacheSize = cacheSize;
		map = new FixedSizeHashMap<>(cacheSize, cacheSize);
		refQueue = new ReferenceQueue<>();
	}

	/**
	 * @see java.util.Map#put(java.lang.Object, java.lang.Object)
	 */
	@Override
	public V put(K key, V value) {
		processQueue();
		MySoftReference ref = new MySoftReference(key, value);
		MySoftReference oldRef = map.put(key, ref);
		if (oldRef != null) {
			return oldRef.get();
		}
		return null;
	}

	/**
	 * @see java.util.Map#get(java.lang.Object)
	 */
	@Override
	public V get(Object key) {
		processQueue();
		MySoftReference ref = map.get(key);
		if (ref != null) {
			return ref.get();
		}
		return null;
	}

	/**
	 * @see java.util.Map#size()
	 */
	@Override
	public int size() {
		processQueue();
		return map.size();
	}

	/**
	 * @see java.util.Map#clear()
	 */
	@Override
	public void clear() {
		map.clear();
		refQueue = new ReferenceQueue<>();
	}

	/**
	 * @see java.util.Map#isEmpty()
	 */
	@Override
	public boolean isEmpty() {
		processQueue();
		return map.isEmpty();
	}

	/**
	 * @see java.util.Map#containsKey(java.lang.Object)
	 */
	@Override
	public boolean containsKey(Object key) {
		processQueue();
		return map.containsKey(key);
	}

	/**
	 * @see java.util.Map#containsValue(java.lang.Object)
	 */
	@Override
	public boolean containsValue(Object value) {
		processQueue();
		Iterator<MySoftReference> it = map.values().iterator();
		while (it.hasNext()) {
			MySoftReference ref = it.next();
			if (value.equals(ref.get())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @see java.util.Map#values()
	 */
	@Override
	public Collection<V> values() {
		List<V> list = new ArrayList<>(map.size());
		Iterator<MySoftReference> it = map.values().iterator();
		while (it.hasNext()) {
			MySoftReference ref = it.next();
			V obj = ref.get();
			if (obj != null) {
				list.add(obj);
			}
		}
		return list;
	}

	/**
	 * @see java.util.Map#putAll(java.util.Map)
	 */
	@Override
	public void putAll(Map<? extends K, ? extends V> t) {
		Iterator<? extends K> it = t.keySet().iterator();
		while (it.hasNext()) {
			K key = it.next();
			V value = t.get(key);
			if (value != null) {
				put(key, value);
			}
		}
	}

	/**
	 * @see java.util.Map#entrySet()
	 */
	@Override
	public Set<Map.Entry<K, V>> entrySet() {
		processQueue();

		Set<Map.Entry<K, V>> result = new HashSet<>();
		Set<Entry<K, MySoftReference>> entrySet = map.entrySet();
		for (Entry<K, MySoftReference> entry : entrySet) {
			MySoftReference value = entry.getValue();
			V realValue = value.get();
			if (realValue != null) {
				SimpleImmutableEntry<K, V> newEntry =
					new AbstractMap.SimpleImmutableEntry<>(entry.getKey(), realValue);
				result.add(newEntry);
			}
		}

		return result;
	}

	/**
	 * @see java.util.Map#keySet()
	 */
	@Override
	public Set<K> keySet() {
		processQueue();
		return map.keySet();
	}

	/**
	 * @see java.util.Map#remove(java.lang.Object)
	 */
	@Override
	public V remove(Object key) {
		MySoftReference ref = map.remove(key);
		if (ref != null) {
			return ref.get();
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	private void processQueue() {
		MySoftReference ref;
		while ((ref = (MySoftReference) refQueue.poll()) != null) {
			map.remove(ref.key);
		}
	}

	class MySoftReference extends SoftReference<V> {
		K key;

		MySoftReference(K key, V value) {
			super(value, refQueue);
			this.key = key;
		}
	}

}
