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
package generic.cache;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.*;
import java.util.function.Consumer;
import java.util.function.Predicate;

import org.apache.commons.collections4.map.LRUMap;

/**
 * Generic cache implementation that removes items from the cache when they are no longer
 * referenced. It uses weak references for the values and a small hard cache
 * so that recent items don't get garbage collected immediately.
 * <P>
 * This class is thread safe. All public methods are synchronized.
 * 
 * @param <K> The type of the object stored in this cache
 * @param <V> The type of the object stored in this cache
 */
public class WeakReferenceCache<K, V> {

	private Map<K, KeyedReference<K, V>> refsById;
	private ReferenceQueue<V> refQueue;
	private LRUMap<K, V> hardCache;

	/**
	 * Constructs a new WeakReferenceCache with a given hard cache size.  The hard cache size is
	 * the minimum number of objects to keep in the cache. Typically, the cache will contain
	 * more than this number, but the excess objects are subject to garbage collection.
	 * @param hardCacheSize the minimum number of objects to keep in the cache.
	 */
	public WeakReferenceCache(int hardCacheSize) {
		refsById = new HashMap<>();
		refQueue = new ReferenceQueue<>();

		hardCache = new LRUMap<>(hardCacheSize);
	}

	/**
	 * Retrieves the database object with the given key from the cache.
	 * @param key the key of the object to retrieve.
	 * @return the cached object or null if the object with that key is not currently cached.
	 */
	public synchronized V get(K key) {
		KeyedReference<K, V> ref = refsById.get(key);
		if (ref == null) {
			return null;
		}
		V v = ref.get();
		if (v == null) {
			refsById.remove(key);
			return null;
		}
		hardCache.put(key, v);
		return v;
	}

	/**
	 * Returns the number of objects currently in the cache.
	 * @return the number of objects currently in the cache.
	 */
	public synchronized int size() {
		return refsById.size();
	}

	/**
	 * Sets the number of objects to protect against garbage collection.
	 * @param size the minimum number of objects to keep in the cache.
	 */
	public synchronized void setHardCacheSize(int size) {
		hardCache.clear();
		hardCache = new LRUMap<>(size);
	}

	/**
	 * Adds the given database object to the cache.
	 * @param key the key for the cached object
	 * @param data the object to add to the cache
	 * @return the object that has been added to the cache
	 */
	public synchronized V add(K key, V data) {
		processQueue();
		hardCache.put(key, data);
		KeyedReference<K, V> ref = new KeyedReference<>(key, data, refQueue);
		refsById.put(key, ref);
		return data;
	}

	/**
	 * Returns an List of all the cached objects.
	 * @return an List of all the cached objects.
	 */
	public synchronized List<V> getCachedObjects() {
		List<V> list = new ArrayList<>();
		processQueue();
		for (KeyedReference<K, V> ref : refsById.values()) {
			V v = ref.get();
			if (v != null) {
				list.add(v);
			}
		}
		return list;
	}

	/**
	 * Applies the given consumer to all values in the cache.
	 * @param consumer the consumer to apply to all values in the cache
	 */
	public synchronized void apply(Consumer<V> consumer) {
		processQueue();
		for (KeyedReference<K, V> ref : refsById.values()) {
			V v = ref.get();
			if (v != null) {
				consumer.accept(v);
			}
		}
	}

	/**
	 * Removes the object with the given key from the cache.
	 * @param key the key of the object to remove
	 * @return the value that was removed from the cache
	 */
	public synchronized V delete(K key) {
		processQueue();
		KeyedReference<K, V> ref = refsById.remove(key);
		V v = null;
		if (ref != null) {
			v = ref.get();
			ref.clear();
		}
		return v;
	}

	public synchronized void deleteIf(Predicate<V> predicate) {
		Iterator<KeyedReference<K, V>> iterator = refsById.values().iterator();
		while (iterator.hasNext()) {
			KeyedReference<K, V> ref = iterator.next();
			V v = ref.get();
			if (v == null || predicate.test(v)) {
				iterator.remove();
			}
		}
	}

	// we know the cast is safe--we put them in there
	@SuppressWarnings("unchecked")
	private void processQueue() {
		KeyedReference<K, V> ref;
		while ((ref = (KeyedReference<K, V>) refQueue.poll()) != null) {
			K key = ref.getKey();
			KeyedReference<K, V> oldValue = refsById.remove(key);

			if (oldValue != null && oldValue != ref) {
				// we have put another item in the cache with the same key.  Further, we
				// removed the item, but the garbage collector had not put the item on the
				// reference queue until after we added a new reference to the cache.
				// We want to keep the last value that was added, as it has not been deleted.
				refsById.put(key, oldValue);
			}
		}
	}

	private static class KeyedReference<K, V> extends WeakReference<V> {
		private K key;

		KeyedReference(K key, V obj, ReferenceQueue<V> queue) {
			super(obj, queue);
			this.key = key;
		}

		K getKey() {
			return key;
		}
	}

}
