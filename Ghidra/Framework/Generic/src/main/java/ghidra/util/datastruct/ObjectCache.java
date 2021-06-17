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
 * <code>ObjectClass</code> provides a fixed-size long-key-based object cache.
 * Both a hard and weak cache are maintained, where the weak cache is only
 * limited by available memory.  This cache mechanism is useful in ensuring that
 * only a single object instance for a given key exists.
 * <p>
 * The weak cache is keyed, while the hard cache simply maintains the presence of
 * an object in the weak cache.
 */
public class ObjectCache {

	private Map<Long, KeyedSoftReference<?>> hashTable;
	private ReferenceQueue<Object> refQueue;
	private LinkedList<Object> hardCache;
	private int hardCacheSize;

	/**
	 * Construct a keyed-object cache of size hardCacheSize.
	 * @param hardCacheSize hard cache size.
	 */
	public ObjectCache(int hardCacheSize) {
		this.hardCacheSize = hardCacheSize;
		hashTable = new HashMap<>();
		refQueue = new ReferenceQueue<>();
		hardCache = new LinkedList<>();
	}

	/**
	 * Determine if the keyed-object exists in the cache.
	 * @param key object key
	 * @return true if object is cached
	 */
	public synchronized boolean contains(long key) {
		processQueue();
		return hashTable.containsKey(key);
	}

	/**
	 * Get the object from cache which corresponds to the specified key.
	 * @param key object key
	 * @return cached object
	 */
	public synchronized Object get(long key) {
		WeakReference<?> ref = hashTable.get(key);
		if (ref != null) {
			Object obj = ref.get();
			if (obj == null) {
				hashTable.remove(key);
			}
			addToHardCache(obj);
			return obj;
		}
		return null;
	}

	/**
	 * Return the hard cache size
	 * @return the hard cache size
	 */
	public int size() {
		return hardCacheSize;
	}

	/**
	 * Adjust the hard cache size
	 * @param size new hard cache size
	 */
	public synchronized void setHardCacheSize(int size) {
		while (hardCache.size() > size) {
			hardCache.removeLast();
		}
		this.hardCacheSize = size;
	}

	/**
	 * Add an object to the cache
	 * @param key object key
	 * @param obj the object
	 */
	public synchronized void put(long key, Object obj) {
		processQueue();
		KeyedSoftReference<?> ref = new KeyedSoftReference<>(key, obj, refQueue);
		hashTable.put(key, ref);
		addToHardCache(obj);
	}

	/**
	 * Remove the specified keyed object from both hard and weak caches.
	 * An object should be removed from the cache when it becomes invalid.
	 * @param key object key
	 */
	public synchronized void remove(long key) {
		processQueue();
		KeyedSoftReference<?> ref = hashTable.get(key);
		if (ref != null) {
			ref.clear();
			hashTable.remove(key);
		}
	}

	/**
	 * Add the specified object to the hard cache.
	 * @param obj object
	 */
	private void addToHardCache(Object obj) {
		hardCache.addLast(obj);
		if (hardCache.size() > hardCacheSize) {
			hardCache.removeFirst();
		}
	}

	/**
	 * Cleanup weak cache
	 */
	private void processQueue() {
		KeyedSoftReference<?> ref;
		while ((ref = (KeyedSoftReference<?>) refQueue.poll()) != null) {
			hashTable.remove(ref.getKey());
		}
	}

	/**
	 * Provides a weak wrapper for a keyed-object
	 */
	private static class KeyedSoftReference<T> extends WeakReference<T> {
		private long key;

		/**
		 * Construct a keyed-object reference
		 * @param key object key
		 * @param obj object
		 * @param queue reference queue
		 */
		KeyedSoftReference(long key, T obj, ReferenceQueue<T> queue) {
			super(obj, queue);
			this.key = key;
		}

		/**
		 * Return object key
		 * @return object key
		 */
		long getKey() {
			return key;
		}
	}

}
