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

/**
 * Soft reference cache class that caches objects for long keys. This cache will
 * store at most "cacheSize" number of entries, but since it uses soft references
 * for the cached values, those object may be reclaimed.
 */

public class SoftCacheLongKeyMap  {
	private int cacheSize;
	private ReferenceQueue<Object> refQueue;
	private Entry head;
	private LongObjectHashtable<Object> map;
	
	/**
	 * Construct a new SoftCacheLongKeyMap that caches at most cacheSize number of entries
	 * @param cacheSize the max number of entries to cache.
	 */
	public SoftCacheLongKeyMap(int cacheSize) {
		this.cacheSize = Math.max(cacheSize, 10);
		map = new LongObjectHashtable<>();
		head = new Entry(0, null);
		head.nextEntry = head;
		head.prevEntry = head;
		refQueue = new ReferenceQueue<>();
	}
	/**
	 * Caches the given value for the given key
	 * @param key the key
	 * @param value the cached value for the given key
	 * @return any previous object that is cached for the given key.
	 */
	public Object put(long key, Object value) {
		processQueue();
		if (map.size() == cacheSize) {
			remove(head.nextEntry.key);
		}
		Object obj = map.remove(key);
		Entry entry = new Entry(key, value);
		head.addBefore(entry);
		map.put(key, entry);
		return obj;
	}
	
	/**
	 * Returns the cached value for the given key, if it exists.
	 * @param key the key for which to get a cached value.
	 * @return the object that was cached for that key, or null if none exists.
	 */
	public Object get(long key) {
		processQueue();
		Entry entry = (Entry)map.get(key);
		if (entry != null) {
			entry.delete();
			head.addBefore(entry);
			return entry.get();
		}
		return null;
	}
	
	/**
	 * Returns the number of items in the cache.  Can change from one call to 
	 * the next even if no entries were added or deleted.
	 */
	public int size() {
		processQueue();
		return map.size();
	}

	/**
	 * Removes all entries from the cache
	 */
	public void clear() {
		map.removeAll();
		refQueue = new ReferenceQueue<>();
	}

	/**
	 * Returns true if the cache is empty. If true, it will remain empty until a new
	 * entry is added. However if false, it may return true even if nothing was removed
	 */
	public boolean isEmpty() {
		processQueue();
		return map.size() == 0;
	}
	/**
	 * Returns true if the cache currently contains the given key. Not useful since even
	 * if it returns true, there is no guarentee that a get will work after containsKey
	 * returns true.
	 * @param key the Key to check
	 */
	public boolean containsKey(long key) {
		processQueue();
		return map.contains(key);
	}

	/**
	 * Removes any cached value for the given key.
	 * @param key the key for which to remove cached values.
	 * @return the cached object that was stored for the given key, or null
	 */
	public Object remove(long key) {
		Entry entry = (Entry)map.remove(key);
		if (entry != null) {
			entry.delete();
			return entry.get();
		}
		return null;
	}
	
	/**
	 * Returns a list of all current keys.
	 */
	public long[] getKeys() {
		processQueue();
		return map.getKeys();
	}
	private void processQueue() {
		Entry entry;
		while((entry = (Entry)refQueue.poll()) != null) {
			remove(entry.key);	
		}
	}

	class Entry extends SoftReference<Object> {
		long key;
		Entry nextEntry;
		Entry prevEntry;
		Entry(long key, Object value) {
			super(value, refQueue);
			this.key = key;
		}
		void addBefore(Entry entry) {
			entry.nextEntry = this;
			entry.prevEntry = this.prevEntry;
			this.prevEntry.nextEntry = entry;
			this.prevEntry = entry;
		}
		void delete() {
			prevEntry.nextEntry = nextEntry;
			nextEntry.prevEntry = prevEntry;
		}
	}

}
