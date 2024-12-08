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
package ghidra.util.timer;

import java.time.Duration;
import java.util.*;
import java.util.Map.Entry;

/**
 * Class for caching key,value entries for a limited time and cache size. Entries in this cache
 * will be removed after the cache duration time has passed. If the cache ever exceeds its capacity,
 * the least recently used entry will be removed.
 * <P>
 * This class uses a {@link LinkedHashMap} with it ordering mode set to "access order". This means
 * that iterating through keys, values, or entries of the map will be presented oldest first. 
 * Inserting or accessing an entry in the map will move the entry to the back of the list, thus
 * making it the youngest. This means that entries closest to or past expiration will be presented
 * first. 
 * <P>
 * This class is designed to be subclassed for two specific cases. The first case is for when 
 * additional processing is required when an entry is removed from the cache. This typically would
 * be for cases where resources need to be released, such as closing a File or disposing the object.
 * The second reason to subclass this cache is to get more control of expiring values. Overriding
 * {@link #shouldRemoveFromCache(Object, Object)}, which gets called when an entry's time
 * has expired, gives the client a chance to decide if the entry should be removed.
 *
 * @param <K> the key
 * @param <V> the value
 */
public class GTimerCache<K, V> {
	// These defines are the HashMap defaults, but the map class didn't provide public constants
	private static final int INITIAL_MAP_SIZE = 16;
	private static final float LOAD_FACTOR = 0.75f;

	private int capacity;
	private long lifetime;
	private Runnable timerExpiredRunnable = this::timerExpired;

	// the following fields should only be used in synchronized blocks
	private Map<K, CachedValue> map;
	private GTimerMonitor timerMonitor;

	/**
	 * Constructs new GTimerCache with a duration for cached entries and a maximum
	 * number of entries to cache.
	 * @param lifetime the duration that a key,value will remain in the cache without being
	 * accessed (accessing a cached entry resets its time)
	 * @param capacity the maximum number of entries in the cache before least recently used
	 * entries are removed
	 */
	public GTimerCache(Duration lifetime, int capacity) {
		if (lifetime.isZero() || lifetime.isNegative()) {
			throw new IllegalArgumentException("The duration must be a time > 0!");
		}
		if (capacity < 1) {
			throw new IllegalArgumentException("The capacity must be > 0!");
		}
		this.lifetime = lifetime.toMillis();
		this.capacity = capacity;

		map = new LinkedHashMap<>(INITIAL_MAP_SIZE, LOAD_FACTOR, true) {
			@Override
			protected boolean removeEldestEntry(Entry<K, CachedValue> eldest) {
				if (size() > GTimerCache.this.capacity) {
					valueRemoved(eldest.getKey(), eldest.getValue().getValue());
					return true;
				}
				return false;
			}
		};
	}

	/**
	 * Sets the capacity for this cache. If this cache currently has more values than the new
	 * capacity, oldest values will be removed.
	 * @param capacity the new capacity for this cache
	 */
	public synchronized void setCapacity(int capacity) {
		if (capacity < 1) {
			throw new IllegalArgumentException("The capacity must be > 0!");
		}
		this.capacity = capacity;
		if (map.size() <= capacity) {
			return;
		}

		Iterator<Entry<K, CachedValue>> it = map.entrySet().iterator();
		int n = map.size() - capacity;
		for (int i = 0; i < n; i++) {
			Entry<K, CachedValue> next = it.next();
			it.remove();
			CachedValue value = next.getValue();
			valueRemoved(value.getKey(), value.getValue());
		}
	}

	/**
	 * Sets the duration for keeping cached values.
	 * @param duration the length of time to keep a cached value
	 */
	public synchronized void setDuration(Duration duration) {
		if (duration.isZero() || duration.isNegative()) {
			throw new IllegalArgumentException("The duration must be a time > 0!");
		}

		this.lifetime = duration.toMillis();
		if (timerMonitor != null) {
			timerMonitor.cancel();
			timerMonitor = null;
		}
		timerExpired();// this will purge any older values and reset the timer to the correct delay
	}

	/**
	 * Adds an key,value entry to the cache
	 * @param key the key with which the value is associated
	 * @param value the value being cached
	 * @return The previous value associated with the key or null if no previous value
	 */
	public synchronized V put(K key, V value) {
		Objects.requireNonNull(key);
		Objects.requireNonNull(value);

		CachedValue old = map.put(key, new CachedValue(key, value));
		V previous = old == null ? null : old.getValue();
		if (!Objects.equals(value, previous)) {
			if (previous != null) {
				valueRemoved(key, previous);
			}
			valueAdded(key, value);
		}

		if (timerMonitor == null) {
			timerMonitor = GTimer.scheduleRunnable(lifetime, timerExpiredRunnable);
		}
		return previous;
	}

	/**
	 * Removes the cache entry with the given key.
	 * @param key the key of the entry to remove
	 * @return the value removed or null if the key wasn't in the cache
	 */
	public synchronized V remove(K key) {
		CachedValue removed = map.remove(key);
		if (removed == null) {
			return null;
		}
		valueRemoved(removed.getKey(), removed.getValue());
		return removed.value;
	}

	/**
	 * Returns true if the cache contains a value for the given key.
	 * @param key the key to check if it is in the cache
	 * @return true if the cache contains a value for the given key
	 */
	public synchronized boolean containsKey(K key) {
		return map.containsKey(key);
	}

	/**
	 * Returns the number of entries in the cache.
	 * @return the number of entries in the cache
	 */
	public synchronized int size() {
		return map.size();
	}

	/**
	 * Returns the value for the given key. Also, resets time the associated with this entry.
	 * @param key the key to retrieve a value
	 * @return the value for the given key
	 */
	public synchronized V get(K key) {
		// Note: the map's get() updates its access order
		CachedValue cachedValue = map.get(key);
		if (cachedValue == null) {
			return null;
		}
		cachedValue.updateAccessTime();
		return cachedValue.getValue();
	}

	/**
	 * Clears all the values in the cache. The expired callback will be called for each entry
	 * that was in the cache.
	 */
	public synchronized void clear() {
		for (Entry<K, CachedValue> entry : map.entrySet()) {
			CachedValue value = entry.getValue();
			valueRemoved(value.getKey(), value.getValue());
		}
		map.clear();
	}

	/**
	 * Called when an item is being removed from the cache. This method is for use by subclasses 
	 * that need to do more processing on items as they are removed, such as releasing resources.
	 * <P>
	 * Note: this method will always be called from within a synchronized block. Subclasses should
	 * be careful if they make any external calls from within this method.
	 *
	 * @param key The key of the value being removed
	 * @param value the value that is being removed
	 */
	protected void valueRemoved(K key, V value) {
		// stub for subclasses
	}

	/**
	 * Called when an value is being added to the cache. This method is for use by
	 * subclasses that need to do more processing on items when they are added to the cache.
	 * <P>
	 * Note: this method will always be called from within a synchronized block. Subclasses should
	 * be careful if they make any external calls from within this method.
	 *
	 * @param key The key of the value being added
	 * @param value the new value
	 */
	protected void valueAdded(K key, V value) {
		// stub for subclasses
	}

	/**
	 * Called when an item's cache time has expired to determine if the item should be removed from
	 * the cache. The default to to remove an item when its time has expired. Subclasses can 
	 * override this method to have more control over expiring value removal.
	 * <P>
	 * Note: this method will always be called from within a synchronized block. Subclasses should
	 * be careful if they make any external calls from within this method.
	 * 
	 * @param key the key of the item whose time has expired
	 * @param value the value of the item whose time has expired
	 * @return true if the item should be removed, false otherwise
	 */
	protected boolean shouldRemoveFromCache(K key, V value) {
		return true;
	}

	private synchronized void timerExpired() {
		timerMonitor = null;
		long eventTime = System.currentTimeMillis();
		List<CachedValue> expiredValues = getAndRemoveExpiredValues(eventTime);
		purgeOrReinstateExpiredValues(expiredValues);
		restartTimer(eventTime);
	}

	private List<CachedValue> getAndRemoveExpiredValues(long eventTime) {
		List<CachedValue> expiredValues = new ArrayList<>();

		Iterator<CachedValue> it = map.values().iterator();
		while (it.hasNext()) {
			CachedValue next = it.next();
			if (!next.isExpired(eventTime)) {
				// since the map is ordered by expire time, none that follow can be expired
				break;
			}
			expiredValues.add(next);
			it.remove();
		}
		return expiredValues;
	}

	private void purgeOrReinstateExpiredValues(List<CachedValue> expiredValues) {
		for (CachedValue cachedValue : expiredValues) {
			if (shouldRemoveFromCache(cachedValue.getKey(), cachedValue.getValue())) {
				valueRemoved(cachedValue.getKey(), cachedValue.getValue());
			}
			else {
				// The client wants to keep the entry in the cache. We've decided to treat this like
				// adding a new entry.
				cachedValue.updateAccessTime();
				map.put(cachedValue.getKey(), cachedValue);
			}
		}
	}

	private void restartTimer(long eventTime) {
		if (map.isEmpty()) {
			return;
		}

		CachedValue first = map.values().iterator().next();
		long elapsed = eventTime - first.getLastAccessedTime();
		long remaining = lifetime - elapsed;
		timerMonitor = GTimer.scheduleRunnable(remaining, timerExpiredRunnable);
	}

	private class CachedValue {
		private final K key;
		private final V value;
		private long lastAccessedTime;

		CachedValue(K key, V value) {
			this.key = key;
			this.value = value;
			this.lastAccessedTime = System.currentTimeMillis();
		}

		void updateAccessTime() {
			lastAccessedTime = System.currentTimeMillis();
		}

		long getLastAccessedTime() {
			return lastAccessedTime;
		}

		K getKey() {
			return key;
		}

		V getValue() {
			return value;
		}

		boolean isExpired(long eventTime) {
			long elapsed = eventTime - lastAccessedTime;
			return elapsed >= lifetime;

		}
	}
}
