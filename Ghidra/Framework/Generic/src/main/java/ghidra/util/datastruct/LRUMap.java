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

import java.util.*;

import ghidra.util.SystemUtilities;

/**
 * A LRU (Least Recently Used) map that maintains <i>access-order</i> (newest to oldest)
 *  iteration over the elements.  
 * This map is limited to the given size.  
 * As new items are added, the older items will be removed from this map.
 * <p>
 * If you need to be notified of removals, then you can override 
 *  {@link #eldestEntryRemoved(java.util.Map.Entry)}.
 * <p>
 * If you don't want the eldest removed, override  
 *  {@link #removeEldestEntry(java.util.Map.Entry)} and return false;
 * <p>
 * If you would like to have the iteration order of your LRU structure be based upon access, 
 * but want it to iterate from least recently used to most recently used, then you should see
 * {@link FixedSizeHashMap}.
 *  
 * @param <K> the key type 
 * @param <V> the value type
 * 
 * @see LinkedHashMap
 * @see FixedSizeHashMap
 */

public class LRUMap<K, V> implements Map<K, V> {
	static final float DEFAULT_LOAD_FACTOR = 0.75f;

	protected HashMap<K, Entry<K, V>> map;
	private int cacheSize;
	private Entry<K, V> head;
	private volatile long modificationID = 0;

	public LRUMap(int cacheSize) {
		this.cacheSize = cacheSize;
		int initialCapacity = (int) (cacheSize / DEFAULT_LOAD_FACTOR) + 1;
		map = new HashMap<>(initialCapacity, DEFAULT_LOAD_FACTOR);

		head = new Entry<>(null, null);
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
	public boolean containsKey(Object key) {
		return map.containsKey(key);
	}

	@Override
	public boolean containsValue(Object value) {
		for (V mapValue : values()) {
			if (SystemUtilities.isEqual(value, mapValue)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public V get(Object key) {
		Entry<K, V> entry = map.get(key);
		if (entry == null) {
			return null;
		}

		removeEntry(entry);
		addToTop(entry);

		return entry.value;
	}

	@Override
	public V put(K key, V value) {
		V oldValue = null;
		Entry<K, V> entry = map.get(key);
		if (entry != null) {
			oldValue = entry.value;
			removeEntry(entry);
			entry.value = value;
		}
		else {
			entry = new Entry<>(key, value);
			map.put(key, entry);
		}

		addToTop(entry);

		removeOldEntries();

		modificationID++;

		return oldValue;
	}

	@Override
	public V remove(Object key) {
		Entry<K, V> entry = map.remove(key);
		modificationID++;
		if (entry != null) {
			removeEntry(entry);
			return entry.value;
		}
		return null;
	}

	@Override
	public void putAll(Map<? extends K, ? extends V> m) {
		for (Map.Entry<? extends K, ? extends V> mapEntry : m.entrySet()) {
			put(mapEntry.getKey(), mapEntry.getValue());
		}
	}

	@Override
	public void clear() {
		map.clear();
		head.next = head.previous = head;
		modificationID++;
	}

	@Override
	public Set<K> keySet() {
		return new AbstractSet<K>() {
			@Override
			public Iterator<K> iterator() {
				return new KeyIterator();
			}

			@Override
			public int size() {
				return map.size();
			}

			@Override
			public boolean contains(Object o) {
				return containsKey(o);
			}

			@Override
			public boolean remove(Object o) {
				return LRUMap.this.remove(o) != null;
			}

			@Override
			public void clear() {
				LRUMap.this.clear();
			}
		};
	}

	@Override
	public Collection<V> values() {
		return new AbstractCollection<V>() {
			@Override
			public Iterator<V> iterator() {
				return new ValueIterator();
			}

			@Override
			public int size() {
				return map.size();
			}

			@Override
			public void clear() {
				LRUMap.this.clear();
			}
		};
	}

	@Override
	public Set<Map.Entry<K, V>> entrySet() {
		return new AbstractSet<Map.Entry<K, V>>() {
			@Override
			public Iterator<Map.Entry<K, V>> iterator() {
				return new EntryIterator();
			}

			@Override
			public int size() {
				return map.size();
			}

			@Override
			public boolean contains(Object o) {
				if (!(o instanceof Map.Entry)) {
					return false;
				}
				@SuppressWarnings("unchecked")
				Map.Entry<K, V> e = (Map.Entry<K, V>) o;
				K key = e.getKey();
				V value = LRUMap.this.get(key);
				return SystemUtilities.isEqual(e.getValue(), value);
			}

			@Override
			public boolean remove(Object o) {
				if (!(o instanceof Map.Entry)) {
					return false;
				}
				@SuppressWarnings("unchecked")
				Map.Entry<K, V> e = (Map.Entry<K, V>) o;
				K key = e.getKey();
				return LRUMap.this.remove(key) != null;
			}

			@Override
			public void clear() {
				LRUMap.this.clear();
			}
		};
	}

	private void removeOldEntries() {
		// head.previous is the bottom of the list, or the oldest
		Entry<K, V> eldest = head.previous;
		if (removeEldestEntry(eldest)) {
			map.remove(eldest.key);
			removeEntry(eldest);
			eldestEntryRemoved(eldest);
		}
	}

	private void addToTop(Entry<K, V> entry) {
		entry.previous = head;
		entry.next = head.next;
		head.next.previous = entry;
		head.next = entry;
	}

	private void removeEntry(Entry<K, V> entry) {
		entry.previous.next = entry.next;
		entry.next.previous = entry.previous;
		entry.next = null;
		entry.previous = null;
	}

	protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
		return map.size() > cacheSize;
	}

	/**
	 * This is called after an item has been removed from the cache.
	 * @param eldest the item being removed
	 */
	protected void eldestEntryRemoved(Map.Entry<K, V> eldest) {
		// this is just a way for subclasses to know when items are removed from the cache
	}

	@Override
	public String toString() {
		return map.toString();
	}

//==============================================================================================
// Inner classes
//==============================================================================================

	private abstract class LinkedIterator<T> implements Iterator<T> {
		private Entry<K, V> next = head.next;
		protected Entry<K, V> current = null;
		private long startModificactionID = modificationID;

		@Override
		public boolean hasNext() {
			return next != head;
		}

		protected void advance() {
			if (!hasNext()) {
				throw new NoSuchElementException();
			}
			if (modificationID != startModificactionID) {
				throw new ConcurrentModificationException();
			}
			current = next;
			next = current.next;
		}

		@Override
		public void remove() {
			if (current == null) {
				throw new IllegalStateException();
			}
			if (modificationID != startModificactionID) {
				throw new ConcurrentModificationException();
			}
			LRUMap.this.remove(current.getKey());
			current = null;
			startModificactionID = modificationID;
		}
	}

	private class KeyIterator extends LinkedIterator<K> {
		@Override
		public K next() {
			advance();
			return current.getKey();
		}
	}

	private class ValueIterator extends LinkedIterator<V> {
		@Override
		public V next() {
			advance();
			return current.getValue();
		}
	}

	private class EntryIterator extends LinkedIterator<Map.Entry<K, V>> {
		@Override
		public Entry<K, V> next() {
			advance();
			return current;
		}
	}

	private static class Entry<K, V> implements Map.Entry<K, V> {
		Entry<K, V> next;
		Entry<K, V> previous;
		V value;
		K key;

		Entry(K key, V value) {
			this.key = key;
			this.value = value;
			this.next = this;
			this.previous = this;
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
			V old = this.value;
			this.value = value;
			return old;
		}

		@Override
		public String toString() {
			return key + ", " + value;
		}
	}

}
