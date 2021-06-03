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

/**
 * Class to provide a navigable, e.g., tree-, map with weak values
 * 
 * @param <K> the type of keys
 * @param <V> the type of values
 */
public abstract class AbstractWeakValueNavigableMap<K, V> extends AbstractWeakValueMap<K, V>
		implements NavigableMap<K, V> {

	/**
	 * A view of this same map that limits or changes the order of the keys
	 *
	 * <p>
	 * TODO: By virtue of extending (indirectly) {@link AbstractWeakValueMap}, this view inherits a
	 * unique, but totally unused, {@link AbstractWeakValueMap#refQueue}. This is a small and
	 * harmless, but unnecessary waste.
	 *
	 * @param <K> the type of keys
	 * @param <V> the type of values
	 */
	protected static class NavigableView<K, V> extends AbstractWeakValueNavigableMap<K, V> {
		protected final AbstractWeakValueNavigableMap<K, V> map;
		protected final NavigableMap<K, WeakValueRef<K, V>> mod;

		public NavigableView(AbstractWeakValueNavigableMap<K, V> map,
				NavigableMap<K, WeakValueRef<K, V>> sub) {
			this.map = map;
			this.mod = Collections.unmodifiableNavigableMap(sub);
		}

		@Override
		protected NavigableMap<K, WeakValueRef<K, V>> getRefMap() {
			map.processQueue();
			return mod;
		}
	}

	@Override
	protected abstract NavigableMap<K, WeakValueRef<K, V>> getRefMap();

	@Override
	public Comparator<? super K> comparator() {
		return getRefMap().comparator();
	}

	@Override
	public K firstKey() {
		processQueue();
		return getRefMap().firstKey();
	}

	@Override
	public K lastKey() {
		processQueue();
		return getRefMap().lastKey();
	}

	/**
	 * Construct a generated (wrapper) entry, for the entry-retrieval methods.
	 * 
	 * <p>
	 * This handles the null case in one place.
	 * 
	 * @param ent the entry to wrap, possibly null
	 * @return the generated entry, or null
	 */
	protected GeneratedEntry generateEntry(Entry<K, WeakValueRef<K, V>> ent) {
		if (ent == null) {
			return null;
		}
		return new GeneratedEntry(ent.getKey(), ent.getValue().get());
	}

	@Override
	public Entry<K, V> lowerEntry(K key) {
		processQueue();
		return generateEntry(getRefMap().lowerEntry(key));
	}

	@Override
	public K lowerKey(K key) {
		processQueue();
		return getRefMap().lowerKey(key);
	}

	@Override
	public Entry<K, V> floorEntry(K key) {
		processQueue();
		return generateEntry(getRefMap().floorEntry(key));
	}

	@Override
	public K floorKey(K key) {
		processQueue();
		return getRefMap().floorKey(key);
	}

	@Override
	public Entry<K, V> ceilingEntry(K key) {
		processQueue();
		return generateEntry(getRefMap().ceilingEntry(key));
	}

	@Override
	public K ceilingKey(K key) {
		processQueue();
		return getRefMap().ceilingKey(key);
	}

	@Override
	public Entry<K, V> higherEntry(K key) {
		processQueue();
		return generateEntry(getRefMap().higherEntry(key));
	}

	@Override
	public K higherKey(K key) {
		processQueue();
		return getRefMap().higherKey(key);
	}

	@Override
	public Entry<K, V> firstEntry() {
		processQueue();
		return generateEntry(getRefMap().firstEntry());
	}

	@Override
	public Entry<K, V> lastEntry() {
		processQueue();
		return generateEntry(getRefMap().lastEntry());
	}

	@Override
	public Entry<K, V> pollFirstEntry() {
		processQueue();
		return generateEntry(getRefMap().pollFirstEntry());
	}

	@Override
	public Entry<K, V> pollLastEntry() {
		processQueue();
		return generateEntry(getRefMap().pollLastEntry());
	}

	@Override
	public NavigableMap<K, V> descendingMap() {
		processQueue();
		return new NavigableView<>(this, getRefMap().descendingMap());
	}

	@Override
	public NavigableSet<K> navigableKeySet() {
		return getRefMap().navigableKeySet();
	}

	@Override
	public NavigableSet<K> descendingKeySet() {
		return getRefMap().descendingKeySet();
	}

	@Override
	public NavigableMap<K, V> subMap(K fromKey, boolean fromInclusive, K toKey,
			boolean toInclusive) {
		processQueue();
		return new NavigableView<>(this,
			getRefMap().subMap(fromKey, fromInclusive, toKey, toInclusive));
	}

	@Override
	public NavigableMap<K, V> headMap(K toKey, boolean inclusive) {
		processQueue();
		return new NavigableView<>(this, getRefMap().headMap(toKey, inclusive));
	}

	@Override
	public NavigableMap<K, V> tailMap(K fromKey, boolean inclusive) {
		processQueue();
		return new NavigableView<>(this, getRefMap().tailMap(fromKey, inclusive));
	}

	@Override
	public SortedMap<K, V> subMap(K fromKey, K toKey) {
		processQueue();
		return subMap(fromKey, true, toKey, false);
	}

	@Override
	public SortedMap<K, V> headMap(K toKey) {
		return headMap(toKey, false);
	}

	@Override
	public SortedMap<K, V> tailMap(K fromKey) {
		return tailMap(fromKey, true);
	}
}
