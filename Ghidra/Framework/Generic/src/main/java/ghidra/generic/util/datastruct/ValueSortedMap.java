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
package ghidra.generic.util.datastruct;

import java.util.*;
import java.util.Map.Entry;

/**
 * A map that is sorted by value.
 * 
 * <p>
 * This is an extension of {@link Map} where entries are sorted by value, rather than by key. Such a
 * map may be useful as a priority queue where the cost of an entry may change over time. As such,
 * the collections returned by {@link #entrySet()}, {@link #keySet()}, and {@link #values()} all
 * extend {@link Deque}. The order of the entries will be updated on any call to
 * {@link Map#put(Object, Object)}, or a call to {@link Collection#add(Object)} on the entry set.
 * Additionally, if the values are mutable objects, whose order may change, there is an
 * {@link #update(Object)} method, which notifies the map that the given key may need to be
 * repositioned. The associated collections also extend the {@link List} interface, providing fairly
 * efficient implementations of {@link List#get(int)} and {@link List#indexOf(Object)}. Sequential
 * access is best performed via {@link Collection#iterator()}, since this will use a linked list.
 * 
 * @param <K> the type of the keys
 * @param <V> the type of the values
 */
public interface ValueSortedMap<K, V> {
	/**
	 * An interface with a subset of methods from {@link List}.
	 * 
	 * <p>
	 * We've opted to implement this instead of {@link List} so that newer JDKs do not impose new
	 * requirements on our implementations.
	 * 
	 * @param <E> the type of element
	 */
	public interface LesserList<E> extends Iterable<E> {
		boolean isEmpty();

		int size();

		/**
		 * Get the element at the given index
		 * 
		 * @param i the index
		 * @return the element
		 */
		E get(int i);

		/**
		 * Copy this to a new list
		 * 
		 * @return the list
		 */
		List<E> toList();

		ListIterator<E> listIterator(int index);

		/**
		 * Get the index of a given element
		 * 
		 * <p>
		 * Returns the index of the element, or -1 if not found
		 * 
		 * @param o the object
		 * @return the index or -1
		 */
		int indexOf(Object o);

		boolean contains(Object o);

		/**
		 * Get and remove the first element
		 * 
		 * @return the first element, or null if empty
		 */
		E poll();

		boolean remove(Object o);

		default boolean removeAll(Collection<?> col) {
			boolean result = false;
			for (Object e : col) {
				result |= remove(e);
			}
			return result;
		}
	}

	public interface ValueSortedMapEntryList<K, V> extends LesserList<Entry<K, V>> {
	}

	public interface ValueSortedMapKeyList<K> extends LesserList<K> {
	}

	V put(K key, V value);

	V get(Object key);

	V remove(K key);

	ValueSortedMapEntryList<K, V> entrySet();

	/**
	 * Returns a key-value mapping associated with the greatest value strictly less than the given
	 * value, or {@code null} if there is no such value.
	 * 
	 * @param value the value
	 * @return the found entry, or {@code null}
	 */
	Entry<K, V> lowerEntryByValue(V value);

	/**
	 * Returns a key-value mapping associated with the greatest value less than or equal to the
	 * given value, or {@code null} if there is no such value.
	 * 
	 * @param value the value
	 * @return the found entry, or {@code null}
	 */
	Entry<K, V> floorEntryByValue(V value);

	/**
	 * Returns a key-value mapping associated with the least value greater than or equal to the
	 * given value, or {@code null} if there is no such value.
	 * 
	 * @param value the value
	 * @return the found entry, or {@code null}
	 */
	Entry<K, V> ceilingEntryByValue(V value);

	/**
	 * Returns a key-value mapping associated with the least value strictly greater than the given
	 * value, or {@code null} if there is no such value.
	 * 
	 * @param value the value
	 * @return the found entry, or {@code null}
	 */
	Entry<K, V> higherEntryByValue(V value);

	/**
	 * Returns a view of the portion of this map whose values range from {@code fromValue} to
	 * {@code toValue}. The returned map is an unmodifiable view.
	 * 
	 * @param fromValue low endpoint of the values in the returned map
	 * @param fromInclusive {@code true} if the low endpoint is to be included in the returned view
	 * @param toValue high endpoint of the values in the returned map
	 * @param toInclusive {@code true} if the high endpoint is to be included in the returned view
	 * @return the view
	 */
	ValueSortedMap<K, V> subMapByValue(V fromValue, boolean fromInclusive, V toValue,
			boolean toInclusive);

	/**
	 * Returns a view of the portion of this map whose values are less than (or equal to, if
	 * {@code inclusive} is true) {@code toValue}. The returned map is an unmodifiable view.
	 * 
	 * @param toValue high endpoint of the values in the returned map
	 * @param inclusive {@code true} if the high endpoint is to be included in the returned view
	 * @return the view
	 */
	ValueSortedMap<K, V> headMapByValue(V toValue, boolean inclusive);

	/**
	 * Returns a view of the portion of this map whose values are greater than (or equal to, if
	 * {@code inclusive} is true) {@code toValue}. The returned map is an unmodifiable view.
	 * 
	 * @param fromValue low endpoint of the values in the returned map
	 * @param inclusive {@code true} if the low endpoint is to be included in the returned view
	 * @return the view
	 */
	ValueSortedMap<K, V> tailMapByValue(V fromValue, boolean inclusive);

	ValueSortedMapKeyList<K> keySet();

	/**
	 * Notify the map of an external change to the cost of a key's associated value
	 * 
	 * <p>
	 * This is meant to update the entry's position after a change in cost. The position may not
	 * necessarily change, however, if the cost did not change significantly.
	 * 
	 * @param key the key whose associated value has changed in cost
	 * @return true if the entry's position changed
	 */
	boolean update(K key);

	SortedList<V> values();

	boolean isEmpty();

	boolean containsKey(Object key);

	boolean containsValue(Object value);

	int size();

	void clear();
}
