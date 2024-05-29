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

/**
 * A set where the ordering of elements may change over time, based on an alternative comparator
 * 
 * <p>
 * This is an implementation of {@link Set} where elements may be sorted by an alternative
 * comparator (usually by "cost"), rather than by the natural ordering. It may seem odd, but the
 * natural ordering is still used to determine the uniqueness of keys. That is, two elements that
 * are unequal -- but are considered equal by the alternative comparator -- may co-exist in the set.
 * (Note: in such cases, the two elements are ordered first-in first-out). Additionally, if the
 * elements are mutable, then their ordering may change over time. This mode of operation is enabled
 * by the {@link #update(Object)} method, which must be called to notify the set of any change to an
 * element that may affect its order. This set also implements the {@link List} and {@link Deque}
 * interfaces. Since the set is ordered, it makes sense to treat it as a list. It provides fairly
 * efficient implementations of {@link #get(int)} and {@link #indexOf(Object)}. Sequential access is
 * best performed via {@link #iterator()}, since this will use a linked list.
 * 
 * <p>
 * The underlying implementation is backed by {@link TreeValueSortedMap}. Currently, it is not
 * thread safe.
 * 
 * @param <E> the type of the elements
 */
public class DynamicSortedTreeSet<E> extends AbstractSet<E> {
	private final transient TreeValueSortedMap<E, E>.ValueSortedTreeMapKeySet keys;
	private final transient TreeValueSortedMap<E, E> map;

	/**
	 * Construct a dynamic sorted tree set using the elements' natural ordering
	 * 
	 * <p>
	 * Other than, perhaps, a more convenient interface, this offers few if any benefits over the
	 * stock {@link Set}.
	 */
	public DynamicSortedTreeSet() {
		map = new TreeValueSortedMap<>();
		keys = map.keySet();
	}

	/**
	 * Construct a dynamic sorted tree set using a custom comparator to order the elements
	 * 
	 * @param comparator the comparator, providing a total ordering of the values
	 */
	public DynamicSortedTreeSet(Comparator<E> comparator) {
		map = new TreeValueSortedMap<>(comparator);
		keys = map.keySet();
	}

	@Override
	public boolean add(E e) {
		return map.put(e, e) == null;
	}

	@Override
	public void clear() {
		map.clear();
	}

	@Override
	public boolean contains(Object o) {
		return map.containsKey(o);
	}

	public E get(int index) {
		return keys.get(index);
	}

	public int indexOf(Object o) {
		return keys.indexOf(o);
	}

	@Override
	public boolean isEmpty() {
		return map.isEmpty();
	}

	@Override
	public Iterator<E> iterator() {
		return keys.iterator();
	}

	@Override
	public boolean remove(Object o) {
		return keys.remove(o);
	}

	@Override
	public boolean removeAll(Collection<?> c) {
		return keys.removeAll(c);
	}

	@Override
	public boolean retainAll(Collection<?> c) {
		return keys.retainAll(c);
	}

	@Override
	public int size() {
		return map.size();
	}

	@Override
	public Spliterator<E> spliterator() {
		return Spliterators.spliterator(this, Spliterator.ORDERED | Spliterator.DISTINCT);
	}

	/**
	 * Notify the queue of a change to an element's cost.
	 * 
	 * <p>
	 * This may cause the element's index to change.
	 * 
	 * @param e the element whose cost may have changed
	 * @return true if the index changed
	 */
	public boolean update(E e) {
		return map.update(e);
	}
}
