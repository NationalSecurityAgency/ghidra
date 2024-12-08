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
 * A view of the value-sorted map for implementing
 * {@link #subMapByValue(Object, boolean, Object, boolean)}, etc.
 * 
 * @param <K> the type of keys
 * @param <V> the type of values
 */
public class RestrictedValueSortedMap<K, V> implements ValueSortedMap<K, V> {

	/**
	 * A list iterator suitable for {@link List#listIterator()}, etc., on the entries of a
	 * {@link RestrictedValueSortedMap}
	 */
	public class RestrictedEntryListIterator implements ListIterator<Entry<K, V>> {
		protected final ListIterator<Entry<K, V>> wit;

		/**
		 * Construct an iterator
		 */
		public RestrictedEntryListIterator() {
			this(0);
		}

		/**
		 * Construct an iterator starting at a given index of the <em>sub</em> list.
		 * 
		 * @param start initial iterator position
		 */
		public RestrictedEntryListIterator(int start) {
			this.wit = wrapped.entrySet().listIterator(getLowestIndex() + start);
		}

		@Override
		public boolean hasNext() {
			if (!wit.hasNext()) {
				return false;
			}
			Entry<K, V> next = wit.next();
			wit.previous();
			return inBounds(next.getValue());
		}

		@Override
		public Entry<K, V> next() {
			return wit.next();
		}

		@Override
		public boolean hasPrevious() {
			if (!wit.hasPrevious()) {
				return false;
			}
			Entry<K, V> prev = wit.previous();
			wit.next();
			return inBounds(prev.getValue());
		}

		@Override
		public Entry<K, V> previous() {
			return wit.previous();
		}

		@Override
		public int nextIndex() {
			return wit.nextIndex() - getLowestIndex();
		}

		@Override
		public int previousIndex() {
			return wit.previousIndex() - getLowestIndex();
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public void set(Entry<K, V> e) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void add(Entry<K, V> e) {
			throw new UnsupportedOperationException();
		}
	}

	/**
	 * A list iterator suitable for {@link List#listIterator()}, etc., on the keys of a
	 * {@link RestrictedValueSortedMap}
	 */
	public class RestrictedKeyListIterator implements ListIterator<K> {
		protected final RestrictedEntryListIterator wit;

		/**
		 * Construct an iterator
		 */
		public RestrictedKeyListIterator() {
			this(0);
		}

		/**
		 * Construct an iterator starting at a given index of the <em>sub</em> list.
		 * 
		 * @param start initial iterator position
		 */
		public RestrictedKeyListIterator(int start) {
			this.wit = new RestrictedEntryListIterator(start);
		}

		@Override
		public boolean hasNext() {
			return wit.hasNext();
		}

		@Override
		public K next() {
			return wit.next().getKey();
		}

		@Override
		public boolean hasPrevious() {
			return wit.hasPrevious();
		}

		@Override
		public K previous() {
			return wit.previous().getKey();
		}

		@Override
		public int nextIndex() {
			return wit.nextIndex();
		}

		@Override
		public int previousIndex() {
			return wit.previousIndex();
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public void set(K e) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void add(K e) {
			throw new UnsupportedOperationException();
		}
	}

	/**
	 * A list iterator suitable for {@link List#listIterator()}, etc., on the values of a
	 * {@link RestrictedValueSortedMap}
	 */
	public class RestrictedValueListIterator implements ListIterator<V> {
		protected final RestrictedEntryListIterator wit;

		/**
		 * Construct an iterator
		 */
		public RestrictedValueListIterator() {
			this(0);
		}

		/**
		 * Construct an iterator starting at a given index of the <em>sub</em> list.
		 * 
		 * @param start initial iterator position
		 */
		public RestrictedValueListIterator(int start) {
			this.wit = new RestrictedEntryListIterator(start);
		}

		@Override
		public boolean hasNext() {
			return wit.hasNext();
		}

		@Override
		public V next() {
			return wit.next().getValue();
		}

		@Override
		public boolean hasPrevious() {
			return wit.hasPrevious();
		}

		@Override
		public V previous() {
			return wit.previous().getValue();
		}

		@Override
		public int nextIndex() {
			return wit.nextIndex();
		}

		@Override
		public int previousIndex() {
			return wit.previousIndex();
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public void set(V e) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void add(V e) {
			throw new UnsupportedOperationException();
		}
	}

	/**
	 * A list view suitable for {@link ValueSortedMap#entrySet()} of
	 * {@link RestrictedValueSortedMap}
	 */
	public class RestrictedValueSortedMapEntryList implements ValueSortedMapEntryList<K, V> {
		@Override
		public List<Entry<K, V>> toList() {
			List<Entry<K, V>> copy = new ArrayList<>(size());
			for (Entry<K, V> ent : this) {
				copy.add(ent);
			}
			return copy;
		}

		@Override
		public int size() {
			return restrictedSize();
		}

		@Override
		public boolean isEmpty() {
			return restrictedIsEmpty();
		}

		@SuppressWarnings("unchecked")
		@Override
		public boolean contains(Object o) {
			if (!wrapped.entrySet().contains(o)) {
				return false;
			}
			Entry<K, V> ent = (Entry<K, V>) o;
			V val = ent.getValue();
			if (!inBounds(val)) {
				return false;
			}
			return true;
		}

		@Override
		public Iterator<Entry<K, V>> iterator() {
			return new RestrictedEntryListIterator();
		}

		@Override
		public Entry<K, V> get(int index) {
			if (index < 0) {
				throw new IndexOutOfBoundsException("" + index);
			}
			Entry<K, V> ent = inBoundsOrNull(wrapped.entrySet().get(getLowestIndex() + index));
			if (ent == null) {
				throw new IndexOutOfBoundsException("" + index);
			}
			return ent;
		}

		@Override
		public int indexOf(Object o) {
			return inBoundsOrNeg1(wrapped.entrySet().indexOf(o));
		}

		@Override
		public ListIterator<Entry<K, V>> listIterator(int index) {
			return new RestrictedEntryListIterator(index);
		}

		@Override
		public Entry<K, V> poll() {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean remove(Object o) {
			throw new UnsupportedOperationException();
		}
	}

	/**
	 * A list view suitable for {@link ValueSortedMap#keySet()} of {@link RestrictedValueSortedMap}
	 */
	public class RestrictedValueSortedMapKeyList implements ValueSortedMapKeyList<K> {
		@Override
		public List<K> toList() {
			List<K> copy = new ArrayList<>(size());
			for (K k : this) {
				copy.add(k);
			}
			return copy;
		}

		@Override
		public int size() {
			return restrictedSize();
		}

		@Override
		public boolean isEmpty() {
			return restrictedIsEmpty();
		}

		@Override
		public boolean contains(Object o) {
			return containsKey(o);
		}

		@Override
		public Iterator<K> iterator() {
			return new RestrictedKeyListIterator();
		}

		@Override
		public K get(int index) {
			if (index < 0) {
				throw new IndexOutOfBoundsException("" + index);
			}
			Entry<K, V> ent = inBoundsOrNull(wrapped.entrySet().get(getLowestIndex() + index));
			if (ent == null) {
				throw new IndexOutOfBoundsException("" + index);
			}
			return ent.getKey();
		}

		@Override
		public int indexOf(Object o) {
			return inBoundsOrNeg1(wrapped.keySet().indexOf(o));
		}

		@Override
		public ListIterator<K> listIterator(int index) {
			return new RestrictedKeyListIterator(index);
		}

		@Override
		public K poll() {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean remove(Object o) {
			throw new UnsupportedOperationException();
		}
	}

	/**
	 * A list view suitable for {@link ValueSortedMap#values()} of {@link RestrictedValueSortedMap}
	 */
	public class RestrictedSortedList implements SortedList<V> {
		@Override
		public List<V> toList() {
			List<V> copy = new ArrayList<>(size());
			for (V v : this) {
				copy.add(v);
			}
			return copy;
		}

		@Override
		public int size() {
			return restrictedSize();
		}

		@Override
		public boolean isEmpty() {
			return restrictedIsEmpty();
		}

		@Override
		public boolean contains(Object o) {
			return containsValue(o);
		}

		@Override
		public Iterator<V> iterator() {
			return new RestrictedValueListIterator();
		}

		@Override
		public V get(int index) {
			if (index < 0) {
				throw new IndexOutOfBoundsException("" + index);
			}
			Entry<K, V> ent = inBoundsOrNull(wrapped.entrySet().get(getLowestIndex() + index));
			if (ent == null) {
				throw new IndexOutOfBoundsException("" + index);
			}
			return ent.getValue();
		}

		@Override
		public int indexOf(Object o) {
			return inBoundsOrNeg1(wrapped.values().indexOf(o));
		}

		@Override
		public ListIterator<V> listIterator(int index) {
			return new RestrictedValueListIterator(index);
		}

		@Override
		public V poll() {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean remove(Object o) {
			throw new UnsupportedOperationException();
		}

		@Override
		public int lowerIndex(V element) {
			return inBoundsOrNeg1(wrapped.values().lowerIndex(element));
		}

		@Override
		public int floorIndex(V element) {
			return inBoundsOrNeg1(wrapped.values().floorIndex(element));
		}

		@Override
		public int ceilingIndex(V element) {
			return inBoundsOrNeg1(wrapped.values().ceilingIndex(element));
		}

		@Override
		public int higherIndex(V element) {
			return inBoundsOrNeg1(wrapped.values().higherIndex(element));
		}
	}

	private final ValueSortedMap<K, V> wrapped;
	private final Comparator<V> comparator;
	private final boolean hasFrom;
	private final V fromValue;
	private final boolean fromInclusive;
	private final boolean hasTo;
	private final V toValue;
	private final boolean toInclusive;

	/**
	 * Construct a restricted view of a value-sorted map
	 * 
	 * @param wrapped the value-sorted map to restrict
	 * @param comparator the value comparator
	 * @param hasFrom true if there exists a lower bound
	 * @param fromValue the lower bound, if present
	 * @param fromInclusive true to include the lower bound
	 * @param hasTo true if there exists an upper bound
	 * @param toValue the upper bound, if present
	 * @param toInclusive true to include the upper bound
	 */
	protected RestrictedValueSortedMap(ValueSortedMap<K, V> wrapped, Comparator<V> comparator,
			boolean hasFrom, V fromValue, boolean fromInclusive, boolean hasTo, V toValue,
			boolean toInclusive) {
		if (hasFrom && hasTo) {
			int cmp = comparator.compare(fromValue, toValue);
			if (cmp > 0 || cmp == 0 && !fromInclusive && !toInclusive) {
				throw new IllegalArgumentException("from must be less than to");
			}
		}
		this.wrapped = wrapped;
		this.comparator = comparator;
		this.hasFrom = hasFrom;
		this.fromValue = fromValue;
		this.fromInclusive = fromInclusive;
		this.hasTo = hasTo;
		this.toValue = toValue;
		this.toInclusive = toInclusive;
	}

	protected int getLowestIndex() {
		if (!hasFrom) {
			return 0;
		}
		final int i;
		if (fromInclusive) {
			i = wrapped.values().ceilingIndex(fromValue);
		}
		else {
			i = wrapped.values().higherIndex(fromValue);
		}
		if (i == -1) {
			return wrapped.size();
		}
		return i;
	}

	protected int getHighestIndexPlusOne() {
		if (!hasTo) {
			return wrapped.size();
		}
		final int i;
		if (toInclusive) {
			i = wrapped.values().floorIndex(toValue);
		}
		else {
			i = wrapped.values().lowerIndex(toValue);
		}
		if (i == -1) {
			return 0;
		}
		return i;
	}

	@Override
	public int size() {
		return restrictedSize();
	}

	protected int inBoundsOrNeg1(int index) {
		if (index == -1) {
			return -1;
		}
		int lowest = getLowestIndex();
		if (index < lowest) {
			return -1;
		}
		if (index >= getHighestIndexPlusOne()) {
			return -1;
		}
		return index - lowest;
	}

	protected int restrictedSize() {
		final int fromIndex = getLowestIndex();
		final int toIndex = getHighestIndexPlusOne();
		return toIndex - fromIndex;
	}

	@Override
	public boolean isEmpty() {
		return restrictedIsEmpty();
	}

	protected boolean restrictedIsEmpty() {
		return restrictedSize() != 0;
	}

	protected boolean inBounds(V val) {
		if (hasFrom) {
			int fromCmp = comparator.compare(val, fromValue);
			if (fromCmp < 0 || fromCmp == 0 && !fromInclusive) {
				return false;
			}
		}
		if (hasTo) {
			int toCmp = comparator.compare(val, toValue);
			if (toCmp > 0 || toCmp == 0 && !toInclusive) {
				return false;
			}
		}
		return true;
	}

	protected V inBoundsOrNull(V val) {
		if (!inBounds(val)) {
			return null;
		}
		return val;
	}

	protected Entry<K, V> inBoundsOrNull(Entry<K, V> ent) {
		if (!inBounds(ent.getValue())) {
			return null;
		}
		return ent;
	}

	@Override
	public boolean containsKey(Object key) {
		if (!wrapped.containsKey(key)) {
			return false;
		}
		V val = wrapped.get(key);
		return inBounds(val);
	}

	@SuppressWarnings("unchecked")
	@Override
	public boolean containsValue(Object value) {
		if (!inBounds((V) value)) {
			return false;
		}
		return wrapped.containsValue(value);
	}

	@Override
	public V get(Object key) {
		return inBoundsOrNull(wrapped.get(key));
	}

	@Override
	public V put(K key, V value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public V remove(Object key) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void clear() {
		throw new UnsupportedOperationException();
	}

	@Override
	public ValueSortedMapEntryList<K, V> entrySet() {
		return new RestrictedValueSortedMapEntryList();
	}

	@Override
	public Entry<K, V> lowerEntryByValue(V value) {
		return inBoundsOrNull(wrapped.lowerEntryByValue(value));
	}

	@Override
	public Entry<K, V> floorEntryByValue(V value) {
		return inBoundsOrNull(wrapped.floorEntryByValue(value));
	}

	@Override
	public Entry<K, V> ceilingEntryByValue(V value) {
		return inBoundsOrNull(wrapped.ceilingEntryByValue(value));
	}

	@Override
	public Entry<K, V> higherEntryByValue(V value) {
		return inBoundsOrNull(wrapped.higherEntryByValue(value));
	}

	@SuppressWarnings("hiding")
	@Override
	public ValueSortedMap<K, V> subMapByValue(V fromValue, boolean fromInclusive, V toValue,
			boolean toInclusive) {
		if (!inBounds(fromValue) || !inBounds(toValue)) {
			throw new IllegalArgumentException("Bounds must be within existing bounds");
		}
		return new RestrictedValueSortedMap<>(wrapped, comparator, true, fromValue, fromInclusive,
			true, toValue, toInclusive);
	}

	@SuppressWarnings("hiding")
	@Override
	// TODO: Test this implementation and related others
	public ValueSortedMap<K, V> headMapByValue(V toValue, boolean inclusive) {
		if (!inBounds(toValue)) {
			throw new IllegalArgumentException("Bounds must be within existing bounds");
		}
		return new RestrictedValueSortedMap<>(wrapped, comparator, hasFrom, fromValue,
			fromInclusive, true, toValue, inclusive);
	}

	@SuppressWarnings("hiding")
	@Override
	public ValueSortedMap<K, V> tailMapByValue(V fromValue, boolean inclusive) {
		if (!inBounds(fromValue)) {
			throw new IllegalArgumentException("Bounds must be within existing bounds");
		}
		return new RestrictedValueSortedMap<>(wrapped, comparator, true, fromValue, inclusive,
			hasTo, toValue, toInclusive);
	}

	@Override
	public ValueSortedMapKeyList<K> keySet() {
		return new RestrictedValueSortedMapKeyList();
	}

	@Override
	public boolean update(K key) {
		throw new UnsupportedOperationException();
	}

	@Override
	public SortedList<V> values() {
		return new RestrictedSortedList();
	}
}
