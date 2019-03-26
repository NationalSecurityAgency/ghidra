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
package generic.stl;

import java.util.*;

@SuppressWarnings("all") // note: if we ever decide to support this API, then remove this
public class VectorSTL<T> implements Iterable<T> {

	// used by sort if T is comparable
//	static Comparator<? extends Comparable<?>> comparableComparator = createComparator();
	@SuppressWarnings("unchecked")
	static Comparator comparableComparator = createComparator();

	private static Comparator createComparator() {
		Comparator c = (o1, o2) -> {
			Comparable c1 = (Comparable) o1;
			Comparable c2 = (Comparable) o2;
			return c1.compareTo(c2);
		};
		return c;
	}

	private ArrayList<T> data;

	public VectorSTL() {
		data = new ArrayList<>();
	}

	public VectorSTL(int initialCapacity) {
		data = new ArrayList<>(initialCapacity);
	}

	public VectorSTL(int initialCapacity, T value) {
		data = new ArrayList<>(initialCapacity);
		for (int ii = 0; ii < initialCapacity; ++ii) {
			data.add(value);
		}
	}

	public VectorSTL(VectorSTL<T> other) {
		data = new ArrayList<>(other.data);
	}

	@Override
	public String toString() {
		return data.toString();
	}

	public void reserve(int capacity) {
		data.ensureCapacity(capacity);
	}

	public IteratorSTL<T> begin() {
		return new VectorIterator<>(data, 0);
	}

	public IteratorSTL<T> end() {
		return new VectorIterator<>(data, data.size());
	}

	public IteratorSTL<T> rBegin() {
		return new ReverseVectorIterator<>(data, data.size() - 1);
	}

	public IteratorSTL<T> rEnd() {
		return new ReverseVectorIterator<>(data, -1);
	}

	public void clear() {
		data.clear();
	}

	public int size() {
		return data.size();
	}

	public boolean empty() {
		return data.isEmpty();
	}

	public T get(int index) {
		return data.get(index);
	}

	public T front() {
		return data.get(0);
	}

	public T back() {
		return data.get(size() - 1);
	}

	public void setBack(T value) {
		data.set(size() - 1, value);
	}

	public void push_back(T value) {
		data.add(value);
	}

	public T pop_back() {
		return data.remove(size() - 1);
	}

	public void insert(int index, T value) {
		data.add(index, value);
	}

	public void appendAll(VectorSTL<T> vector) {
		data.addAll(vector.data);
	}

	public void insertAll(IteratorSTL<T> pos, VectorSTL<T> vector) {
		VectorIterator<T> iter = (VectorIterator<T>) pos;
		data.addAll(iter.getIndex(), vector.data);
	}

	public void insert(IteratorSTL<T> iterator, T value) {
		VectorIterator<T> vectorIterator = (VectorIterator<T>) iterator;
		vectorIterator.insert(value);
	}

	public void set(int index, T value) {
		data.set(index, value);
	}

	public void set(IteratorSTL<T> iter, T value) {
		VectorIterator<T> listIter = (VectorIterator<T>) iter;
		listIter.set(value);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (!(obj instanceof VectorSTL)) {
			return false;
		}
		VectorSTL<?> other = (VectorSTL<?>) obj;
		int size = data.size();
		if (size != other.data.size()) {
			return false;
		}
		for (int i = 0; i < size; i++) {
			if (!data.get(i).equals(other.data.get(i))) {
				return false;
			}
		}
		return true;
	}

	public T erase(int index) {
		return data.remove(index);
	}

	public IteratorSTL<T> erase(IteratorSTL<T> it) {
		VectorIterator<T> iter = (VectorIterator<T>) it;
		int index = iter.index;
		if (index < 0 || index >= data.size()) {
			throw new IndexOutOfBoundsException();
		}
		data.remove(index);
		return it;
	}

	public void erase(IteratorSTL<T> start, IteratorSTL<T> end) {
		VectorIterator<T> vstart = (VectorIterator<T>) start;
		VectorIterator<T> vend = (VectorIterator<T>) end;
		int count = vend.index - vstart.index;
		if (count < 0) {
			throw new IllegalArgumentException("end is befor start");
		}
		List<T> subList = data.subList(vstart.index, vend.index);
		subList.clear();
	}

	/**
	 * Sorts the vector. To use this method T must be comparable.
	 * @throws UnsupportedOperationException if T is not comparable;
	 */
	public void sort() {
		if (data.isEmpty()) {
			return;
		}
		T item = data.get(0);
		if (!(item instanceof Comparable)) {
			throw new UnsupportedOperationException("T must be comparable");
		}
		Collections.sort(data, comparableComparator);
	}

	public void sort(Comparator<T> comparator) {
		Collections.sort(data, comparator);
	}

	public VectorSTL<T> copy() {
		return new VectorSTL<>(this);
	}

	@Override
	public Iterator<T> iterator() {
		return data.iterator();
	}

	/**
	 * Returns an iterator postioned at the item in the vector that is the smallest key less or equal than
	 * the given key.  This method assumes the vector is sorted in ascending order.
	 * @param key the key for which to find the lower bound
	 * @return an iterator postioned at the item in the vector that is the smallest key less or equal than
	 * the given key. 
	 * @throws UnsupportedOperationException if T is not comparable
	 */
	public IteratorSTL<T> lower_bound(T key, Comparator<T> comparator) {
		int i = Collections.binarySearch(data, key, comparator);
		// binary search does not guarantee it will find the first of a sequence of equal keys,
		// so look for the first.  if i < 0 we don't have any exact matches so this loop won't execute
		for (; i > 0; i--) {
			if (!data.get(i - 1).equals(key)) {
				break;
			}
		}
		// at this point if i >= 0, i is pointing to the lower bound
		// if it is negative, the lower bound = -i-1;

		if (i < 0) {
			i = -i - 1;
		}
		return new VectorIterator<>(data, i);

	}

	/**
	 * Returns an iterator postioned at the item in the vector that is the smallest key less or equal than
	 * the given key.  This method assumes the vector is sorted in ascending order.
	 * @param key the key for which to find the lower bound
	 * @return an iterator postioned at the item in the vector that is the smallest key less or equal than
	 * the given key. 
	 */
	public IteratorSTL<T> lower_bound(T key) {
		if (!(key instanceof Comparable)) {
			throw new UnsupportedOperationException("T must be comparable");
		}
		return lower_bound(key, comparableComparator);
	}

	/**
	 * Returns an iterator postioned at the item in the vector that is the smallest key less than
	 * the given key.  This method assumes the vector is sorted in ascending order.
	 * @param key the key for which to find the upper bound
	 * @return an iterator postioned at the item in the vector that is the smallest key less than
	 * the given key. 
	 * @throws UnsupportedOperationException if T is not comparable
	 */
	public IteratorSTL<T> upper_bound(T key) {
		if (!(key instanceof Comparable)) {
			throw new UnsupportedOperationException("T must be comparable");
		}
		return upper_bound(key, comparableComparator);
	}

	/**
	 * Returns an iterator postioned at the item in the vector that is the smallest key less than
	 * the given key.  This method assumes the vector is sorted in ascending order.
	 * @param key the key for which to find the upper bound
	 * @return an iterator postioned at the item in the vector that is the smallest key less than
	 * the given key. 
	 * @throws UnsupportedOperationException if T is not comparable
	 */
	public IteratorSTL<T> upper_bound(T key, Comparator<T> comparator) {
		int i = Collections.binarySearch(data, key, comparator);

		// if it is negative, the upper bound index is -i-1;
		if (i < 0) {
			i = -i - 1;
		}

		// advance until the data is > key
		for (; i < data.size(); i++) {
			if (!data.get(i).equals(key)) {
				break;
			}
		}
		return new VectorIterator<>(data, i);
	}

	public static <K> void merge(VectorSTL<K> v1, VectorSTL<K> v2, VectorSTL<K> destination) {
		if (v1.empty() && v2.empty()) {
			destination.clear();
			return;
		}
		K value = v1.empty() ? v2.get(0) : v1.get(0);
		if (!(value instanceof Comparable)) {
			throw new UnsupportedOperationException("T must be comparable");
		}
		merge(v1, v2, destination, comparableComparator);

	}

	public static <K> void merge(VectorSTL<K> v1, VectorSTL<K> v2, VectorSTL<K> destination,
			Comparator<K> comparator) {
		destination.clear();
		destination.reserve(v1.size() + v2.size());
		IteratorSTL<K> it1 = v1.begin();
		IteratorSTL<K> it2 = v2.begin();
		while (!it1.isEnd() && !it2.isEnd()) {
			if (comparator.compare(it1.get(), it2.get()) <= 0) {
				destination.push_back(it1.get());
				it1.increment();
			}
			else {
				destination.push_back(it2.get());
				it2.increment();
			}
		}
		while (!it1.isEnd()) {
			destination.push_back(it1.get());
			it1.increment();
		}
		while (!it2.isEnd()) {
			destination.push_back(it2.get());
			it2.increment();
		}
	}

	public void resize(int size, T value) {
		while (size() > size) {
			pop_back();
		}
		while (size() < size) {
			push_back(value);
		}
	}

	public void insert(IteratorSTL<T> pos, T[] list) {
		VectorIterator<T> iter = (VectorIterator<T>) pos;
		data.addAll(iter.index, Arrays.asList(list));
	}

	// mock-up of the stl vector's assignment operator
	public void assign(VectorSTL<T> otherVector) {
		data.clear();
		data.addAll(otherVector.data);
	}
}
