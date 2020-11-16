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

import org.apache.commons.collections4.comparators.ComparableComparator;

import ghidra.util.ReversedListIterator;

/**
 * A tree-based implementation of a value-sorted map
 *
 * The underlying implementation is currently an unbalanced binary tree whose nodes also comprise a
 * doubly-linked list. Currently, it is not thread safe.
 *
 * Note this implementation isn't terribly smart, as it makes no efforts to balance the tree. It is
 * also not thread safe.
 * 
 * @param <K> the type of the keys
 * @param <V> the type of the values
 */
public class TreeValueSortedMap<K, V> extends AbstractMap<K, V> implements ValueSortedMap<K, V> {

	/**
	 * Create a tree using the values' natural ordering
	 */
	public static <K, V extends Comparable<V>> TreeValueSortedMap<K, V> createWithNaturalOrder() {
		Comparator<V> natural = Comparator.naturalOrder();
		return new TreeValueSortedMap<>(natural);
	}

	/**
	 * Create a tree using a custom comparator to order the values
	 * 
	 * @param comparator the comparator, providing a total ordering of the values
	 */
	public static <K, V> TreeValueSortedMap<K, V> createWithComparator(Comparator<V> comparator) {
		return new TreeValueSortedMap<>(comparator);
	}

	/**
	 * An iterator of the entries
	 */
	protected class EntryListIterator implements ListIterator<Entry<K, V>> {
		private boolean atEnd = false;
		private Node next;
		private Node cur;

		/**
		 * Construct a list iterator over the entries
		 * 
		 * A start of null implies one past the end of the list, i.e., {@code tail.next}
		 * 
		 * @param start the starting node
		 */
		private EntryListIterator(Node start) {
			next = start;
			atEnd = start == null;
		}

		@Override
		public void add(Entry<K, V> e) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean hasNext() {
			return !atEnd;
		}

		@Override
		public boolean hasPrevious() {
			if (atEnd) {
				return true;
			}
			return next.prev != null;
		}

		@Override
		public Node next() {
			if (!hasNext()) {
				throw new NoSuchElementException();
			}
			cur = next;
			next = next.next;
			atEnd = next == null;
			return cur;
		}

		@Override
		public int nextIndex() {
			return next.computeIndex();
		}

		@Override
		public Node previous() {
			if (!hasPrevious()) {
				throw new NoSuchElementException();
			}
			if (atEnd) {
				next = tail;
				atEnd = tail == null;
			}
			else {
				cur = next = next.prev;
			}
			return cur;
		}

		@Override
		public int previousIndex() {
			if (atEnd) {
				return size() - 1;
			}
			return next.computeIndex() - 1;
		}

		@Override
		public void remove() {
			if (cur == null) {
				throw new IllegalStateException();
			}
			nodeMap.remove(cur.key);
			cur.remove();
			cur = null;
		}

		@Override
		public void set(Entry<K, V> e) {
			throw new UnsupportedOperationException();
		}
	}

	/**
	 * An iterator of the keys
	 */
	protected class KeyListIterator implements ListIterator<K> {
		private EntryListIterator it;

		/**
		 * Construct a list iterator over the keys
		 * 
		 * A start of null implies one past the end of the list, i.e., {@code tail.next}
		 * 
		 * @param start the starting node
		 */
		private KeyListIterator(Node start) {
			it = new EntryListIterator(start);
		}

		@Override
		public void add(K e) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean hasNext() {
			return it.hasNext();
		}

		@Override
		public boolean hasPrevious() {
			return it.hasPrevious();
		}

		@Override
		public K next() {
			return it.next().key;
		}

		@Override
		public int nextIndex() {
			return it.nextIndex();
		}

		@Override
		public K previous() {
			return it.previous().key;
		}

		@Override
		public int previousIndex() {
			return it.previousIndex();
		}

		@Override
		public void remove() {
			it.remove();
		}

		@Override
		public void set(K e) {
			throw new UnsupportedOperationException();
		}
	}

	/**
	 * An entry in the map.
	 * 
	 * Nodes are elements of a binary tree and a doubly-linked list.
	 */
	protected class Node implements Entry<K, V> {
		// Node key and data 
		protected final K key;
		protected V val;

		// Tree-related fields
		protected Node parent;
		protected Node lChild;
		protected Node rChild;
		protected int sizeLeft;

		// Linked list-related fields
		protected Node next;
		protected Node prev;

		@Override
		public String toString() {
			return key + "=" + val;
		}

		/**
		 * Construct a new node
		 * 
		 * @param key the key
		 * @param val the data
		 */
		protected Node(K key, V val) {
			this.key = key;
			this.val = val;
		}

		@Override
		public boolean equals(Object obj) {
			try {
				@SuppressWarnings("unchecked")
				Entry<K, V> that = (Entry<K, V>) obj;
				return Objects.equals(this.key, that.getKey()) &&
					Objects.equals(this.val, that.getValue());
			}
			catch (ClassCastException e) {
				return false;
			}
		}

		@Override
		public int hashCode() {
			return Objects.hash(this.key, this.val);
		}

		/**
		 * Compute this node's index.
		 * 
		 * This uses the {@link #sizeLeft} field to compute the index in O(log n) on average.
		 * 
		 * @return the index
		 */
		public int computeIndex() {
			Node cur = this;
			int index = sizeLeft;
			while (cur.parent != null) {
				if (cur.parent.rChild == cur) {
					index++;
					index += cur.parent.sizeLeft;
				}
				cur = cur.parent;
			}
			return index;
		}

		/**
		 * Retrieve the node at a given index in this subtree
		 * 
		 * This really only makes sense at the root
		 * 
		 * @param index the index
		 * @return the node at the given index
		 */
		private Node getByIndex(int index) {
			if (index < 0) {
				throw new IndexOutOfBoundsException(Integer.toString(index));
			}
			Node cur = this;
			int i = index;
			while (true) {
				if (i < 0) {
					throw new AssertionError("INTERNAL: sizeLeft values inconsistent");
				}
				else if (cur == null) {
					throw new IndexOutOfBoundsException(Integer.toString(index));
				}
				else if (i == cur.sizeLeft) {
					return cur;
				}
				else if (i > cur.sizeLeft) {
					i -= cur.sizeLeft;
					i--;
					cur = cur.rChild;
				}
				else {
					cur = cur.lChild;
				}
			}
		}

		@Override
		public K getKey() {
			return key;
		}

		@Override
		public V getValue() {
			return val;
		}

		/**
		 * Insert a node into this subtree and the linked list
		 * 
		 * @param item the node to insert
		 */
		void insert(Node item) {
			Node cur = this;
			while (true) {
				int c = comparator.compare(item.val, cur.val);
				if (c < 0) {
					cur.sizeLeft++;
					if (cur.lChild == null) {
						cur.lChild = item;
						item.parent = cur;
						cur.insertBefore(item);
						break;
					}
					cur = cur.lChild;
				}
				else { // Includes the == case. Ties are first-in first-out. 
					if (cur.rChild == null) {
						cur.rChild = item;
						item.parent = cur;
						cur.insertAfter(item);
						break;
					}
					cur = cur.rChild;
				}
			}
		}

		/**
		 * Insert a node as a successor to this node in the linked list
		 * 
		 * NOTE: Called only after the node is inserted into the tree
		 */
		private void insertAfter(Node item) {
			item.prev = this;
			item.next = next;

			if (this.next == null) {
				tail = item;
			}
			else {
				this.next.prev = item;
			}
			this.next = item;
		}

		/**
		 * Insert a node as a predecessor to this node in the linked list
		 * 
		 * NOTE: Called only after the node is inserted into the tree
		 */
		private void insertBefore(Node item) {
			item.prev = prev;
			item.next = this;

			if (this.prev == null) {
				head = item;
			}
			else {
				this.prev.next = item;
			}
			this.prev = item;
		}

		/**
		 * Remove this node from the tree and linked list
		 */
		private void remove() {
			// Correct the sizeLeft counts
			Node cur = this;
			while (cur.parent != null) {
				if (cur.parent.lChild == cur) {
					cur.parent.sizeLeft--;
				}
				cur = cur.parent;
			}

			// Remove from the tree
			// promote one of my children into my position
			if (parent == null) {
				// prefer the left
				if (lChild != null) {
					root = lChild;
					lChild.parent = null;
				}
				else if (rChild != null) {
					root = rChild;
					rChild.parent = null;
				}
				else {
					root = null;
				}
			}
			else if (parent.lChild == this) {
				if (lChild != null) {
					parent.lChild = lChild;
					lChild.parent = parent;
				}
				else if (rChild != null) {
					parent.lChild = rChild;
					rChild.parent = parent;
				}
				else {
					parent.lChild = null;
				}
			}
			else {
				if (lChild != null) {
					parent.rChild = lChild;
					lChild.parent = parent;
				}
				else if (rChild != null) {
					parent.rChild = rChild;
					rChild.parent = parent;
				}
				else {
					parent.rChild = null;
				}
			}
			if (lChild != null && rChild != null) {
				prev.rChild = rChild;
				rChild.parent = prev;
			}

			// In case the node is re-used, as in update()
			lChild = null;
			rChild = null;
			sizeLeft = 0;
			// The other links are all overwritten by insert

			// Remove from the list
			if (prev == null) {
				head = next;
			}
			else {
				prev.next = next;
			}
			if (next == null) {
				tail = prev;
			}
			else {
				next.prev = prev;
			}
		}

		/**
		 * Find the given value in this subtree
		 * 
		 * @param value the value to find
		 * @param mode when the value occurs multiple times, identifies which instance to find
		 * @return the node containing the given value, or null if not found
		 */
		private Node searchValue(V value, SearchMode mode) {
			Node cur = this;
			Node eq = null;
			int c;
			while (true) {
				c = comparator.compare(value, cur.val);
				if (c == 0) {
					eq = cur;
				}
				if (c < 0 || (c == 0 && mode.inEq == Comp.LT)) {
					if (cur.lChild == null) {
						break;
					}
					cur = cur.lChild;
				}
				else if (c > 0 || (c == 0 && mode.inEq == Comp.GT)) {
					if (cur.rChild == null) {
						break;
					}
					cur = cur.rChild;
				}
				else {
					break;
				}
			}
			if (eq != null) {
				if (mode.allowEq == BoundType.CLOSED) {
					return eq;
				}
				if (mode.comp == Comp.LT) {
					return eq.prev;
				}
				return eq.next;
			}
			if (mode.comp == Comp.LT) {
				if (c < 0) {
					return cur.prev; // May be null;
				}
				return cur; // c != 0 here, so c > 0
			}
			if (mode.comp == Comp.GT) {
				if (c < 0) {
					return cur;
				}
				return cur.next;
			}
			return null; // Other search modes require exact match
		}

		@Override
		public V setValue(V value) {
			V oldVal = this.val;
			this.val = value;
			updateNode(this);
			return oldVal;
		}
	}

	private enum BoundType {
		CLOSED, OPEN
	}

	private enum Comp {
		NONE, LT, GT
	}

	/**
	 * When searching for values, identifies which instance to find
	 */
	private enum SearchMode {
		/** Find any occurrence */
		ANY(BoundType.CLOSED, Comp.NONE, Comp.NONE),
		/** Find the first occurrence */
		FIRST(BoundType.CLOSED, Comp.LT, Comp.NONE),
		/** Find the last occurrence */
		LAST(BoundType.CLOSED, Comp.GT, Comp.NONE),
		/** Find the nearest match less than */
		LOWER(BoundType.OPEN, Comp.NONE, Comp.LT),
		/** Find the nearest match less than or equal */
		FLOOR(BoundType.CLOSED, Comp.LT, Comp.LT),
		/** Find the nearest match greater than or equal */
		CEILING(BoundType.CLOSED, Comp.GT, Comp.GT),
		/** Find the nearest match greater than */
		HIGHER(BoundType.OPEN, Comp.NONE, Comp.GT);

		final BoundType allowEq;
		final Comp inEq;
		final Comp comp;

		SearchMode(BoundType allowEq, Comp inEq, Comp comp) {
			this.allowEq = allowEq;
			this.inEq = inEq;
			this.comp = comp;
		}
	}

	/**
	 * An iterator of the values
	 */
	protected class ValueListIterator implements ListIterator<V> {
		private EntryListIterator it;

		/**
		 * Construct a list iterator over the values
		 * 
		 * A start of null implies one past the end of the list, i.e., {@code tail.next}
		 * 
		 * @param start the starting node
		 */
		private ValueListIterator(Node start) {
			it = new EntryListIterator(start);
		}

		@Override
		public void add(V e) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean hasNext() {
			return it.hasNext();
		}

		@Override
		public boolean hasPrevious() {
			return it.hasPrevious();
		}

		@Override
		public V next() {
			return it.next().val;
		}

		@Override
		public int nextIndex() {
			return it.nextIndex();
		}

		@Override
		public V previous() {
			return it.previous().val;
		}

		@Override
		public int previousIndex() {
			return it.previousIndex();
		}

		@Override
		public void remove() {
			it.remove();
		}

		@Override
		public void set(V e) {
			throw new UnsupportedOperationException();
		}
	}

	/**
	 * A public view of the map as a set of entries
	 * 
	 * In addition to {@link Set}, this view implements {@link List} and {@link Deque}, since an
	 * ordered set ought to behave like a list, and since this implementation is meant to be used as
	 * a dynamic-cost priority queue.
	 * 
	 * Generally, all of the mutation methods are supported.
	 */
	protected class ValueSortedTreeMapEntrySet extends AbstractSet<Entry<K, V>>
			implements ValueSortedMapEntryList<K, V> {
		private ValueSortedTreeMapEntrySet() {
		}

		/**
		 * Inserts (by copy) the entry into the owning map
		 */
		@Override
		public boolean add(Entry<K, V> e) {
			return put(e.getKey(), e.getValue()) == null;
		}

		/**
		 * Inserts (by copy) the entry into the owning map, ignoring index
		 * 
		 * @param index ignored since order is determined by the entry's value
		 */
		@Override
		public void add(int index, Entry<K, V> element) {
			add(element);
		}

		/**
		 * Inserts (by copy) all entries in the collection, ignoring index
		 * 
		 * @param index ignored since order is determined by the entries' values
		 */
		@Override
		public boolean addAll(int index, Collection<? extends Entry<K, V>> c) {
			return addAll(c);
		}

		/**
		 * Inserts (by copy) the entry at its sorted position, not necessarily first
		 */
		@Override
		public void addFirst(Entry<K, V> e) {
			put(e.getKey(), e.getValue());
		}

		/**
		 * Inserts (by copy) the entry at its sorted position, not necessarily last
		 */
		@Override
		public void addLast(Entry<K, V> e) {
			put(e.getKey(), e.getValue());
		}

		@Override
		public void clear() {
			TreeValueSortedMap.this.clear();
		}

		@Override
		public boolean contains(Object o) {
			if (o == null) {
				return false;
			}
			try {
				@SuppressWarnings("unchecked")
				Node n = (Node) o;
				Node m = nodeMap.get(n.key);
				return Objects.equals(n.val, m.val);
			}
			catch (ClassCastException e) {
				return false;
			}
		}

		@Override
		public Iterator<Entry<K, V>> descendingIterator() {
			return new ReversedListIterator<>(new EntryListIterator(tail.next)); // i.e., null
		}

		@Override
		public Entry<K, V> element() {
			return getFirst();
		}

		@Override
		public Entry<K, V> get(int index) {
			return root.getByIndex(index);
		}

		@Override
		public Entry<K, V> getFirst() {
			Entry<K, V> ret = peekFirst();
			if (ret == null) {
				throw new NoSuchElementException();
			}
			return ret;
		}

		@Override
		public Entry<K, V> getLast() {
			Entry<K, V> ret = peekLast();
			if (ret == null) {
				throw new NoSuchElementException();
			}
			return ret;
		}

		@Override
		public int indexOf(Object o) {
			if (o == null) {
				return -1;
			}
			try {
				@SuppressWarnings("unchecked")
				Node n = (Node) o;
				return n.computeIndex();
			}
			catch (ClassCastException e) {
				return -1;
			}
		}

		@Override
		public boolean isEmpty() {
			return root == null;
		}

		@Override
		public Iterator<Entry<K, V>> iterator() {
			return listIterator();
		}

		@Override
		public int lastIndexOf(Object o) {
			return indexOf(o);
		}

		@Override
		public ListIterator<Entry<K, V>> listIterator() {
			return new EntryListIterator(head);
		}

		@Override
		public ListIterator<Entry<K, V>> listIterator(int index) {
			if (root == null) {
				return Collections.emptyListIterator();
			}
			return new EntryListIterator(root.getByIndex(index));
		}

		@Override
		public boolean offer(Entry<K, V> e) {
			return put(e.getKey(), e.getValue()) == null;
		}

		/**
		 * Inserts (by copy) the entry at its sorted position, not necessarily first
		 */
		@Override
		public boolean offerFirst(Entry<K, V> e) {
			return put(e.getKey(), e.getValue()) == null;
		}

		/**
		 * Inserts (by copy) the entry at its sorted position, not necessarily last
		 */
		@Override
		public boolean offerLast(Entry<K, V> e) {
			return put(e.getKey(), e.getValue()) == null;
		}

		@Override
		public Entry<K, V> peek() {
			return peekFirst();
		}

		@Override
		public Entry<K, V> peekFirst() {
			return head;
		}

		@Override
		public Entry<K, V> peekLast() {
			return tail;
		}

		@Override
		public Entry<K, V> poll() {
			return pollFirst();
		}

		@Override
		public Entry<K, V> pollFirst() {
			if (head == null) {
				return null;
			}
			Node result = head;
			head.remove();
			nodeMap.remove(result.key);
			return result;
		}

		@Override
		public Entry<K, V> pollLast() {
			if (tail == null) {
				return tail;
			}
			Node result = tail;
			tail.remove();
			nodeMap.remove(result.key);
			return result;
		}

		@Override
		public Entry<K, V> pop() {
			return removeFirst();
		}

		@Override
		public void push(Entry<K, V> e) {
			put(e.getKey(), e.getValue());
		}

		@Override
		public Entry<K, V> remove() {
			return removeFirst();
		}

		@Override
		public Entry<K, V> remove(int index) {
			Node n = root.getByIndex(index);
			n.remove();
			nodeMap.remove(n.key);
			return n;
		}

		@Override
		public boolean remove(Object o) {
			try {
				@SuppressWarnings("unchecked")
				Node n = (Node) o;
				Node rm = nodeMap.get(n.key);
				if (rm == n) {
					n.remove();
					nodeMap.remove(n.key);
					return true;
				}
				if (Objects.equals(n.val, rm.val)) {
					nodeMap.remove(rm.key);
					rm.remove();
					return true;
				}
				return false;
			}
			catch (ClassCastException e) {
				return false;
			}
		}

		@Override
		public Entry<K, V> removeFirst() {
			Entry<K, V> ret = pollFirst();
			if (ret == null) {
				throw new NoSuchElementException();
			}
			return ret;
		}

		@Override
		public boolean removeFirstOccurrence(Object o) {
			return remove(o);
		}

		@Override
		public Entry<K, V> removeLast() {
			Entry<K, V> ret = pollLast();
			if (ret == null) {
				throw new NoSuchElementException();
			}
			return ret;
		}

		@Override
		public boolean removeLastOccurrence(Object o) {
			return remove(o);
		}

		/**
		 * Modify the entry (key and value) at index
		 * 
		 * Because the map is sorted by value, the index of the given entry may not remain the same
		 * after it is modified. In fact, this is equivalent to removing the entry at the given
		 * index, and then inserting the given entry at its sorted position.
		 */
		@Override
		public Entry<K, V> set(int index, Entry<K, V> element) {
			Entry<K, V> result = remove(index);
			add(element);
			return result;
		}

		@Override
		public int size() {
			return nodeMap.size();
		}

		/**
		 * This operation is not supported
		 */
		@Override
		public List<Entry<K, V>> subList(int fromIndex, int toIndex) {
			throw new UnsupportedOperationException();
		}
	}

	/**
	 * A public view of the map as a set of keys
	 * 
	 * In addition to {@link Set}, this view implements {@link List} and {@link Deque}, since an
	 * ordered set ought to behave like a list, and since this implementation is meant to be used as
	 * a dynamic-cost priority queue.
	 * 
	 * Generally, only the removal mutation methods are supported, all others are not supported.
	 */
	protected class ValueSortedTreeMapKeySet extends AbstractSet<K>
			implements ValueSortedMapKeyList<K> {
		private ValueSortedTreeMapKeySet() {
		}

		@Override
		public void add(int index, K element) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean add(K e) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean addAll(Collection<? extends K> c) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean addAll(int index, Collection<? extends K> c) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void addFirst(K e) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void addLast(K e) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void clear() {
			TreeValueSortedMap.this.clear();
		}

		@Override
		public boolean contains(Object o) {
			return nodeMap.containsKey(o);
		}

		@Override
		public Iterator<K> descendingIterator() {
			return new ReversedListIterator<>(new KeyListIterator(tail.next)); // i.e., null
		}

		@Override
		public K element() {
			return getFirst();
		}

		@Override
		public K get(int index) {
			return entrySet.get(index).getKey();
		}

		@Override
		public K getFirst() {
			return entrySet.getFirst().getKey();
		}

		@Override
		public K getLast() {
			return entrySet.getLast().getKey();
		}

		@Override
		public int indexOf(Object o) {
			Node n = nodeMap.get(o);
			if (n == null) {
				return -1;
			}
			return n.computeIndex();
		}

		@Override
		public boolean isEmpty() {
			return root == null;
		}

		@Override
		public Iterator<K> iterator() {
			return listIterator();
		}

		@Override
		public int lastIndexOf(Object o) {
			return indexOf(o);
		}

		@Override
		public ListIterator<K> listIterator() {
			return new KeyListIterator(head);
		}

		@Override
		public ListIterator<K> listIterator(int index) {
			return new KeyListIterator(root.getByIndex(index));
		}

		@Override
		public boolean offer(K e) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean offerFirst(K e) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean offerLast(K e) {
			throw new UnsupportedOperationException();
		}

		@Override
		public K peek() {
			return peekFirst();
		}

		@Override
		public K peekFirst() {
			Entry<K, V> n = entrySet.peekFirst();
			if (n == null) {
				return null;
			}
			return n.getKey();
		}

		@Override
		public K peekLast() {
			Entry<K, V> n = entrySet.peekLast();
			if (n == null) {
				return null;
			}
			return n.getKey();
		}

		@Override
		public K poll() {
			return pollFirst();
		}

		@Override
		public K pollFirst() {
			Entry<K, V> n = entrySet.pollFirst();
			if (n == null) {
				return null;
			}
			return n.getKey();
		}

		@Override
		public K pollLast() {
			Entry<K, V> n = entrySet.pollLast();
			if (n == null) {
				return null;
			}
			return n.getKey();
		}

		@Override
		public K pop() {
			return removeFirst();
		}

		@Override
		public void push(K e) {
			throw new UnsupportedOperationException();
		}

		@Override
		public K remove() {
			return removeFirst();
		}

		@Override
		public K remove(int index) {
			return entrySet.remove(index).getKey();
		}

		@Override
		public boolean remove(Object o) {
			return TreeValueSortedMap.this.remove(o) != null;
		}

		@Override
		public K removeFirst() {
			return entrySet.removeFirst().getKey();
		}

		@Override
		public boolean removeFirstOccurrence(Object o) {
			return TreeValueSortedMap.this.remove(o) != null;
		}

		@Override
		public K removeLast() {
			return entrySet.removeLast().getKey();
		}

		@Override
		public boolean removeLastOccurrence(Object o) {
			return TreeValueSortedMap.this.remove(o) != null;
		}

		@Override
		public K set(int index, K element) {
			throw new UnsupportedOperationException();
		}

		@Override
		public int size() {
			return nodeMap.size();
		}

		/**
		 * This operation is not supported
		 */
		@Override
		public List<K> subList(int fromIndex, int toIndex) {
			throw new UnsupportedOperationException();
		}
	}

	/**
	 * A public view of the map as a list of values
	 * 
	 * This view implements {@link SortedList} and {@link Deque}, since an ordered collection ought
	 * to behave like a list, and since this implementation is meant to be used as a dynamic-cost
	 * priority queue.
	 * 
	 * Generally, only the removal mutation methods are supported, all others are not supported.
	 */
	protected class ValueSortedTreeMapValues extends AbstractCollection<V>
			implements SortedList<V>, Deque<V> {
		private ValueSortedTreeMapValues() {
		}

		@Override
		public void add(int index, V element) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean add(V e) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean addAll(Collection<? extends V> c) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean addAll(int index, Collection<? extends V> c) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void addFirst(V e) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void addLast(V e) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void clear() {
			TreeValueSortedMap.this.clear();
		}

		@Override
		public boolean contains(Object o) {
			try {
				@SuppressWarnings("unchecked")
				V val = (V) o;
				return root.searchValue(val, SearchMode.ANY) != null;
			}
			catch (ClassCastException e) {
				return false;
			}
		}

		@Override
		public Iterator<V> descendingIterator() {
			return new ReversedListIterator<>(new ValueListIterator(tail.next)); // i.e., null
		}

		@Override
		public V element() {
			return getFirst();
		}

		@Override
		public V get(int index) {
			return entrySet.get(index).getValue();
		}

		@Override
		public V getFirst() {
			return entrySet.getFirst().getValue();
		}

		@Override
		public V getLast() {
			return entrySet.getLast().getValue();
		}

		@Override
		public int indexOf(Object o) {
			try {
				@SuppressWarnings("unchecked")
				V val = (V) o;
				Node n = searchValue(val, SearchMode.FIRST);
				if (n == null) {
					return -1;
				}
				return n.computeIndex();
			}
			catch (ClassCastException e) {
				return -1;
			}
		}

		@Override
		public int lowerIndex(V element) {
			if (root == null) {
				return -1;
			}
			Node n = searchValue(element, SearchMode.LOWER);
			if (n == null) {
				return -1;
			}
			return n.computeIndex();
		}

		@Override
		public int floorIndex(V element) {
			Node n = searchValue(element, SearchMode.FLOOR);
			if (n == null) {
				return -1;
			}
			return n.computeIndex();
		}

		@Override
		public int ceilingIndex(V element) {
			Node n = searchValue(element, SearchMode.CEILING);
			if (n == null) {
				return -1;
			}
			return n.computeIndex();
		}

		@Override
		public int higherIndex(V element) {
			Node n = searchValue(element, SearchMode.HIGHER);
			if (n == null) {
				return -1;
			}
			return n.computeIndex();
		}

		@Override
		public boolean isEmpty() {
			return root == null;
		}

		@Override
		public Iterator<V> iterator() {
			return listIterator();
		}

		@Override
		public int lastIndexOf(Object o) {
			try {
				@SuppressWarnings("unchecked")
				V val = (V) o;
				Node n = root.searchValue(val, SearchMode.LAST);
				if (n == null) {
					return -1;
				}
				return n.computeIndex();
			}
			catch (ClassCastException e) {
				return -1;
			}
		}

		@Override
		public ListIterator<V> listIterator() {
			return new ValueListIterator(head);
		}

		@Override
		public ListIterator<V> listIterator(int index) {
			return new ValueListIterator(root.getByIndex(index));
		}

		@Override
		public boolean offer(V e) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean offerFirst(V e) {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean offerLast(V e) {
			throw new UnsupportedOperationException();
		}

		@Override
		public V peek() {
			return peekFirst();
		}

		@Override
		public V peekFirst() {
			Entry<K, V> n = entrySet.peekFirst();
			if (n == null) {
				return null;
			}
			return n.getValue();
		}

		@Override
		public V peekLast() {
			Entry<K, V> n = entrySet.peekLast();
			if (n == null) {
				return null;
			}
			return n.getValue();
		}

		@Override
		public V poll() {
			return pollFirst();
		}

		@Override
		public V pollFirst() {
			Entry<K, V> n = entrySet.pollFirst();
			if (n == null) {
				return null;
			}
			return n.getValue();
		}

		@Override
		public V pollLast() {
			Entry<K, V> n = entrySet.pollLast();
			if (n == null) {
				return null;
			}
			return n.getValue();
		}

		@Override
		public V pop() {
			return removeFirst();
		}

		@Override
		public void push(V e) {
			throw new UnsupportedOperationException();
		}

		@Override
		public V remove() {
			return removeFirst();
		}

		@Override
		public V remove(int index) {
			return entrySet.remove(index).getValue();
		}

		@Override
		public boolean remove(Object o) {
			return removeFirstOccurrence(o);
		}

		@Override
		public V removeFirst() {
			return entrySet.removeFirst().getValue();
		}

		@Override
		public boolean removeFirstOccurrence(Object o) {
			try {
				@SuppressWarnings("unchecked")
				V val = (V) o;
				Node n = root.searchValue(val, SearchMode.FIRST);
				if (n == null) {
					return false;
				}
				n.remove();
				nodeMap.remove(n.key);
				return true;
			}
			catch (ClassCastException e) {
				return false;
			}
		}

		@Override
		public V removeLast() {
			return entrySet.removeLast().getValue();
		}

		@Override
		public boolean removeLastOccurrence(Object o) {
			try {
				@SuppressWarnings("unchecked")
				V val = (V) o;
				Node n = root.searchValue(val, SearchMode.LAST);
				if (n == null) {
					return false;
				}
				n.remove();
				nodeMap.remove(n.key);
				return true;
			}
			catch (ClassCastException e) {
				return false;
			}
		}

		@Override
		public V set(int index, V element) {
			throw new UnsupportedOperationException();
		}

		@Override
		public int size() {
			return nodeMap.size();
		}

		/**
		 * This operation is not supported
		 */
		@Override
		public List<V> subList(int fromIndex, int toIndex) {
			throw new UnsupportedOperationException();
		}
	}

	// The user-provided comparator
	protected final Comparator<V> comparator;
	// A hash map to locate entries by key
	protected final Map<K, Node> nodeMap = new HashMap<>();
	/*
	 * Remember, the tree is indexed by *value*, not by key, and more specifically, they are indexed
	 * by the comparator, so an entry's cost may change at any time. Thus, this map provides an
	 * index by key. This is especially important during an update, since we need to locate the
	 * affected node, given that it's most likely not in its correct position at the moment. We also
	 * use it to ensure each key occurs at most once.
	 */

	// Pre-constructed views. Unlike Java's stock collections, I create these outright
	// At least one ought to be accessed for this implementation to be useful
	private transient final ValueSortedTreeMapEntrySet entrySet = createEntrySet();
	private transient final ValueSortedTreeMapKeySet keySet = createKeySet();
	private transient final ValueSortedTreeMapValues values = createValues();

	// Pointers into the data structure
	protected Node root; // The root of the binary tree
	protected Node head; // The node with the least value
	protected Node tail; // The node with the greatest value

	@SuppressWarnings({ "rawtypes", "unchecked" })
	protected TreeValueSortedMap() {
		this(new ComparableComparator());
	}

	protected TreeValueSortedMap(Comparator<V> comparator) {
		this.comparator = comparator;
	}

	protected ValueSortedTreeMapEntrySet createEntrySet() {
		return new ValueSortedTreeMapEntrySet();
	}

	protected ValueSortedTreeMapKeySet createKeySet() {
		return new ValueSortedTreeMapKeySet();
	}

	protected ValueSortedTreeMapValues createValues() {
		return new ValueSortedTreeMapValues();
	}

	protected Node createNode(K key, V value) {
		return new Node(key, value);
	}

	protected Node searchValue(V value, SearchMode mode) {
		if (root == null) {
			return null;
		}
		return root.searchValue(value, mode);
	}

	@Override
	public void clear() {
		nodeMap.clear();
		head = null;
		tail = null;
		root = null;
	}

	@Override
	public boolean containsKey(Object key) {
		return nodeMap.containsKey(key);
	}

	@Override
	public boolean containsValue(Object value) {
		try {
			@SuppressWarnings("unchecked")
			V val = (V) value;
			return searchValue(val, SearchMode.ANY) != null;
		}
		catch (ClassCastException e) {
			return false;
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see ValueSortedTreeMapEntrySet
	 */
	@Override
	public ValueSortedTreeMapEntrySet entrySet() {
		return entrySet;
	}

	@Override
	public V get(Object key) {
		Node n = nodeMap.get(key);
		if (n == null) {
			return null;
		}
		return n.val;
	}

	@Override
	public Entry<K, V> lowerEntryByValue(V value) {
		return searchValue(value, SearchMode.LOWER);
	}

	@Override
	public Entry<K, V> floorEntryByValue(V value) {
		return searchValue(value, SearchMode.FLOOR);
	}

	@Override
	public Entry<K, V> ceilingEntryByValue(V value) {
		return searchValue(value, SearchMode.CEILING);
	}

	@Override
	public Entry<K, V> higherEntryByValue(V value) {
		return searchValue(value, SearchMode.HIGHER);
	}

	@Override
	public boolean isEmpty() {
		return root == null;
	}

	/**
	 * Check if a node is correctly positioned relative to its immediate neighbors
	 * 
	 * @param n the node
	 * @return true if the node need not be moved
	 */
	private boolean isOrdered(Node n) {
		if (n.prev != null) {
			if (comparator.compare(n.prev.val, n.val) > 0) {
				return false;
			}
		}
		if (n.next != null) {
			if (comparator.compare(n.next.val, n.val) < 0) {
				return false;
			}
		}
		return true;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see ValueSortedTreeMapKeySet
	 */
	@Override
	public ValueSortedTreeMapKeySet keySet() {
		return keySet;
	}

	@Override
	public V put(K key, V value) {
		Node n = nodeMap.get(key);
		if (n != null) {
			return n.setValue(value);
		}
		n = createNode(key, value);
		nodeMap.put(key, n);
		if (root == null) {
			root = n;
			head = n;
			tail = n;
		}
		else {
			root.insert(n);
		}
		return null;
	}

	@Override
	public void putAll(Map<? extends K, ? extends V> m) {
		for (Entry<? extends K, ? extends V> ent : m.entrySet()) {
			put(ent.getKey(), ent.getValue());
		}
	}

	@Override
	public V remove(Object key) {
		Node n = nodeMap.remove(key);
		if (n == null) {
			return null;
		}
		n.remove();
		return n.val;
	}

	@Override
	public int size() {
		return nodeMap.size();
	}

	@Override
	public boolean update(K key) {
		Node n = nodeMap.get(key);
		if (n == null) {
			throw new NoSuchElementException();
		}
		return updateNode(n);
	}

	/**
	 * Update a node's position
	 * 
	 * This ought to be called any time the value of a node is modified, whether internall or
	 * externally. The only way we know of external changes is if the user calls
	 * {@link #update(Object)}.
	 * 
	 * @param n the node whose position to check and update
	 * @return true if the node's position changed
	 */
	private boolean updateNode(Node n) {
		if (isOrdered(n)) {
			return false;
		}
		n.remove();
		root.insert(n);
		return true;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see ValueSortedTreeMapValues
	 */
	@Override
	public ValueSortedTreeMapValues values() {
		return values;
	}

	@Override
	public ValueSortedMap<K, V> subMapByValue(V fromValue, boolean fromInclusive, V toValue,
			boolean toInclusive) {
		return new RestrictedValueSortedMap<>(this, comparator, true, fromValue, fromInclusive,
			true, toValue, toInclusive);
	}

	@Override
	// TODO: Test this implementation and related others
	public ValueSortedMap<K, V> headMapByValue(V toValue, boolean inclusive) {
		return new RestrictedValueSortedMap<>(this, comparator, false, null, false, true, toValue,
			inclusive);
	}

	@Override
	public ValueSortedMap<K, V> tailMapByValue(V fromValue, boolean inclusive) {
		return new RestrictedValueSortedMap<>(this, comparator, true, fromValue, inclusive, false,
			null, false);
	}
}
