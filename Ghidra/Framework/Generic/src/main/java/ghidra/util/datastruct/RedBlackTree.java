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

import static ghidra.util.datastruct.RedBlackEntry.NodeColor.BLACK;
import static ghidra.util.datastruct.RedBlackEntry.NodeColor.RED;

import java.util.ConcurrentModificationException;
import java.util.ListIterator;

import org.apache.commons.collections4.iterators.EmptyListIterator;


/**
 * A RedBlack Tree implementation with K type keys and place to store V type values.
 */

public class RedBlackTree<K extends Comparable<K>, V> implements Iterable<RedBlackEntry<K, V>> {

	private RedBlackEntry<K, V> root;
	private int size;
	private int modCount = 0;
	private RedBlackEntry<K, V> maxEntry;
	private RedBlackEntry<K, V> minEntry;

	/**
	 * Creates a new RedBlackKeySet that can store keys between 0 and n.
	 */
	public RedBlackTree() {
	}

	/**
	 * Returns the number keys in this set.
	 */
	public int size() {
		return size;
	}

	/**
	 * Returns true if the key is in the set.
	 * @param key the key whose presence is to be tested.
	 */
	public boolean containsKey(K key) {
		RedBlackEntry<K, V> node = getNode(key);
		return node != null;
	}

	/**
	 * Returns the first entry in this set.
	 */
	public RedBlackEntry<K, V> getFirst() {
		return minEntry;
	}

	/**
	 * Returns the last entry in this set.
	 */
	public RedBlackEntry<K, V> getLast() {
		return maxEntry;
	}

	/**
	 * Returns the node with largest key in the set that is less or equal to the given key.
	 * Returns null if there are no keys less than or equal to the given key.
	 * @param key the search key
	 */
	public RedBlackEntry<K, V> getEntryLessThanEqual(K key) {
		RedBlackEntry<K, V> bestNode = null;

		RedBlackEntry<K, V> node = root;
		while (node != null) {
			int result = key.compareTo(node.key);
			if (result == 0) {
				return node;
			}
			if (result < 0) {
				node = node.left;
			}
			else {
				bestNode = node;
				node = node.right;
			}

		}
		return bestNode;
	}

	/**
	 * Returns the node with largest key in the set that is less or equal to the given key.
	 * Returns null if there are no keys less than or equal to the given key.
	 * @param key the search key
	 */
	public RedBlackEntry<K, V> getEntryGreaterThanEqual(K key) {
		RedBlackEntry<K, V> bestNode = null;

		RedBlackEntry<K, V> node = root;
		while (node != null) {
			int result = key.compareTo(node.key);
			if (result == 0) {
				return node;
			}
			if (result < 0) {
				bestNode = node;
				node = node.left;
			}
			else {
				node = node.right;
			}

		}
		return bestNode;
	}

	/**
	 * Adds the given key,value to the map. If the map does not allow duplicate keys and a key
	 * already exists, the old value will be replaced by the new value and the old value will be
	 * returned. 
	 * @param key the key to add to the set.
	 * @return the old value associated with the key, or null if the key was not previously in the map.
	 */
	public V put(K key, V value) {
		RedBlackEntry<K, V> node = getOrCreateEntry(key);
		V oldValue = node.getValue();
		node.setValue(value);
		return oldValue;
	}

	public RedBlackEntry<K, V> getOrCreateEntry(K key) {
		if (root == null) {
			size++;
			modCount++;
			root = new RedBlackEntry<K, V>(key, null, null);
			maxEntry = root;
			minEntry = root;
			return root;
		}

		if (key.compareTo(maxEntry.key) > 0) {
			size++;
			modCount++;
			RedBlackEntry<K, V> newNode = new RedBlackEntry<K, V>(key, null, maxEntry);
			maxEntry.right = newNode;
			maxEntry = newNode;
			fixAfterInsertion(maxEntry);
			return newNode;
		}

		RedBlackEntry<K, V> node = root;
		while (true) {
			int comp = key.compareTo(node.key);
			if (comp == 0) {
				return node;
			}
			else if (comp < 0) {
				if (node.left != null) {
					node = node.left;
				}
				else {
					size++;
					modCount++;
					RedBlackEntry<K, V> newNode = new RedBlackEntry<K, V>(key, null, node);
					node.left = newNode;
					if (node == minEntry) {
						minEntry = newNode;
					}
					fixAfterInsertion(node.left);
					return newNode;
				}
			}
			else {
				if (node.right != null) {
					node = node.right;
				}
				else {
					size++;
					modCount++;
					RedBlackEntry<K, V> newNode = new RedBlackEntry<K, V>(key, null, node);
					node.right = newNode;
					if (node == maxEntry) {
						maxEntry = newNode;
					}
					fixAfterInsertion(node.right);
					return newNode;
				}
			}
		}

	}

	public RedBlackEntry<K, V> getEntry(K key) {
		return getNode(key);
	}

	private RedBlackEntry<K, V> getNode(K key) {
		RedBlackEntry<K, V> node = getEntryLessThanEqual(key);
		if (node != null && node.getKey().equals(key)) {
			return node;
		}
		return null;
	}

	/**
	 * Removes the given key (first if duplicates are allowed) from the set.
	 * @param key the key to remove from the set.
	 * @return the value associated with the key removed or null if the key not found.
	 */
	public V remove(K key) {

		RedBlackEntry<K, V> node = getNode(key);
		if (node == null) {
			return null;
		}
		V value = node.value;
		deleteEntry(node);
		return value;
	}

	public void removeNode(RedBlackEntry<K, V> node) {
		deleteEntry(node);
	}

	/**
	 * Removes all entries from the set.
	 */
	public void removeAll() {
		size = 0;
		modCount++;
		root = null;
		maxEntry = null;
	}

	/**
	 *  Test if the set is empty.
	 *@return true if the set is empty.
	 */
	public boolean isEmpty() {
		return size == 0;
	}

	@Override
	public ListIterator<RedBlackEntry<K, V>> iterator() {
		return new RedBlackTreeIterator(true);
	}

	public ListIterator<RedBlackEntry<K, V>> iterator(boolean forward) {
		return new RedBlackTreeIterator(forward);
	}

	@SuppressWarnings("unchecked")
	public ListIterator<RedBlackEntry<K, V>> iterator(RedBlackEntry<K, V> firstEntry,
			boolean forward) {
		if (firstEntry == null) {
			return EmptyListIterator.INSTANCE;
		}
		return new RedBlackTreeIterator(firstEntry, forward);
	}

	public ListIterator<RedBlackEntry<K, V>> iterator(K key, boolean forward) {
		RedBlackEntry<K, V> entry =
			forward ? getEntryGreaterThanEqual(key) : getEntryLessThanEqual(key);

		return new RedBlackTreeIterator(entry, forward);
	}

	/**
	 * Balancing operations.
	 *
	 * Implementations of re-balancing during insertion and deletion are
	 * slightly different than the CLR version.  Rather than using dummy
	 * nilnodes, we use a set of accessors that deal properly with null.  They
	 * are used to avoid messiness surrounding nullness checks in the main
	 * algorithms.
	 */

	/**
	 * Returns the color of the given node.
	 */
	private static <K, V> RedBlackEntry.NodeColor colorOf(RedBlackEntry<K, V> p) {
		return (p == null ? BLACK : p.color);
	}

	/**
	 * Returns the parent of the given node.
	 */
	private static <K, V> RedBlackEntry<K, V> parentOf(RedBlackEntry<K, V> p) {
		return (p == null ? null : p.parent);
	}

	/**
	 *  Sets the color of the given node to the given color.
	 */
	private static <K, V> void setColor(RedBlackEntry<K, V> p, RedBlackEntry.NodeColor c) {
		if (p != null)
			p.color = c;
	}

	/**
	 * Returns the left child of the given node.
	 */
	private static <K, V> RedBlackEntry<K, V> leftOf(RedBlackEntry<K, V> p) {
		return (p == null) ? null : p.left;
	}

	/**
	 *  Returns the right child of the given node.
	 */
	private static <K, V> RedBlackEntry<K, V> rightOf(RedBlackEntry<K, V> p) {
		return (p == null) ? null : p.right;
	}

	/** From CLR **/
	private void rotateLeft(RedBlackEntry<K, V> p) {
		RedBlackEntry<K, V> r = p.right;
		p.right = r.left;
		if (r.left != null) {
			r.left.parent = p;
		}
		r.parent = p.parent;
		if (p.parent == null) {
			root = r;
		}
		else if (p.parent.left == p) {
			p.parent.left = r;
		}
		else {
			p.parent.right = r;
		}
		r.left = p;
		p.parent = r;
	}

	/** From CLR **/
	private void rotateRight(RedBlackEntry<K, V> p) {
		RedBlackEntry<K, V> l = p.left;
		p.left = l.right;
		if (l.right != null) {
			l.right.parent = p;
		}
		l.parent = p.parent;
		if (p.parent == null) {
			root = l;
		}
		else if (p.parent.right == p) {
			p.parent.right = l;
		}
		else {
			p.parent.left = l;
		}
		l.right = p;
		p.parent = l;
	}

	/** From CLR **/
	private void fixAfterInsertion(RedBlackEntry<K, V> x) {
		x.color = RED;

		while (x != null && x != root && x.parent.color == RED) {
			if (parentOf(x) == leftOf(parentOf(parentOf(x)))) {
				RedBlackEntry<K, V> y = rightOf(parentOf(parentOf(x)));
				if (colorOf(y) == RED) {
					setColor(parentOf(x), BLACK);
					setColor(y, BLACK);
					setColor(parentOf(parentOf(x)), RED);
					x = parentOf(parentOf(x));
				}
				else {
					if (x == rightOf(parentOf(x))) {
						x = parentOf(x);
						rotateLeft(x);
					}
					setColor(parentOf(x), BLACK);
					setColor(parentOf(parentOf(x)), RED);
					if (parentOf(parentOf(x)) != null) {
						rotateRight(parentOf(parentOf(x)));
					}
				}
			}
			else {
				RedBlackEntry<K, V> y = leftOf(parentOf(parentOf(x)));
				if (colorOf(y) == RED) {
					setColor(parentOf(x), BLACK);
					setColor(y, BLACK);
					setColor(parentOf(parentOf(x)), RED);
					x = parentOf(parentOf(x));
				}
				else {
					if (x == leftOf(parentOf(x))) {
						x = parentOf(x);
						rotateRight(x);
					}
					setColor(parentOf(x), BLACK);
					setColor(parentOf(parentOf(x)), RED);
					if (parentOf(parentOf(x)) != null) {
						rotateLeft(parentOf(parentOf(x)));
					}
				}
			}
		}
		root.color = BLACK;
	}

	/**
	 * Delete node p, and then rebalance the tree.
	 */
	public void deleteEntry(RedBlackEntry<K, V> p) {
		modCount++;
		size--;

		if (p == minEntry) {
			minEntry = p.getSuccessor();
		}
		if (p == maxEntry) {
			maxEntry = p.getPredecessor();
		}

		// If strictly internal, first swap position with successor.
		if (p.left != null && p.right != null) {
			RedBlackEntry<K, V> node = p.getSuccessor();
			swapPosition(node, p);
		}

		// Start fixup at replacement node, if it exists.
		RedBlackEntry<K, V> replacement = (p.left != null ? p.left : p.right);

		if (replacement != null) {
			// Link replacement to parent
			replacement.parent = p.parent;
			if (p.parent == null) {
				root = replacement;
			}
			else if (p.isLeftChild()) {
				p.parent.left = replacement;
			}
			else {
				p.parent.right = replacement;
			}

			// Null out links so they are OK to use by fixAfterDeletion.
			p.left = p.right = p.parent = null;

			// Fix replacement
			if (p.color == BLACK) {
				fixAfterDeletion(replacement);
			}
		}
		else if (p.parent == null) { // return if we are the only node.
			root = null;
		}
		else { //  No children. Use self as phantom replacement and unlink.
			if (p.color == BLACK) {
				fixAfterDeletion(p);
			}

			if (p.parent != null) {
				if (p.isLeftChild()) {
					p.parent.left = null;
				}
				else if (p == p.parent.right) {
					p.parent.right = null;
				}
				p.parent = null;
			}
		}
		p.color = null;	// set color to null to mark it as disposed.
	}

	/** From CLR **/
	private void fixAfterDeletion(RedBlackEntry<K, V> x) {
		while (x != root && colorOf(x) == BLACK) {
			if (x == leftOf(parentOf(x))) {
				RedBlackEntry<K, V> sib = rightOf(parentOf(x));

				if (colorOf(sib) == RED) {
					setColor(sib, BLACK);
					setColor(parentOf(x), RED);
					rotateLeft(parentOf(x));
					sib = rightOf(parentOf(x));
				}

				if (colorOf(leftOf(sib)) == BLACK && colorOf(rightOf(sib)) == BLACK) {
					setColor(sib, RED);
					x = parentOf(x);
				}
				else {
					if (colorOf(rightOf(sib)) == BLACK) {
						setColor(leftOf(sib), BLACK);
						setColor(sib, RED);
						rotateRight(sib);
						sib = rightOf(parentOf(x));
					}
					setColor(sib, colorOf(parentOf(x)));
					setColor(parentOf(x), BLACK);
					setColor(rightOf(sib), BLACK);
					rotateLeft(parentOf(x));
					x = root;
				}
			}
			else { // symmetric
				RedBlackEntry<K, V> sib = leftOf(parentOf(x));

				if (colorOf(sib) == RED) {
					setColor(sib, BLACK);
					setColor(parentOf(x), RED);
					rotateRight(parentOf(x));
					sib = leftOf(parentOf(x));
				}

				if (colorOf(rightOf(sib)) == BLACK && colorOf(leftOf(sib)) == BLACK) {
					setColor(sib, RED);
					x = parentOf(x);
				}
				else {
					if (colorOf(leftOf(sib)) == BLACK) {
						setColor(rightOf(sib), BLACK);
						setColor(sib, RED);
						rotateLeft(sib);
						sib = leftOf(parentOf(x));
					}
					setColor(sib, colorOf(parentOf(x)));
					setColor(parentOf(x), BLACK);
					setColor(leftOf(sib), BLACK);
					rotateRight(parentOf(x));
					x = root;
				}
			}
		}

		setColor(x, BLACK);
	}

	/**
	 * Swap the linkages of two nodes in a tree.
	 */
	private void swapPosition(RedBlackEntry<K, V> x, RedBlackEntry<K, V> y) {
		// Save initial values.
		RedBlackEntry<K, V> px = x.parent, lx = x.left, rx = x.right;
		RedBlackEntry<K, V> py = y.parent, ly = y.left, ry = y.right;
		boolean xWasLeftChild = px != null && x == px.left;
		boolean yWasLeftChild = py != null && y == py.left;

		// Swap, handling special cases of one being the other's parent.
		if (x == py) {  // x was y's parent
			x.parent = y;
			if (yWasLeftChild) {
				y.left = x;
				y.right = rx;
			}
			else {
				y.right = x;
				y.left = lx;
			}
		}
		else {
			x.parent = py;
			if (py != null) {
				if (yWasLeftChild) {
					py.left = x;
				}
				else {
					py.right = x;
				}
			}
			y.left = lx;
			y.right = rx;
		}

		if (y == px) { // y was x's parent
			y.parent = x;
			if (xWasLeftChild) {
				x.left = y;
				x.right = ry;
			}
			else {
				x.right = y;
				x.left = ly;
			}
		}
		else {
			y.parent = px;
			if (px != null) {
				if (xWasLeftChild) {
					px.left = y;
				}
				else {
					px.right = y;
				}
			}
			x.left = ly;
			x.right = ry;
		}

		// Fix children's parent pointers
		if (x.left != null) {
			x.left.parent = x;
		}
		if (x.right != null) {
			x.right.parent = x;
		}
		if (y.left != null) {
			y.left.parent = y;
		}
		if (y.right != null) {
			y.right.parent = y;
		}

		// Swap colors
		RedBlackEntry.NodeColor c = x.color;
		x.color = y.color;
		y.color = c;

		// Check if root changed
		if (root == x) {
			root = y;
		}
		else if (root == y) {
			root = x;
		}
	}

	private class RedBlackTreeIterator implements ListIterator<RedBlackEntry<K, V>> {

		private RedBlackEntry<K, V> nextNode;
		private RedBlackEntry<K, V> previousNode;
		private RedBlackEntry<K, V> lastReturnedNode;
		private final boolean forward;
		private int expectedModCount = modCount;

		RedBlackTreeIterator(boolean forward) {
			this.forward = forward;
			if (!isEmpty()) {
				nextNode = forward ? getFirst() : getLast();
				previousNode = null;
			}
		}

		RedBlackTreeIterator(RedBlackEntry<K, V> firstNode, boolean forward) {
			this.forward = forward;
			this.nextNode = firstNode;
			if (firstNode != null) {
				this.previousNode = forward ? nextNode.getPredecessor() : nextNode.getSuccessor();
			}
			else {
				this.previousNode = forward ? getLast() : getFirst();
			}
		}

		@Override
		public boolean hasNext() {
			return nextNode != null;
		}

		@Override
		public boolean hasPrevious() {
			return previousNode != null;
		}

		@Override
		public RedBlackEntry<K, V> next() {
			if (modCount != expectedModCount) {
				throw new ConcurrentModificationException();
			}
			if (nextNode == null) {
				return null;
			}
			lastReturnedNode = nextNode;
			previousNode = nextNode;
			nextNode = forward ? nextNode.getSuccessor() : nextNode.getPredecessor();
			return lastReturnedNode;
		}

		@Override
		public RedBlackEntry<K, V> previous() {
			if (modCount != expectedModCount) {
				throw new ConcurrentModificationException();
			}
			if (previousNode == null) {
				return null;
			}
			lastReturnedNode = previousNode;
			nextNode = previousNode;
			previousNode = forward ? previousNode.getPredecessor() : previousNode.getSuccessor();
			return lastReturnedNode;
		}

		@Override
		public void remove() {
			if (lastReturnedNode == null) {
				throw new IllegalStateException(
					"next has not been called or remove has already been called");
			}
			deleteEntry(lastReturnedNode);
			if (nextNode != null) {
				previousNode = forward ? nextNode.getPredecessor() : nextNode.getSuccessor();
			}
			else {
				previousNode = forward ? getLast() : getFirst();
			}
			lastReturnedNode = null;
		}

		@Override
		public int nextIndex() {
			throw new UnsupportedOperationException();
		}

		@Override
		public int previousIndex() {
			throw new UnsupportedOperationException();
		}

		@Override
		public void set(RedBlackEntry<K, V> e) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void add(RedBlackEntry<K, V> e) {
			throw new UnsupportedOperationException();
		}

	}
}
