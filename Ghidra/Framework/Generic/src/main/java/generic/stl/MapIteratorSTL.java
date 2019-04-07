/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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


public class MapIteratorSTL<K, V> implements IteratorSTL<Pair<K, V>> {
	protected RedBlackTree<K, V> tree;
	protected RedBlackNode<K, V> node;
	protected boolean erased;

	MapIteratorSTL(RedBlackTree<K,V> tree, RedBlackNode<K,V> node, boolean erased) {
		this.tree = tree;
		this.node = node;
		this.erased = erased;
	}

	MapIteratorSTL(RedBlackTree<K,V> tree, RedBlackNode<K,V> node) {
		this.tree = tree;
		this.node = node;
	}
	
	public void assign( IteratorSTL<Pair<K,V>> otherIterator ) {
		MapIteratorSTL<K,V> other = (MapIteratorSTL<K, V>)otherIterator;
		this.tree = other.tree;
		this.node = other.node;
		this.erased = other.erased;
	}
	public IteratorSTL<Pair<K,V>> decrement() {
		if (node == null && tree.isEmpty()) {
			throw new IndexOutOfBoundsException();
		}
		if (node == null) {
			node = tree.getLast();
		}
		else {
			node = node.getPredecessor();
		}
		erased = false;
		return this;
	}

	public Pair<K, V> get() {
		if (erased) {
			throw new IndexOutOfBoundsException("element erased");
		}

		if (node == null) {
			throw new IndexOutOfBoundsException();
		}
		return new Pair<K,V>(node.getKey(), node.getValue());
	}

	public IteratorSTL<Pair<K,V>> increment() {
		if (!erased && node == null) {
			throw new IndexOutOfBoundsException();
		}
		if (!erased) { // erased nodes already point to the successor
			node = node.getSuccessor();
		}
		erased = false;
		return this;
	}

	public void insert(Pair<K, V> value) {
		throw new UnsupportedOperationException();
	}

	public boolean isBegin() {
		if (erased) {
			throw new RuntimeException("Iterater in invalid state");
		}
		return node == tree.getFirst();
	}

	public boolean isEnd() {
		if (erased) {
			throw new RuntimeException("Iterater in invalid state");
		}
		return node == null;
	}

	public void set(Pair<K, V> value) {
		throw new UnsupportedOperationException();
	}

	public IteratorSTL<Pair<K, V>> copy() {
		return new MapIteratorSTL<K, V>(tree, node);
	}
	public IteratorSTL<Pair<K, V>> decrement( int n ) {
		throw new UnsupportedOperationException();
	}
	public IteratorSTL<Pair<K, V>> increment( int n ) {
		throw new UnsupportedOperationException();
	}
		
	@SuppressWarnings("unchecked")
	@Override
	public boolean equals( Object obj ) {
		if (obj == this) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (obj.getClass() != getClass() ) {
			return false;
		}
		MapIteratorSTL<K, V> other = (MapIteratorSTL<K, V>) obj;
		return tree == other.tree && node == other.node && erased == other.erased;
	}
}
