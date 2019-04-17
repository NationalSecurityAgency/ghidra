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

public class SetIterator<T> implements IteratorSTL<T> {

	protected RedBlackTree<T, T> tree;
	protected RedBlackNode<T, T> node;
	public boolean erased = false;

	
	SetIterator(RedBlackTree<T,T> tree, RedBlackNode<T,T> node) {
		this.tree = tree;
		this.node = node;
	}
	SetIterator(RedBlackTree<T,T> tree, RedBlackNode<T,T> node, boolean erased) {
		this.tree = tree;
		this.node = node;
		this.erased = erased;
	}
	public void assign( IteratorSTL<T> otherIterator ) {
		SetIterator<T> other = (SetIterator<T>) otherIterator;
		this.tree = other.tree;
		this.node = other.node;
		this.erased = other.erased;
	}
	public IteratorSTL<T> copy() {
		return new SetIterator<T>( tree, node, erased);
	}
	
	public IteratorSTL<T> decrement() {
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

	public T get() {
		if (erased) {
			throw new IndexOutOfBoundsException("element erased");
		}
		if (node == null) {
			throw new IndexOutOfBoundsException();
		}
		return node.getKey();
	}

	public IteratorSTL<T> increment() {
		if (!erased && node == null) {
			throw new IndexOutOfBoundsException();
		}
		if (!erased) {	// erased nodes already point to the successor
			node = node.getSuccessor();
		}
		erased = false;
		return this;
	}

	public void insert(T value) {
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

	public void set(T value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (obj.getClass() != this.getClass()) {
			return false;
		}
		SetIterator<?> other = (SetIterator)obj;
		return tree == other.tree && node == other.node && erased == other.erased;
	}
	@Override
	public int hashCode() {
		return tree.hashCode();
	}
	public IteratorSTL<T> decrement( int n ) {
		throw new UnsupportedOperationException();
	}
	public IteratorSTL<T> increment( int n ) {
		throw new UnsupportedOperationException();
	}


}
