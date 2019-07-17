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


public class ReverseMapIteratorSTL<K, V> extends MapIteratorSTL<K, V> {

	ReverseMapIteratorSTL(RedBlackTree<K,V> tree, RedBlackNode<K,V> node) {
		super( tree, node);
	}

	@Override
    public IteratorSTL<Pair<K,V>> increment() {
		if (node == null) {
			throw new IndexOutOfBoundsException();
		}
		node = node.getPredecessor();
		return this;
	}
	@Override
    public IteratorSTL<Pair<K,V>> decrement() {
		if (node == null && tree.isEmpty()) {
			throw new IndexOutOfBoundsException();
		}
		if (node == null) {
			node = tree.getFirst();
		}
		else {
			node = node.getSuccessor();
		}
		return this;
	}

	public void delete() {
		if (node == null) {
			throw new IndexOutOfBoundsException();
		}
		RedBlackNode<K, V> nextNode = node.getPredecessor();
		tree.deleteEntry(node);
		node = nextNode;
	}

	public void delete(int count) {
		throw new UnsupportedOperationException();
	}

	@Override
    public void insert(Pair<K, V> value) {
		throw new UnsupportedOperationException();
	}

	@Override
    public boolean isBegin() {
		return node == tree.getLast();
	}
	@Override
    public IteratorSTL<Pair<K, V>> copy() {
		return new ReverseMapIteratorSTL<K, V>(tree, node);
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
		ReverseMapIteratorSTL<K, V> other = (ReverseMapIteratorSTL<K, V>) obj;
		return tree == other.tree && node == other.node;
	}
}
