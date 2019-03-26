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

public class ReverseSetIterator<T> extends SetIterator<T> {

	ReverseSetIterator(RedBlackTree<T,T> tree, RedBlackNode<T,T> node) {
		super(tree, node);
	}
	
	@Override
    public IteratorSTL<T> copy() {
		return new ReverseSetIterator<T>( tree, node);
	}
	
	
	@Override
    public IteratorSTL<T> increment() {
		if (node == null) {
			throw new IndexOutOfBoundsException();
		}
		node = node.getPredecessor();
		return this;
	}
	@Override
    public IteratorSTL<T> decrement() {
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
		RedBlackNode<T, T> nextNode = node.getPredecessor();
		tree.deleteEntry(node);
		node = nextNode;
	}

	@Override
    public boolean isBegin() {
		return node == tree.getLast();
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
		ReverseSetIterator<?> other = (ReverseSetIterator)obj;
		return tree == other.tree && node == other.node;
	}
	@Override
	public int hashCode() {
		return tree.hashCode();
	}

}
