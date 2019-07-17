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


import java.util.Comparator;

public class MultiSetSTL<K> {
	RedBlackTree<K,K> rbTree;

	public MultiSetSTL(Comparator<K> comparator) {
		rbTree = new RedBlackTree<>(comparator, true);
	}

	public void insert(K key) {
		rbTree.put(key, key);
	}

	public boolean contains(K key) {
		return rbTree.containsKey(key);
	}

	public boolean remove(K key) {
		return rbTree.remove(key) != null;
	}

	public IteratorSTL<K> begin() {
		return new SetIterator<>(rbTree, rbTree.getFirst());
	}
	public IteratorSTL<K> end() {
		return new SetIterator<>(rbTree, null);
	}
	public IteratorSTL<K> rBegin() {
		return new ReverseSetIterator<>(rbTree, rbTree.getLast());
	}
	public IteratorSTL<K> rEnd() {
		return new ReverseSetIterator<>(rbTree, null);
	}
	public IteratorSTL<K> lower_bound( K key ) {

		RedBlackNode<K,K> node = rbTree.lowerBound( key );
		return new SetIterator<>(rbTree, node);
	}


	public IteratorSTL<K> upper_bound( K key ) {
		RedBlackNode<K,K> node = rbTree.upperBound( key );
		SetIterator<K> it = new SetIterator<>(rbTree, node);
		return it;
	}
	public static void main(String[] args) {
		MultiSetSTL<Integer> set = new ComparableMultiSetSTL<Integer>();
		set.insert(7);
		set.insert(3);
		set.insert(9);
		set.insert(20);
		set.insert(15);
		set.insert(1);
		set.insert(20);
		set.insert(20);
		set.insert(4);
		set.insert(50);

//		IteratorSTL<Integer> it = set.begin();
//		while(!it.isEnd()) {
//			System.out.println("value = "+it.getAndIncrement());
//		}
//System.out.println("  ----");
//		it = set.rBegin();
//		while(!it.isEnd()) {
//			System.out.println("value = "+it.getAndIncrement());
//		}
//
//		it = set.lower_bound( 20 );
//		while(!it.isEnd()) {
//			System.out.println("value = "+it.getAndIncrement());
//		}


	}

	//TODO can we make this faster using the hint?
	public IteratorSTL<K> insert( IteratorSTL<K> low, K key ) {
		Pair<RedBlackNode<K, K>, Boolean> pair = rbTree.put(key, key);
		return new SetIterator<>(rbTree, pair.first);
	}

	public void erase( IteratorSTL<K> position ) {
		SetIterator<K> setIterator = (SetIterator<K>) position;

		RedBlackNode<K, K> node = setIterator.node;
		if (node == null) {
			throw new IndexOutOfBoundsException();
		}
		setIterator.node = node.getSuccessor();
		setIterator.erased = true;
		rbTree.deleteEntry(node);
	}


}

