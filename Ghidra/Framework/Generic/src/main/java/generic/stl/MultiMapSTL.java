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

public class MultiMapSTL<K,V> {
	RedBlackTree<K,V> rbTree;

	public MultiMapSTL(Comparator<K> comparator) {
		rbTree = new RedBlackTree<>(comparator, true);
	}

	public void add(K key, V value) {
		rbTree.put(key, value);
	}

	public boolean contains(K key) {
		return rbTree.containsKey(key);
	}

	public V remove(K key) {
		return rbTree.remove(key);
	}

	public void erase( IteratorSTL<Pair<K,V>> iter ) {
		MapIteratorSTL<K,V> it = ((MapIteratorSTL<K,V>)iter);
		RedBlackNode<K, V> node = it.node;
		if (node == null) {
			throw new IndexOutOfBoundsException();
		}

		it.node = node.getSuccessor();
		it.erased = true;
		rbTree.deleteEntry(node);
	}

	public IteratorSTL<Pair<K,V>> begin() {
		return new MapIteratorSTL<>(rbTree, rbTree.getFirst());
	}
	public IteratorSTL<Pair<K,V>> end() {
		return new MapIteratorSTL<>(rbTree, null);
	}
	public IteratorSTL<Pair<K,V>> rBegin() {
		return new ReverseMapIteratorSTL<>(rbTree, rbTree.getLast());
	}
	public IteratorSTL<Pair<K,V>> rEnd() {
		return new ReverseMapIteratorSTL<>(rbTree, null);
	}

	public IteratorSTL<Pair<K,V>> lower_bound( K key ) {

		RedBlackNode<K, V> node = rbTree.lowerBound( key );
		return new MapIteratorSTL<>(rbTree, node);
	}


	public IteratorSTL<Pair<K,V>> upper_bound( K key ) {
		RedBlackNode<K, V> node = rbTree.upperBound( key );
		MapIteratorSTL<K, V> it = new MapIteratorSTL<>(rbTree, node);
		return it;
	}

	public static void main(String[] args) {
		MultiMapSTL<Integer, String> set = new ComparableMultiMapSTL<>();
		set.add(7, "dog");
		set.add(3, "blue");
		set.add(9, "elf");
		set.add(20,"gate");
		set.add(15, "fog");
		set.add(1, "apple");
		set.add(20, "hog");
		set.add(20,"indian");
		set.add(4, "cat");
		set.add(50, "jump");

//		IteratorSTL<Pair<Integer, String>> it = set.begin();
//		while(!it.isEnd()) {
//			System.out.println("value = "+it.getAndIncrement());
//		}
//System.out.println("  ----");
//		it = set.rBegin();
//		while(!it.isEnd()) {
//			System.out.println("value = "+it.getAndIncrement());
//		}
//
	}

}
