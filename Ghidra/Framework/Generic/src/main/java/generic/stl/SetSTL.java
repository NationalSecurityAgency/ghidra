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


public class SetSTL<K> {
	RedBlackTree<K,K> rbTree;
	
	public SetSTL(Comparator<K> comparator) {
		rbTree = new RedBlackTree<>(comparator, false);
	}
	public SetSTL(SetSTL<K> set) {
		rbTree = new RedBlackTree<>(set.rbTree);
	}
	
	public Pair<IteratorSTL<K>, Boolean> insert(K key) {
		Pair<RedBlackNode<K, K>, Boolean> result = rbTree.put(key, key);
		return new Pair<>( new SetIterator<>( rbTree, result.first ), 
				result.second );
	}
	
	public boolean contains(K key) {
		return rbTree.containsKey(key);
	}
	
	public boolean remove(K key) {
		return rbTree.remove(key) != null;
	}
	
	public IteratorSTL<K> find( K key ) {
		RedBlackNode<K, K> node = rbTree.findFirstNode( key );
		if ( node == null ) {
			return end();
		}
		return new SetIterator<>( rbTree, node );
	}
	
	public void erase( IteratorSTL<K> iterator ) {
		SetIterator<K> it = (SetIterator<K>)iterator;
		RedBlackNode<K, K> node = it.node;
		
		if (node == null) {
			throw new IndexOutOfBoundsException();
		}
		it.node = node.getSuccessor();
		it.erased = true;
		rbTree.deleteEntry(node);
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

	public void erase( K key ) {
		rbTree.remove( key );
	}

	public void clear() {
		rbTree.removeAll();
	}
	
	public boolean isEmpty() {
		return rbTree.isEmpty();
	}

	@Override
    public String toString() {
	    StringBuilder sb = new StringBuilder();
	    sb.append("{ ");
	    IteratorSTL<K> ii = begin();
	    while (!ii.isEnd()) {
	        K thing = ii.get();
	        sb.append(thing.toString());
	        sb.append(" ");
	        ii.increment();
	    }
	    sb.append("}");
	    return sb.toString();
	}
}
