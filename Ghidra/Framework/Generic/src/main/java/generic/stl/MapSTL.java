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


public class MapSTL<K,V> {
	
	public static final String EOL = System.getProperty( "line.separator" );

	RedBlackTree<K,V> rbTree;
	
	public MapSTL(Comparator<K> comparator) {
		rbTree = new RedBlackTree<>(comparator, false);
	}

	@Override
    public String toString() {
        StringBuffer buffy = new StringBuffer("{");
        IteratorSTL<Pair<K, V>> begin = begin();
        while ( !begin.isEnd() ) {
            Pair<K, V> pair = begin.get();
            begin.increment();
            buffy.append( pair.toString() ).append( ", " ).append( EOL );
        }
        buffy.append("}");
        return buffy.toString();
    }
	
	public void put( K key, V value ) {
		rbTree.put( key, value );
	}
	
	public boolean add(K key, V value) {
		if (rbTree.containsKey( key )) {
			return false;
		}
		rbTree.put(key, value);
		return true;
	}
	
	public boolean contains(K key) {
		return rbTree.containsKey(key);
	}
	
	public V remove(K key) {
		return rbTree.remove(key);
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
	
	public V erase(K key) {
	    return remove(key);
	}
	
	public boolean empty() {
	    return rbTree.isEmpty();
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
	
	public boolean isEmpty() {
		return rbTree.isEmpty();
	}
	
	public void clear() {
		rbTree.removeAll();
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
	
	public void erase( IteratorSTL<Pair<K,V>> start, IteratorSTL<Pair<K,V>> end ) {
		while ( !start.equals( end ) ) {
			erase(start);
			start.increment();
		}
	}
	
	public V get( K key ) {
		RedBlackNode<K, V> node = rbTree.findFirstNode( key );
		if ( node == null ) {
			return null;
		}
		return node.value;
	}
	
	public IteratorSTL<Pair<K,V>> find(K key) {
	    if (rbTree.containsKey(key)) {
	        return lower_bound(key);
	    }
	    return end();
	}
	public int size() {
		return rbTree.size();
	}
	
	public void insert(IteratorSTL<Pair<K,V>> start, IteratorSTL<Pair<K,V>> end ) {
		while(!start.equals(end)) {
			add(start.get().first, start.get().second);		
			start.increment();
		}
	}
}
