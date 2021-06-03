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
import static generic.stl.RedBlackNode.NodeColor.BLACK;
import static generic.stl.RedBlackNode.NodeColor.RED;


import java.util.Comparator;


/**
 * A RedBlack Tree implementation with K type keys and place to store V type values.
 */


public class RedBlackTree<K,V> {
	
	public static final String EOL = System.getProperty( "line.separator" );

	private RedBlackNode<K,V> root;
    private int size;
	private final Comparator<K> comparator;
	private final boolean allowDuplicateKeys;

    /**
     * Creates a new RedBlackTree
     * @param comparator the comparator for this tree
     * @param allowDuplicateKeys true to allow duplicate keys
     */
    public RedBlackTree(Comparator<K> comparator, boolean allowDuplicateKeys) {
		this.comparator = comparator;
		this.allowDuplicateKeys = allowDuplicateKeys;
    }

    /**
     * Creates a copy of an existing RedBlackTree
     * @param tree the existing tree to copy
     */
    public RedBlackTree(RedBlackTree<K, V> tree) {
    	this.comparator = tree.comparator;
    	this.allowDuplicateKeys = tree.allowDuplicateKeys;
    	RedBlackNode<K, V> node = tree.getFirst();
    	while(node != null) {
    		put(node.key, node.value);
    		node = node.getSuccessor();
    	}
    }
    
    @Override
	public String toString() {
		StringBuffer buffy = new StringBuffer( "RedBlackTree[size=" + size + "]\n" );
		int showSize = Math.min( 20, size() );		
		RedBlackNode<K, V> current = getFirst();
		for ( int i = 0; i < showSize; i++ ) {
			buffy.append( "\t[" ).append( i ).append( "]=(" ).append( current.key ).append( 
			    "," ).append( current.value ).append( ")" ).append( EOL );
			current = current.getSuccessor();
		}
		return buffy.toString();
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

	    RedBlackNode<K,V> node = root;
        while(node != null) {
        	int comp = comparator.compare(key, node.key);
            if (comp == 0 ){
                return true;
            }
            if (comp < 0) {
                node = node.left;
            }
            else {
                node = node.right;
            }
        }
        return false;
    }

    /**
     * Returns the first entry in this set.
     */
    public RedBlackNode<K,V> getFirst() {
        if (root == null) {
            return null;
        }
        RedBlackNode<K,V> node = root;

        while(node.left != null) {
            node = node.left;
        }
        return node;
    }

    /**
     * Returns the last entry in this set.
     */
    public RedBlackNode<K,V> getLast() {
        if (root == null) {
            return null;
        }
        RedBlackNode<K,V> node = root;

        while(node.right != null) {
            node = node.right;
        }
        return node;

    }

    /**
     * Finds the node with the lowest key that is &gt;= to the given key.  Returns null if all nodes
     * in the tree have keys less than the given key.
     * @param key the key to search for.
     * @return the node with the lowest key that is &gt;= to the given key or null if no such key exists.
     */
    public RedBlackNode<K,V> lowerBound(K key) {
        RedBlackNode<K,V> bestNode = null;

        RedBlackNode<K,V> node = root;
        while (node != null) {
        	int result = comparator.compare(key, node.key);
            if (result <= 0) {
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
     * Finds the node with the lowest key that is &gt; the given key.  Returns null if all nodes
     * in the tree have keys less than or equal to the given key.
     * @param key the key to search for.
     * @return the node with the lowest key that is &gt; to the given key or null if no such key exists.
     */
    public RedBlackNode<K,V> upperBound(K key){
        RedBlackNode<K,V> bestNode = null;

        RedBlackNode<K,V> node = root;
        while (node != null) {
        	int result = comparator.compare(key, node.key);
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
     * @param value the key's value.
     * @return the old value associated with the key, or null if the key was not previously in the map.
     */
    public Pair<RedBlackNode<K, V>, Boolean> put(K key, V value) {
        if (root == null) {
            size++;
            root = new RedBlackNode<K,V>(key,value,null);
            return new Pair<RedBlackNode<K, V>, Boolean>( root, Boolean.TRUE );
        }
        RedBlackNode<K,V> node = root;

        while (true) {
        	int comp = comparator.compare(key, node.key);
            if (comp == 0 && !allowDuplicateKeys) {
                node.value = value;
                return new Pair<RedBlackNode<K, V>, Boolean>( node, Boolean.FALSE );
            }
            else if (comp < 0) {
                if (node.left != null) {
                    node = node.left;
                }
                else {
                    size++;
                    RedBlackNode<K, V> newNode = new RedBlackNode<K,V>(key, value, node); 
                    node.left = newNode;
                    fixAfterInsertion(newNode);
                    return new Pair<RedBlackNode<K, V>, Boolean>( newNode, Boolean.TRUE );
                }
            }
            else {
                if (node.right != null) {
                    node = node.right;
                }
                else {
                    size++;
                    RedBlackNode<K, V> newNode = new RedBlackNode<K,V>(key, value, node); 
                    node.right = newNode;
                    fixAfterInsertion(newNode);
                    return new Pair<RedBlackNode<K, V>, Boolean>( newNode, Boolean.TRUE );
                }
            }
        }
    }
    public RedBlackNode<K,V> findFirstNode(K key) {
        RedBlackNode<K,V> node = root;
        RedBlackNode<K,V> bestNode = null;
        while(node != null) {
        	int comp = comparator.compare(key, node.key);
            if (comp == 0) {
            	bestNode = node;
            }
            if (comp <= 0) {
                node = node.left;
            }
            else {
                node = node.right;
            }
        }
    	return bestNode;
    }
    public RedBlackNode<K,V> findLastNode(K key) {
        RedBlackNode<K,V> node = root;
        RedBlackNode<K,V> bestNode = null;
        while(node != null) {
        	int comp = comparator.compare(key, node.key);
            if (comp == 0) {
            	bestNode = node;
            }
            if (comp < 0) {
                node = node.left;
            }
            else {
                node = node.right;
            }
        }
    	return bestNode;
    }    
    
    /**
     * Removes the given key (first if duplicates are allowed) from the set.
     * @param key the key to remove from the set.
     * @return the value associated with the key removed or null if the key not found.
     */
    public V remove(K key) {
    	
        RedBlackNode<K,V> node = findFirstNode(key);
        if (node == null) {
            return null;
        }
        V value = node.value;
        deleteEntry(node);
        return value;
    }


    /**
     * Removes all entrys from the set.
     */
    public void removeAll() {
	    size = 0;
	    root = null;
    }

    /**
     *  Test if the set is empty.
     *@return true if the set is empty.
     */
    public boolean isEmpty() {
        return size == 0;
    }


    /**
     * Balancing operations.
     *
     * Implementations of rebalancings during insertion and deletion are
     * slightly different than the CLR version.  Rather than using dummy
     * nilnodes, we use a set of accessors that deal properly with null.  They
     * are used to avoid messiness surrounding nullness checks in the main
     * algorithms.
     */

    /**
     * Returns the color of the given node.
     */
    private static <K,V> RedBlackNode.NodeColor colorOf(RedBlackNode<K,V> p) {
	    return (p == null ? BLACK : p.color);
    }

    /**
     * Returns the parent of the given node.
     */
    private static <K,V> RedBlackNode<K,V> parentOf(RedBlackNode<K,V> p) {
	    return (p == null ? null: p.parent);
    }

    /**
     *  Sets the color of the given node to the given color.
     */
    private static <K,V> void setColor(RedBlackNode<K,V> p, RedBlackNode.NodeColor c) {
	    if (p != null)  p.color = c;
    }

    /**
     * Returns the left child of the given node.
     */
    private static <K,V> RedBlackNode<K,V> leftOf(RedBlackNode<K,V> p) {
	    return (p == null)? null: p.left;
    }

    /**
     *  Returns the right child of the given node.
     */
    private static <K,V> RedBlackNode<K,V> rightOf(RedBlackNode<K,V> p) {
	    return (p == null)? null: p.right;
    }

    /** From CLR **/
    private void rotateLeft(RedBlackNode<K,V> p) {
	    RedBlackNode<K,V> r = p.right;
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
    private void rotateRight(RedBlackNode<K,V> p) {
	    RedBlackNode<K,V> l = p.left;
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
    private void fixAfterInsertion(RedBlackNode<K,V> x) {
	    x.color = RED;

	    while (x != null && x != root && x.parent.color == RED) {
	        if (parentOf(x) == leftOf(parentOf(parentOf(x)))) {
		        RedBlackNode<K,V> y = rightOf(parentOf(parentOf(x)));
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
		        RedBlackNode<K,V> y = leftOf(parentOf(parentOf(x)));
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
	    	        setColor(parentOf(x),  BLACK);
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
    public void deleteEntry(RedBlackNode<K,V> p) {
        size--;

    	// If strictly internal, first swap position with successor.
	    if (p.left != null && p.right != null) {
            RedBlackNode<K,V> node = p.getSuccessor();
    	    swapPosition(node, p);
	    }

    	// Start fixup at replacement node, if it exists.
	    RedBlackNode<K,V> replacement = (p.left != null ? p.left : p.right);

    	if (replacement != null) {
	        // Link replacement to parent
	        replacement.parent = p.parent;
            if (p.parent == null) {
	    	    root = replacement;
            }
            else if (p.isLeftChild()) {
	    	    p.parent.left  = replacement;
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
    }

    /** From CLR **/
    private void fixAfterDeletion(RedBlackNode<K,V> x) {
    	while (x != root && colorOf(x) == BLACK) {
	        if (x == leftOf(parentOf(x))) {
		        RedBlackNode<K,V> sib = rightOf(parentOf(x));

		        if (colorOf(sib) == RED) {
		            setColor(sib, BLACK);
		            setColor(parentOf(x), RED);
		            rotateLeft(parentOf(x));
		            sib = rightOf(parentOf(x));
		        }

		        if (colorOf(leftOf(sib))  == BLACK &&
		            colorOf(rightOf(sib)) == BLACK) {
		            setColor(sib,  RED);
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
		        RedBlackNode<K,V> sib = leftOf(parentOf(x));

		        if (colorOf(sib) == RED) {
		            setColor(sib, BLACK);
		            setColor(parentOf(x), RED);
		            rotateRight(parentOf(x));
		            sib = leftOf(parentOf(x));
		        }

		        if (colorOf(rightOf(sib)) == BLACK &&
		            colorOf(leftOf(sib)) == BLACK) {
		            setColor(sib,  RED);
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
    private void swapPosition(RedBlackNode<K,V> x, RedBlackNode<K,V> y) {
	    // Save initial values.
	    RedBlackNode<K,V> px = x.parent, lx = x.left, rx = x.right;
	    RedBlackNode<K,V> py = y.parent, ly = y.left, ry = y.right;
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
	    RedBlackNode.NodeColor c = x.color;
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

}
