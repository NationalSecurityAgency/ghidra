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
import java.io.Serializable;

/**
 * A RedBlack Tree implementation of a long key set.
 */

public class RedBlackLongKeySet implements Serializable {
	/** the number of bytes in a RedBlackLongKeySet node */
    public static final int NODESIZE = 15;

    private transient RBNode root;
    private transient int size;
    private static final byte RED = (byte)0;
    private static final byte BLACK = (byte)1;

    // RedBlack Tree node
    static class RBNode {
        long key;
        byte color;
        RBNode parent;
        RBNode left;
        RBNode right;
        RBNode(long key, RBNode parent) {
            this.key = key;
            this.parent = parent;
            this.color = BLACK;
        }
    }


    /**
     * Creates a new RedBlackLongKeySet that can store keys between 0 and n.
     */
    public RedBlackLongKeySet() {
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
     * @exception IndexOutOfBoundsException thrown if the given key is not
     * in the range [0, maxKey].
     */
    public boolean containsKey(long key) {

	    RBNode node = root;
        while(node != null) {
            if (key == node.key) {
                return true;
            }
            if (key < node.key) {
                node = node.left;
            }
            else {
                node = node.right;
            }
        }
        return false;
    }

    /**
     * Returns the first key in this set.
     */
    public long getFirst() {
        if (root == null) {
            return -1;
        }
        RBNode node = root;

        while(node.left != null) {
            node = node.left;
        }
        return node.key;
    }

    /**
     * Returns the last key in this set.
     */
    public long getLast() {
        if (root == null) {
            return -1;
        }
        RBNode node = root;

        while(node.right != null) {
            node = node.right;
        }
        return node.key;

    }


    /**
     * Returns the smallest key in the set that is greater than the given key.  Returns
     * -1 if there are no keys greater than the given key.
     * @param key the key for which to find the next key after.
     * @exception IndexOutOfBoundsException thrown if the given key is not
     * in the range [0, maxKey].
     */
    public long getNext(long key){
        if (key < 0) {
            throw new IndexOutOfBoundsException();
        }

        boolean foundValue = false;
        long bestkey = 0;

        RBNode node = root;
        while (node != null) {
            if (key >= node.key) {
                node = node.right;
            }
            else {
                foundValue = true;
                bestkey = node.key;
                node = node.left;
            }

        }
        if (foundValue) {
            return bestkey;
        }
		return -1;

    }

    /**
     * Returns the largest key in the set that is less than the given key. Returns -1 if
     * there are not keys less than the given key.
     * @param key the key for which to find the previous key.
     * @exception IndexOutOfBoundsException thrown if the given key is not
     * in the range [0, maxKey].
     */
    public long getPrevious(long key) {
        if (key < 0) {
            throw new IndexOutOfBoundsException();
        }
        boolean foundValue = false;
        long bestkey = 0;

        RBNode node = root;
        while (node != null) {
            if (key <= node.key) {
                node = node.left;
            }
            else {
                foundValue = true;
                bestkey = node.key;
                node = node.right;
            }

        }
        if (foundValue) {
            return bestkey;
        }
            return -1;

    }

    /**
     * Adds the given key to the set.
     * @param key the key to add to the set.
     * @exception IndexOutOfBoundsException thrown if the given key is not
     * in the range [0, maxKey].
     */
    public void put(long key) {
        if (key < 0) {
            throw new IndexOutOfBoundsException();
        }
        if (root == null) {
            size++;
            root = new RBNode(key,null);
        }
        RBNode node = root;

        while (true) {

            if (key == node.key) {
                return;
            }
            else if (key < node.key) {
                if (node.left != null) {
                    node = node.left;
                }
                else {
                    size++;
                    node.left = new RBNode(key, node);
                    fixAfterInsertion(node.left);
                    return;
                }
            }
            else {
                if (node.right != null) {
                    node = node.right;
                }
                else {
                    size++;
                    node.right = new RBNode(key, node);
                    fixAfterInsertion(node.right);
                    return;
                }
            }
        }
    }

    /**
     * Removes the given key from the set.
     * @param key the key to remove from the set.
     * @exception IndexOutOfBoundsException thrown if the given key is not
     * in the range [0, maxKey].
     */
    public boolean remove(long key) {
        if (key < 0) {
            throw new IndexOutOfBoundsException();
        }
        RBNode node = root;
        while(node != null) {
            if (key == node.key) {
                break;
            }
            if (key < node.key) {
                node = node.left;
            }
            else {
                node = node.right;
            }
        }

        if (node == null) {
            return false;
        }

        size--;
        deleteEntry(node);
        return true;
    }


    /**
     * Removes all keys from the set.
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
    private static byte colorOf(RBNode p) {
	    return (p == null ? BLACK : p.color);
    }

    /**
     * Returns the parent of the given node.
     */
    private static RBNode parentOf(RBNode p) {
	    return (p == null ? null: p.parent);
    }

    /**
     *  Sets the color of the given node to the given color.
     */
    private static void setColor(RBNode p, byte c) {
	    if (p != null)  p.color = c;
    }

    /**
     * Returns the left child of the given node.
     */
    private static RBNode  leftOf(RBNode p) {
	    return (p == null)? null: p.left;
    }

    /**
     *  Returns the right child of the given node.
     */
    private static RBNode  rightOf(RBNode p) {
	    return (p == null)? null: p.right;
    }

    /** From CLR **/
    private void rotateLeft(RBNode p) {
	    RBNode r = p.right;
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
    private void rotateRight(RBNode p) {
	    RBNode l = p.left;
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
    private void fixAfterInsertion(RBNode x) {
	    x.color = RED;

	    while (x != null && x != root && x.parent.color == RED) {
	        if (parentOf(x) == leftOf(parentOf(parentOf(x)))) {
		        RBNode y = rightOf(parentOf(parentOf(x)));
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
		        RBNode y = leftOf(parentOf(parentOf(x)));
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
    private void deleteEntry(RBNode p) {

    	// If strictly internal, first swap position with successor.
	    if (p.left != null && p.right != null) {

            RBNode s = null;

            RBNode node = root;
            while (node != null) {
                if (p.key >= node.key) {
                    node = node.right;
                }
                else {
                    s = node;
                    node = node.left;
                }
            }

    	    swapPosition(s, p);
	    }

    	// Start fixup at replacement node, if it exists.
	    RBNode replacement = (p.left != null ? p.left : p.right);

    	if (replacement != null) {
	        // Link replacement to parent
	        replacement.parent = p.parent;
            if (p.parent == null) {
	    	    root = replacement;
            }
            else if (p == p.parent.left) {
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
		        if (p == p.parent.left) {
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
    private void fixAfterDeletion(RBNode x) {
    	while (x != root && colorOf(x) == BLACK) {
	        if (x == leftOf(parentOf(x))) {
		        RBNode sib = rightOf(parentOf(x));

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
		        RBNode sib = leftOf(parentOf(x));

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
    private void swapPosition(RBNode x, RBNode y) {
	    // Save initial values.
	    RBNode px = x.parent, lx = x.left, rx = x.right;
	    RBNode py = y.parent, ly = y.left, ry = y.right;
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
	    byte c = x.color;
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




    /**
     * Save the state of the <code>TreeMap</code> instance to a stream (i.e.,
     * serialize it).
     *
     * @serialData The <i>size</i> of the TreeMap (the number of key-value
     *		   mappings) is emitted (int), followed by the key (Object)
     *		   and value (Object) for each key-value mapping represented
     *		   by the TreeMap. The key-value mappings are emitted in
     *		   key-order (as determined by the TreeMap's Comparator,
     *		   or by the keys' natural ordering if the TreeMap has no
     *             Comparator).
     */
    private void writeObject(java.io.ObjectOutputStream s)
        throws java.io.IOException {
	    // Write out the Comparator and any hidden stuff
    	s.defaultWriteObject();

	    // Write out size (number of Mappings)
	    s.writeInt(size);
        long key = getFirst();
        while(key >= 0) {
            s.writeLong(key);
            key = getNext(key);
        }
	}



    /**
     * Reconstitute the <code>TreeMap</code> instance from a stream (i.e.,
     * deserialize it).
     */
    private void readObject(final java.io.ObjectInputStream s)
        throws java.io.IOException, ClassNotFoundException {
	    // Read in the Comparator and any hidden stuff
	    s.defaultReadObject();

        // Read in size
        size = s.readInt();

        root = buildFromSorted(0,0,size-1,computeRedLevel(size),s);

    }


    /**
     * Recursive "helper method" that does the real work of the
     * of the previous method.  Identically named parameters have
     * identical definitions.  Additional parameters are documented below.
     * It is assumed that the comparator and size fields of the TreeMap are
     * already set prior to calling this method.  (It ignores both fields.)
     *
     * @param level the current level of tree. Initial call should be 0.
     * @param lo the first element index of this subtree. Initial should be 0.
     * @param hi the last element index of this subtree.  Initial should be
     *	      size-1.
     * @param redLevel the level at which nodes should be red.
     *        Must be equal to computeRedLevel for tree of this size.
     */
    private static RBNode buildFromSorted(int level, int lo, int hi,
                                         int redLevel,
                                         java.io.ObjectInputStream str)
        throws  java.io.IOException, ClassNotFoundException {
        /*
         * Strategy: The root is the middlemost element. To get to it, we
         * have to first recursively construct the entire left subtree,
         * so as to grab all of its elements. We can then proceed with right
         * subtree.
         *
         * The lo and hi arguments are the minimum and maximum
         * indices to pull out of the iterator or stream for current subtree.
         * They are not actually indexed, we just proceed sequentially,
         * ensuring that items are extracted in corresponding order.
         */

        if (hi < lo) return null;

        int mid = (lo + hi) / 2;

        RBNode left  = null;
        if (lo < mid) {
            left = buildFromSorted(level+1, lo, mid - 1, redLevel, str);
        }
        // extract from stream
        long key = str.readLong();


        RBNode middle =  new RBNode(key, null);

        // color nodes in non-full bottommost level red
        if (level == redLevel)
            middle.color = RED;

        if (left != null) {
            middle.left = left;
            left.parent = middle;
        }

        if (mid < hi) {
            RBNode right = buildFromSorted(level+1, mid+1, hi, redLevel, str);
            middle.right = right;
            right.parent = middle;
        }

        return middle;
    }

    /**
     * Find the level down to which to assign all nodes BLACK.  This is the
     * last `full' level of the complete binary tree produced by
     * buildTree. The remaining nodes are colored RED. (This makes a `nice'
     * set of color assignments wrt future insertions.) This level number is
     * computed by finding the number of splits needed to reach the zeroeth
     * node.  (The answer is ~lg(N), but in any case must be computed by same
     * quick O(lg(N)) loop.)
     */
    private static int computeRedLevel(int sz) {
        int level = 0;
        for (int m = sz - 1; m >= 0; m = m / 2 - 1)
            level++;
        return level;
    }
}
