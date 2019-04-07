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
package ghidra.util.datastruct;

import java.io.Serializable;
import java.util.Arrays;

/**
 * The BitTree class maintains a set of ordered keys between the values of
 * 0 and N.  It can quickly (O(log(n))) add keys, remove keys, find the next key
 * greater than some value , and find the prev key less than some value.  It can
 * determine if a key is in the set in O(1) time. This implementation has been
 * limited to short keys so that it can implement the ShortKeySet interface.
 */

public class BitTree implements ShortKeySet, Serializable {
    private final static long serialVersionUID = 1;

    private int size;        // The maximum number of keys in the set.  Keys range from 0 to size-1
    private int power2;      // The next power of 2 that is greater than size.
    private int[] bits;     // Array of bits used to represent a tree of binary values.  A bit at
                    // position N will have a left child at 2*N and a right child at 2*N+1.
                    // Its parent position will be at N/2.
                    // A bit is on if any bits in its subtree are on.  Leaf bits correspond
                    // directly to keys and are on if the key is in the set.

    private int numKeys;    // The current number of keys in the set.



    // masks for seting and clearing bits within an 32 bit integer.
    private static final int[] setMask = { 0x00000001,0x00000002,0x00000004,0x00000008,
                                           0x00000010,0x00000020,0x00000040,0x00000080,
                                           0x00000100,0x00000200,0x00000400,0x00000800,
                                           0x00001000,0x00002000,0x00004000,0x00008000,
                                           0x00010000,0x00020000,0x00040000,0x00080000,
                                           0x00100000,0x00200000,0x00400000,0x00800000,
                                           0x01000000,0x02000000,0x04000000,0x08000000,
                                           0x10000000,0x20000000,0x40000000,0x80000000 };

    private static final int[] clearMask={ 0xfffffffe,0xfffffffd,0xfffffffb,0xfffffff7,
                                           0xffffffef,0xffffffdf,0xffffffbf,0xffffff7f,
                                           0xfffffeff,0xfffffdff,0xfffffbff,0xfffff7ff,
                                           0xffffefff,0xffffdfff,0xffffbfff,0xffff7fff,
                                           0xfffeffff,0xfffdffff,0xfffbffff,0xfff7ffff,
                                           0xffefffff,0xffdfffff,0xffbfffff,0xff7fffff,
                                           0xfeffffff,0xfdffffff,0xfbffffff,0xf7ffffff,
                                           0xefffffff,0xdfffffff,0xbfffffff,0x7fffffff };



    /**
     * The BitTree constructor takes the maximum key value. The legal
     * keys for this set range from 0 to maxKey.
     * @param maxKey the maximum key that will ever be put into this BitTree.
     */
    public BitTree(short maxKey) {
        this(maxKey,false);
    }
    /**
     * The BitTree constructor takes the maximum key value. The legal
     * keys for this set range from 0 to maxKey.
     * @param maxKey the maximum key value.
     * @param isFull if true, then the set is initilized to contain all legal keys.
     */
    public BitTree(short maxKey, boolean isFull) {
        this.size = maxKey+1;

        // find the next power of 2 greater than or equal to n.
        power2 = 2;
        int sz = maxKey+1;
        while (sz > 1) {
            sz /= 2;
            power2 *= 2;
        }

        // The number of bits need to store the tree is 2 times the number of keys.
        // Since we are storing the bits in 32 bit integers we need N/16 integers
        // to store the bits.
        int nInts = power2/16;

        // must have at least 1
        if (nInts < 1) {
            nInts = 1;
        }


        bits = new int[nInts];

        if (isFull) {
            Arrays.fill(bits,0xffffffff);
            numKeys = this.size;
        }
    }


    /**
     * Removes all keys from the set.
     */
    public void removeAll() {
        Arrays.fill(bits,0);
        numKeys = 0;
    }

    /**
     * Returns the number of keys currently in the set.
     */
    public int size() {
        return numKeys;
    }

    /**
     *  Adds a key to the set.
     * @param key to be added.
     * @exception IndexOutOfBoundsException if the given key is not
     * in the range [0, size-1].
     */
    public void put(short key) {

        if ((key < 0) || (key >= size)) {
            throw new IndexOutOfBoundsException();
        }

        // The first "power2" number of bits are used for internal tree nodes.  The
        // leaf nodes start at index "power2".
        int nodeIndex = power2+key;

        // set the leaf bit on to indicate that the key is in the set.
        // if the bit is already on (The key is already in the set), then just return.
        if (!setBit(nodeIndex)) {
            return;
        }

        // increment the number of keys in the set.
        numKeys++;

        // go up the tree setting each parent bit to "on"
        while(nodeIndex != 1) {
            // compute parent index.
            nodeIndex /= 2;
            // if any parent bit is already on, then all its parents are already on,
            // so were done.
            if (!setBit(nodeIndex)) {
                return;
            }
        }
    }

    /**
     *  Removes the key from the set.
     * @param key The key to remove.
     * @exception IndexOutOfBoundsException if the given key is not
     * in the range [0, size-1].
     */
    public boolean remove(short key) {

        if ((key < 0) || (key >= size)) {
            throw new IndexOutOfBoundsException();
        }

        // compute the leaf node index.
        int nodeIndex = power2+key;

        // clear the leaf bit to indicate that the key is not in the set.
        // if it is already "off", then we don't have to do anything
        if (!clearBit(nodeIndex)) {
            return false;
        }

        // decrement the number of keys in the set
        numKeys--;


        // traverse up the tree, clearing any parent nodes if all its child
        // nodes are "off".
        while(nodeIndex != 1) {
            nodeIndex /= 2;
            if (!isBitSet(nodeIndex)) {
                return true;
            }
            if (isBitSet(nodeIndex*2) || isBitSet(nodeIndex*2+1)) {
                return true;
            }
            clearBit(nodeIndex);
        }
        return true;
    }

    /**
     * Determines if a given key is in the set.
     * @param key the key to check if it is in this set.
     * @return true if the key is in the set.
     */
    public boolean containsKey(short key) {
        if ((key < 0) || (key >= size)) {
            return false;
        }
        return isBitSet(power2+key);
    }

    /**
     * finds the next key that is in the set that is greater than the given key.
     * @param key from which to search forward.
     * @return the next key greater than the given key or -1 if there is no key
     * greater than the given key.
     * @exception IndexOutOfBoundsException if the given key is not
     * in the range [0, size-1].
     */
    public short getNext(short key) {
        if ((key < 0) || (key >= size)) {
            throw new IndexOutOfBoundsException();
        }

        // compute leaf node.
        int nodeIndex = key + power2;


        // while we are not at the root, search upward until we find a right
        // sibling that is "on".
        while(nodeIndex != 1) {
            // see if we are odd (i.e. the right child)
            int odd = nodeIndex % 2;

            // if we are the left child see if my sibling on the right is on.
            // if so, then the next key must be in that subtree.
            if (odd == 0) {
                if (isBitSet(nodeIndex+1)) {
                    // we found a right sibling that is "on", set nodeIndex to
                    // that node.
                    nodeIndex++;
                    break;
                }
            }
            nodeIndex = nodeIndex/2;
        }

        // if we made it all the way up to the root node, then there is no key
        // greater than, so return -1;
        if (nodeIndex == 1) {
            return (short)-1;
        }

        // now that we found a right sibling that is "on",
        // follow the leftmost trail of "on" bits to an "on" leaf bit.  This bit
        // represents the next key in the set.
        while (nodeIndex < power2) {
            nodeIndex *= 2;
            // if the left child is not on, then the right child must be "on".
            if (!isBitSet(nodeIndex))  {
                nodeIndex++;
            }
        }
        short nextKey = (short)(nodeIndex-power2);
        if (nextKey >= size) {
            nextKey = -1;
        }
        return nextKey;
    }

    /**
     * Finds the next key that is in the set that is less than the given key.
     * @param key the key to search before.
     * @return the next key less than the given key or -1 if there is no key
     * less than the given key.
     * @exception IndexOutOfBoundsException if the given key is not
     * in the range [0, size-1].
     */
    public short getPrevious(short key) {
        if ((key < 0) || (key >= size)) {
            throw new IndexOutOfBoundsException();
        }

        // find the leaf node for the given key.
        int nodeIndex = key + power2;

        // while we are not at the root, search upward until we find a left
        // sibling that is "on".
        while(nodeIndex != 1) {

            // check if we are a right node.
            int odd = nodeIndex % 2;

            // if we are the right child see if my sibling on the left is "on".
            // if so, then the previous key must be in that subtree.
            if (odd == 1) {
                if (isBitSet(nodeIndex-1)) {
                    nodeIndex--;
                    break;
                }
            }
            nodeIndex = nodeIndex/2;
        }
        // If we went all the way to the root then there is no previous key, return -1.
        if (nodeIndex == 1) {
            return (short)-1;
        }

        // follow the rightmost trail of "on" bits to an "on" leaf bit.  This bit
        // represents the previous key in the set.
        while (nodeIndex < power2) {
            nodeIndex *= 2;
            if (isBitSet(nodeIndex+1))  {
                nodeIndex++;
            }
        }
        return (short)(nodeIndex-power2);
    }

    /**
     *  Checks if the set is empty.
     * @return true if the set is empty.
     */
    public boolean isEmpty() {
        return numKeys == 0;
    }

    /**
     * Returns the first (lowest) key in the set.
     */
    public short getFirst() {
        // if the 0 key is in the set, then return it.
        if(containsKey((short)0)) {
            return (short)0;
        }
        // otherwise return the the next key after 0.
        return getNext((short)0);
    }

    /**
     * Returns the last (highest) key in the set.
     */
    public short getLast() {
        // if the highest possible key is in the set, return it.
        if(containsKey((short)(size-1))) {
            return (short)(size-1);
        }
        // otherwise return the next lowest key.
        return getPrevious((short)(size-1));
    }

    /**
     * Sets the nth bit on.
     */
    private boolean setBit(int n) {
        int intIndex = n >> 5;
        int maskIndex = n & 0x1f;
        int old = bits[intIndex];
        return ((bits[intIndex] |= setMask[maskIndex]) != old);
    }

    /**
     * Sets the nth bit to off.
     */
    private boolean clearBit(int n) {
        int intIndex = n >> 5;
        int maskIndex = n & 0x1f;
        int old = bits[intIndex];
        return ((bits[intIndex] &= clearMask[maskIndex]) != old);
    }

    /**
     * Tests if the the nth bit is on.
     */
    private boolean isBitSet(int n) {
        int intIndex = n >> 5;
        int maskIndex = n & 0x1f;
        return ((bits[intIndex] & setMask[maskIndex]) != 0);
    }

}
