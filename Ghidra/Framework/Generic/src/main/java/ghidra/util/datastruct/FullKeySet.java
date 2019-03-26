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
 * Implementation of the ShortKeySet interface that always contains
 * all the possible keys.  Used to save storage when sets are full.
 */

public class FullKeySet implements ShortKeySet, Serializable {
    
    private int numKeys; // keys range from 0 to numKeys-1

	/**
	 * Construct a new FullKeySet
	 * @param numKeys the number of keys in the set.
	 */
    public FullKeySet(int numKeys) {
        this.numKeys = numKeys;
    }


    /**
     * Returns the number of keys currently in the set.
     */
    public int size() {
        return numKeys;
    }

	/**
	 * 
	 * @see ghidra.util.datastruct.ShortKeySet#containsKey(short)
	 */
    public boolean containsKey(short key) {
        if ((key >= 0) &&(key < numKeys)) {
            return true;
        }
        return false;
    }

	/**
	 * 
	 * @see ghidra.util.datastruct.ShortKeySet#getFirst()
	 */
    public short getFirst() {
        return (short)0;
    }

	/**
	 * 
	 * @see ghidra.util.datastruct.ShortKeySet#getLast()
	 */
    public short getLast() {
        return (short)(numKeys-1);
    }

	/**
	 * 
	 * @see ghidra.util.datastruct.ShortKeySet#put(short)
	 */
    public void put(short key) {
        if ((key < 0) || (key >= numKeys)) {
            throw new IndexOutOfBoundsException();
        }
    }

	/**
	 * 
	 * @see ghidra.util.datastruct.ShortKeySet#remove(short)
	 */
    public boolean remove(short key) {
        if ((key < 0) || (key >= numKeys)) {
            throw new IndexOutOfBoundsException();
        }
        throw new UnsupportedOperationException();

    }

	/**
	 * 
	 * @see ghidra.util.datastruct.ShortKeySet#removeAll()
	 */
    public void removeAll() {
        throw new UnsupportedOperationException();
    }

	/**
	 * 
	 * @see ghidra.util.datastruct.ShortKeySet#getNext(short)
	 */
    public short getNext(short key) {
        if ((key < 0) || (key >= numKeys)) {
            throw new IndexOutOfBoundsException();
        }
        else if (key == numKeys-1) {
            return -1;
        }
        return (short)(key+1);
    }

	/**
	 * 
	 * @see ghidra.util.datastruct.ShortKeySet#getPrevious(short)
	 */
    public short getPrevious(short key) {
        if ((key < 0) || (key >= numKeys)) {
            throw new IndexOutOfBoundsException();
        }
        else if (key == 0) {
            return -1;
        }
        return (short)(key-1);
    }

	/**
	 * 
	 * @see ghidra.util.datastruct.ShortKeySet#isEmpty()
	 */
    public boolean isEmpty() {
        return false;
    }
}
