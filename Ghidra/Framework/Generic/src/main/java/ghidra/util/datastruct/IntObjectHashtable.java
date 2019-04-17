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

/**
 * Class that implements a hashtable with int keys and Object values.
 *
 */


public class IntObjectHashtable<T> implements Serializable {
    private final static long serialVersionUID = 1;

    private IntKeyIndexer indexer;    // allocates and manages index values for keys.
    private T[] values;               // array for holding the values.
    private int capacity;             // current capacity

    /**
     * Default constructor creates a table with an initial default capacity.
     */
    public IntObjectHashtable() {
        this(3);
    }

    /**
     * Constructor creates a table with an initial given capacity.  The capacity
     * will be adjusted to the next highest prime in the PRIMES table.
     * @param capacity the initial capacity.
     */
    @SuppressWarnings("unchecked")
	public IntObjectHashtable(int capacity) {

        capacity = Prime.nextPrime(capacity);
        this.capacity = capacity;
        indexer = new IntKeyIndexer(capacity);
        values = (T[]) new Object[capacity]; // suppressed
    }

    /**
     * Adds a key/value pair to the hashtable. If the key is already in the table,
     * the old value is replaced with the new value.  If the hashtable is already
     * full, the hashtable will attempt to approximately double in size
     * (it will use a prime number), and all the current entries will
     * be rehashed.
     * @param key the key to associate with the given value.
     * @param value the value to associate with the given key.
     * @exception ArrayIndexOutOfBoundsException thrown if the maximum capacity is
     * reached.
     */
    public void put(int key, T value) {

        int index = indexer.put(key);

        // make sure there is room
        if (index >= capacity) {
            grow();
        }

        values[index] = value;
    }

    /**
     * Returns the value for the given key.
     * @param key the key whose associated value is to be returned.
     */
    public T get(int key) {
        int index = indexer.get(key);
        if (index < 0) {
            return null;
        }
        return values[index];
    }

    /**
     * Removes a key from the hashtable
     * @param key key to be removed from the hashtable.
     * @return true if key is found and removed, false otherwise.
     */
    public boolean remove(int key) {
    	int index = indexer.remove(key);
        if (index >= 0) {
        	values[index] = null;
            return true;
        }
        return false;
    }

    /**
     * Remove all entries from the hashtable.
     */
    @SuppressWarnings("unchecked")
	public void removeAll() {
        indexer.clear();
        values = (T[]) new Object[values.length]; // suppressed
    }

	/**
	 * Return true if the given key is in the hashtable.
	 * @param key the key whose presence in this map is to be tested.
	 */
	public boolean contains(int key) {
		return indexer.get(key) >=0;
	}

    /**
     * Return the number of key/value pairs stored in the hashtable.
     */
    public int size() {
        return indexer.getSize();
    }

    /**
     * Returns an array containing all the int keys.
     */
    public int[] getKeys() {
        return indexer.getKeys();
    }

    /**
     * Resizes the hashtable to allow more entries.
     */
    @SuppressWarnings("unchecked")
	private void grow() {

        capacity = indexer.getCapacity();

        Object[] oldValues = values;

        values = (T[]) new Object[capacity]; // suppressed

        System.arraycopy(oldValues,0,values,0,oldValues.length);
    }
}
