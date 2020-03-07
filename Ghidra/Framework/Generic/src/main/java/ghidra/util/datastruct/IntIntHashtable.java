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
import ghidra.util.exception.NoValueException;

/**
 *     Class that implements a hashtable with int keys and int values.
 *     Because this class uses array of primitives
 *     to store the information, it serializes very fast.  This implementation uses
 *     separate chaining to resolve collisions.
 *
 */
public class IntIntHashtable {

    private IntKeyIndexer indexer;  // allocates and manages index values for keys.
    private int[] values;           // array for holding the values.
    private int capacity;           // current capacity

    /**
     * Default constructor creates a table with an initial default capacity.
     */
    public IntIntHashtable() {
        this(3);
    }

    /**
     * Constructor creates a table with an initial given capacity.  The capacity
     * will be adjusted to the next highest prime in the PRIMES table.
     * @param capacity the initial capacity.
     */
    public IntIntHashtable(int capacity) {

        capacity = Prime.nextPrime(capacity);
        this.capacity = capacity;
        indexer = new IntKeyIndexer(capacity);
        values = new int[capacity];
    }


    /**
     * Adds a key/value pair to the hashtable. If the key is already in the table,
     * the old value is replaced with the new value.  If the hashtable is already
     * full, the hashtable will attempt to approximately double in size
     * (it will use a prime number), and all the current entries will
     * be rehashed.
     * @param key the key for the new entry.
     * @param value the value for the new entry.
     * @exception ArrayIndexOutOfBoundsException thrown if the maximum capacity is
     * reached.
     */
    public void put(int key, int value) {

        int index = indexer.put(key);

        // make sure there is room
        if (index >= capacity) {
            grow();
        }

        values[index] = value;
    }

    /**
     * Returns the value for the given key.
     * @param key the key for which to retrieve a value.
     * @exception NoValueException thrown if there is no value for the given key.
     */
    public int get(int key) throws NoValueException {
        int index = indexer.get(key);
        if (index < 0) {
            throw NoValueException.noValueException;
        }
        return values[index];
    }

    /**
     * Removes a key/value from the hashtable
     * @param key the key to remove from the hashtable.
     * @return true if key is found and removed, false otherwise.
     * @throws NoValueException 
     * @exception NoValueException thrown if there is no value for the given key.
     */
    public int remove(int key) throws NoValueException {
    	int index = indexer.remove(key);
    	if (index < 0) {
            throw NoValueException.noValueException;
        }
    	return values[index];
    }

    /**
     * Remove all entries from the hashtable.
     */
    public void removeAll() {
        indexer.clear();
    }

	/**
	 * Return true if the given key is in the hashtable.
	 * @param key the key to be tested for existence in the hashtable.
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
     * resizes the hashtable to allow more entries.
     */
    private void grow() {

        capacity = indexer.getCapacity();

        int[] oldValues = values;

        values = new int[capacity];

        System.arraycopy(oldValues,0,values,0,oldValues.length);
    }


}
