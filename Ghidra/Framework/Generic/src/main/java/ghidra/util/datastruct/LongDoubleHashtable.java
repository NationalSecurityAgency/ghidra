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

import java.io.Serializable;

/**
 *
 *     Class that implements a hashtable with long keys and double values.
 *     Because this class uses array of primitives
 *     to store the information, it serializes very fast.  This implementation uses
 *     separate chaining to resolve collisions.
 *
 *     My local change of LongShortHashtable (SCP 4/13/00)
 */
public class LongDoubleHashtable implements Serializable {

    private LongKeyIndexer indexer; // allocates and manages index values for keys.
    private double[] values;           // array for holding the values.
    private int capacity;           // current capacity


    /**
     * Default constructor creates a table with an initial default capacity.
     */
    public LongDoubleHashtable() {
        this((short)3);
    }

    /**
     * Constructor creates a table with an initial given capacity.  The capacity
     * will be adjusted to the next highest prime in the PRIMES table.
     * @param capacity the initial capacity.
     */
    public LongDoubleHashtable(int capacity) {

        capacity = Prime.nextPrime(capacity);
        this.capacity = capacity;
        indexer = new LongKeyIndexer(capacity);
        values = new double[capacity];
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
    public void put(long key, double value) {

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
     * @exception NoValueException thrown if there is no value for the given key.
     */
    public double get(long key) throws NoValueException {
        int index = indexer.get(key);
        if (index < 0) {
            throw new NoValueException();
        }
        return values[index];
    }

    /**
     * Removes a key from the hashtable
     * @param key key to be removed from the hashtable.
     * @return true if key is found and removed, false otherwise.
     */
    public boolean remove(long key) {
        if (indexer.remove(key) < 0) {
            return false;
        }
        return true;
    }

    /**
     * Remove all entries from the hashtable.
     */
    public void removeAll() {
        indexer.clear();
    }

	/**
	 * Return true if the given key is in the hashtable.
	 * @param key the key whose presence in this map is to be tested.
	 */
	public boolean contains(long key) {
		return indexer.get(key) >=0;
	}

    /**
     * Return the number of key/value pairs stored in the hashtable.
     */
    public int size() {
        return indexer.getSize();
    }

    /**
     * Returns an array containing all the long keys.
     */
    public long[] getKeys() {
        return indexer.getKeys();
    }

    /**
     * Resizes the hashtable to allow more entries.
     */
    private void grow() {

        capacity = indexer.getCapacity();

        double[] oldValues = values;

        values = new double[capacity];

        System.arraycopy(oldValues,0,values,0,oldValues.length);
    }

}
