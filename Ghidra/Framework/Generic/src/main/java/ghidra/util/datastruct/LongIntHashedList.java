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
 * Class that maps a long key to a list of ints.
 */

public class LongIntHashedList implements Serializable {

    private LongKeyIndexer indexer;       // maps keys to index values
    private IntIntIndexedList values;     // keeps a linked list of int values.
    private int capacity;

    private final static int DEFAULT_CAPACITY=16;

    /**
     * Constructs a new LongIntHashedList with a default capacity.
     */
    public LongIntHashedList() {
        this(DEFAULT_CAPACITY);
    }

    /**
     * Constructs a new LongIntHashedList with a given capacity.
     * @param capacity the initial capacity
     */
    public LongIntHashedList(int capacity) {
        this.capacity = capacity;
        indexer = new LongKeyIndexer(capacity);
        values = new IntIntIndexedList(capacity);
    }

    /**
     * Adds the given value to list associated with the given key.
     * @param key the key to be associated with the given value.
     * @param value the value to associate with the given key.
     */
    public void add(long key,int value) {
        int index = indexer.put(key);

        // if the indexer grew (because its key array became full),
        // then we need to grow also.
        if (index >= capacity) {
            capacity = indexer.getCapacity();
            values.growNumLists(capacity);
        }

        // add the value to the list.
        values.add(index, value);
    }

    /**
     * Appends the given value to list associated with the given key.
     * @param key the key to be associated with the given value.
     * @param value the value to associate with the given key.
     */
    public void append(long key,int value) {
        int index = indexer.put(key);
        // if the indexer grew (because its key array became full),
        // then we need to grow also.
        if (index >= capacity) {
            capacity = indexer.getCapacity();
            values.growNumLists(capacity);
        }

        // add the value to the list.
        values.append(index, value);
    }

    /**
     * Tests if the given value is in the list of values associated with
     * the given key.
     * @param key key whose list is to be searched for the given value.
     * @param value the value to be searched for in the list associated with the
     * key.
     */
    public boolean contains(long key, int value) {
        int index = indexer.get(key);

        if (index < 0) {
            // key not found!
            return false;
        }
        return values.contains(index, value);
    }

    /**
     * Returns the array of int values associated with the given key.
     * @param key the key for which to return a set of associated values.
     */
    public int[] get(long key) {
		int index = indexer.get(key);

        if (index < 0) {
            // key not found!
            return null;
        }

        return values.get(index);
    }

    /**
     * Removes the int value from the list associated with the given key.
     * @param key the key associated with a list of valus from which to remove the 
     * given value.
     * @param value the value to be removed from the list of values associated with
     * the given key.
     */
    public boolean remove(long key,int value) {
		int index = indexer.get(key);

        if (index < 0) {
            // key not found
            return false;
        }

        boolean ret = values.remove(index, value);

        // if the list becomes empty, no need to reserve the
        // index for that key.
        if (values.getCount(index) == 0) {
            indexer.remove(key);
        }
        return ret;
    }

    /**
     * Removes all the values in the list associated with the given key.
     * @param key the key whose list of values should be cleared.
     */
    public void removeAll(long key) {
        int index = indexer.get(key);

        if (index < 0) {
            // key not found, nothing to remove
            return;
        }
        values.removeAll(index);
        indexer.remove(key);
    }

    /**
     * Removes all values from all keys.
     */
    public void clear() {
        indexer.clear();
        values.clear();
    }

}
