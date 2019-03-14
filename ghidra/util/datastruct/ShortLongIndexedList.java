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
 * Manages an array of lists of longs. It provides methods for
 * adding, deleting, and retrieving long values for specific lists.
 */
public class ShortLongIndexedList implements Serializable {

    private final static short DEFAULT_CAPACITY=16;

	private long []values;           // array to store the values
    private ShortListIndexer indexer; // keeps track of lists of indexes into values array.
    private int capacity;           // current size of values array.

	/**
	 * Constructor
	 * @param numLists initial number of lists.
	 */
    public ShortLongIndexedList (short numLists) {

        indexer = new ShortListIndexer(numLists, DEFAULT_CAPACITY);
        capacity = indexer.getCapacity();
        values = new long[capacity];
    }

	/**
	 * Add a value to the front of the list indexed by listID.
     * @param listID specifies which list the value is to be added.
     * @param value  the value to be added to the list.
     * @exception IndexOutOfBoundsException thrown if the listID
     * is not in the range [0, numLists].
	 */
    public void add(short listID, long value) {

        int index = indexer.add(listID);
        if (index >= capacity) {
            grow(indexer.getCapacity());
        }
        values[index] = value;

    }

	/**
	 * Add a value to the back of the list indexed by listID.
     * @param listID specifies which list the value is to be appended.
     * @param value the value to be added to the linked list.
     * @exception IndexOutOfBoundsException thrown if the listID
     * is not in the range [0, numLists].
	 */
    public void append(short listID, long value) {

        int index = indexer.append(listID);
        if (index >= capacity) {
            grow(indexer.getCapacity());
        }
        values[index] = value;

    }


	/**
	 * Remove the value from the list indexed by listID.
	 * @param listID the id of the list from which to remove the value.
	 * @param value the value to be removed from the specified list.
     * @exception IndexOutOfBoundsException thrown if the listID
     * is not in the range [0, numLists].
	 */
    public boolean remove(short listID, long value) {

        // find index that contains value
        short index = findIndex(listID, value);
        if (index < 0) {
            return false;
        }
        indexer.remove(listID, index);
        return true;
    }

	/**
	 * Remove all values from a specified list.
	 * @param listID the id of the list to be cleared.
     * @exception IndexOutOfBoundsException thrown if the listID
     * is not in the range [0, numLists].
	 */
	public void removeAll(short listID) {

        indexer.removeAll(listID);
	}

	/**
	 * Returns true if the value exists in the specified list.
	 * @param listID the id of the list to be tested for the given value.
	 * @param value the value to search for in the specified list.
     * @exception IndexOutOfBoundsException thrown if the listID
     * is not in the range [0, numLists].
	 */
    public boolean contains(short listID, long value) {
        int index = findIndex(listID, value);
        if (index == -1) {
            return false;
        }
        return true;
    }

	/**
	 * Get the number of values in the specified list.
	 * @param listID the id of the list for which to get the count.
     * @exception IndexOutOfBoundsException thrown if the listID
     * is not in the range [0, numLists].
	 */
    public int getCount(short listID) {
        return indexer.getListSize(listID);
    }

	/**
	 * Get values stored in the specified list.
	 * @param listID the id of the list from which to get the values.
     * @exception IndexOutOfBoundsException thrown if the listID
     * is not in the range [0, numLists].
	 */
    public long[] get(short listID) {

        int count = indexer.getListSize(listID);

        long []lvalues = new long[count];

        short p = indexer.first(listID);

        for(int i=0;i<count;i++) {
            lvalues[i] = values[p];
            p = indexer.next(p);
        }

        return lvalues;
    }

    /**
     * Returns the number of lists.
     */
    public short getNumLists() {
        return indexer.getNumLists();
    }

	/**
	 * Increase the number of lists.
	 * @param numLists the new number of lists.
	 */
    public void growNumLists(short numLists) {
        indexer.growNumLists(numLists);
    }


    /**
     * Removes all values from all lists.
     */
    public void clear() {
        indexer.clear();
    }

	/**
	 * Increase the capacity for the linked list of values.
	 */
    private void grow(int newCapacity) {

        capacity = newCapacity;
        long[] tempValues = new long[newCapacity];

        System.arraycopy(values, 0, tempValues, 0, values.length);

        values = tempValues;
    }

	/**
	 * Find the index of the value in the list specified by listID.
	 */
    private short findIndex(short listID, long value) {

        short p = indexer.first(listID);

        while (p != -1) {
            if (values[p] == value) {
                return p;
            }
            p = indexer.next(p);
        }
        return -1;
    }
}
