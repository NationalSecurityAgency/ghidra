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
import java.util.Arrays;

/**
 * Class to manage multiple linked lists of short indexes. Users can add indexes
 * to a list, remove indexes from a list, remove all indexes from a list, and
 * retrieve all indexes within a given list.
 *
 */
public class ShortListIndexer implements Serializable {

	private static final short END_OF_LIST = -1;

    private short []heads;   // array containing indexes that are the head of a list.
    private short []links;   // array of links to other entries
    private short freePtr;   // this is the pointer to the next free entry
    private short size;      // the current number of items in all the lists.
    private short capacity;  // the current size of the array used to store values and links;
    private short numLists;  // the current number of lists that are being managed.


    /**
     * The constructor
     * @param numLists - The initial number of lists to be managed.
     * @param capacity - The current size of the pool of possible indexes.  All indexes
     *  begin on the free list.
     */
    public ShortListIndexer(short numLists, short capacity) {

    	this.capacity = capacity;
        this.numLists = numLists;
        links = new short[capacity];
        heads = new short[numLists];
        clear();

    }

    /**
     * Allocates a new index resource and adds it to the front of the linked list
     * indexed by listID.
     * @param listID the id of the list to add to.
     * @exception IndexOutOfBoundsException thrown if the listID is not in the
     * the range [0, numLists).
     */
	public short add(short listID) {
        if ((listID < 0) || (listID >= numLists)) {
            throw new IndexOutOfBoundsException();
        }

		short index=allocate();
        if (index >= 0) {
            links[index] = heads[listID];
		    heads[listID] = index;
        }
		return index;
	}

    /**
     * Allocates a new index resource and adds it to the end of the linked list
     * indexed by listID.
     * @param listID the id of the list to add to.
     * @exception IndexOutOfBoundsException thrown if the listID is not in the
     * the range [0, numLists).
     */
    public short append(short listID) {
        if ((listID < 0) || (listID >= numLists)) {
            throw new IndexOutOfBoundsException();
        }

        short index = allocate();
        if (index >= 0) {
            if (heads[listID] == END_OF_LIST) {
                heads[listID] = index;
            }
            else {
                short p = heads[listID];
                while(links[p] != END_OF_LIST) {
                    p = links[p];
                }
                links[p] = index;
            }
        }
        return index;
    }

   /**
     * Remove the index resource from the linked list indexed by listID.
     * @param listID the id of the list from which to removed the value at index.
     * @param index the index of the value to be removed from the specified list.
     * @exception IndexOutOfBoundsException thrown if the listID is not in the
     * the range [0, numLists).
     */
    public void remove(short listID, short index) {
        if ((listID < 0) || (listID >= numLists)) {
            throw new IndexOutOfBoundsException("The listID is out of bounds");
        }
        if ((index < 0) || (index >= capacity)) {
            throw new IndexOutOfBoundsException();
        }

		short head = heads[listID];

        if (head == END_OF_LIST) {
            return;
        }

        // the special case that the index to be removed is the first one in
        // the list.
        if (head == index) {

            short temp = links[head];
            free(head);
			heads[listID] =temp;
            return;
        }

        short ptr = head;
        // search for the index in the list.  If the end of the list is
        // reached, then the index is not in the list and we don't care.
        while (links[ptr] != END_OF_LIST) {
            if (links[ptr] == index) {
                // found the index to be deleted, remove it from the list by
                // fixing the preivous index's link to skip the removed index.
                links[ptr] = links[index];
                free(index);
				break;
			}
            ptr = links[ptr];
        }

        return;
	}

    /**
     * Removes all indexes from the specified list.
     * @param listID the list to be emptied.
     */
    public void removeAll(short listID) {
        short head = heads[listID];
        heads[listID] = END_OF_LIST;

        // cycle through the list and free all the indexes.
        while (head != END_OF_LIST) {
            short temp = head;
            head = links[head];
            free(temp);
        }
    }


    /**
     * Computes the next size that should be used to grow the index capacity.
     */
    public short getNewCapacity() {
     	short newCapacity;
        if (capacity == Short.MAX_VALUE) {
            return -1;
        }
        else if (capacity < Short.MAX_VALUE/2) {

            newCapacity = (short)(capacity*2);
        }
        else{
            newCapacity = Short.MAX_VALUE;
        }
        return newCapacity;
    }

    /**
     * Returns the current number of used index resources.
     */
    public short getSize() {
        return size;
    }

    /**
     * Returns the current index capacity.
     */
    public short getCapacity() {
        return capacity;
    }

    /**
     * Returns the number of linked list being managed.
     */
    public short getNumLists() {
        return numLists;
    }

    /**
     * Returns the next index resource that follows the given index in a linked list.
     * The index should be an index that is in some linked list.  Otherwise, the
     * results are undefined( probably give you the next index on the free list )
     * @param index to search after to find the next index.
     * @exception IndexOutOfBoundsException thrown if the index is not in the
     * the range [0, capacity].
     */
    public final short next(short index) {
         return links[index];
    }

    /**
     * Returns the first index resource on the linked list indexed by listID.
     * @exception IndexOutOfBoundsException thrown if the listID is not in the
     * the range [0, numLists].
     */
	public final short first(short listID){
		return heads[listID];
	}

    /**
     * Increases the index resource pool.
     * @param newCapacity the new number of resource indexes to manage.  if this number
     * is smaller than the current number of resource indexes, then nothing changes.
     */
    public void growCapacity(short newCapacity) {

        if (newCapacity <= capacity) {
            return;
        }
        short []temp = new short[newCapacity];
        System.arraycopy(links, 0, temp, 0, capacity);
        for (int i=capacity; i<newCapacity; i++) {
            temp[i] = (short)(i+1);
        }
        temp[newCapacity-1] = END_OF_LIST;
        freePtr=capacity;
        capacity = newCapacity;
        links = temp;
	}

    /**
     * Increases the number of managed linked lists.
     * @param newListSize the new number of linked lists.  If this number is
     * smaller than the current number of linked lists, then nothing changes.
     */
    public void growNumLists(short newListSize) {
        if (newListSize <= numLists) {
            return;
        }
        short[] temp = heads;
        heads = new short[newListSize];
        System.arraycopy(temp, 0, heads, 0, temp.length);
        Arrays.fill(heads,temp.length,heads.length, END_OF_LIST);
        numLists = newListSize;
    }

    /**
     *  Removes all indexes from all lists.
     */
	public void clear() {

		for (int i=0; i<capacity; i++) {
		  links[i] = (short)(i+1);
		}
		links[capacity-1] = END_OF_LIST;
		freePtr = 0;
		Arrays.fill(heads, END_OF_LIST);
        size = 0;
	}

    /**
     * Returns the number of indexes in the specified list.
     * @exception IndexOutOfBoundsException thrown if the listID is not in the
     * the range [0, numLists).
     */
    public int getListSize(short listID) {

        if ((listID < 0) || (listID >= numLists)) {
            throw new IndexOutOfBoundsException("The listID is out of bounds");
        }

        int count = 0;
        int p = heads[listID];
        while(p != END_OF_LIST) {
            count++;
            p = links[p];
        }
        return count;
    }
	/**
     *  Returns a free index resource from the free list.  If there are no
     * free index values, then this method will attempt to grow the index
     * resource pool.
     */
    private short allocate(){

    	if (freePtr == END_OF_LIST) {
            growCapacity(getNewCapacity());
            if (freePtr == END_OF_LIST) {
                return END_OF_LIST;
            }
        }
        short p = freePtr;
        freePtr = links[freePtr];
        links[p] = END_OF_LIST;
        ++size;
        return p;
    }

    /**
     * Returns the given index resource to the free list.
     */
    private void free(short p) {
        size--;
        links[p] = freePtr;
        freePtr = p;
    }


}

