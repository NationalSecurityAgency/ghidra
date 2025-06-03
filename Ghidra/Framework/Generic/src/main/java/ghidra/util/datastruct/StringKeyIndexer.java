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
import ghidra.util.exception.AssertException;

import java.io.Serializable;
import java.util.Iterator;

/**
 * This class converts arbitrary Strings into compacted int indexes suitable
 * for use as indexes into an array or table.  Whenever a new key is added,
 * the smallest unused index is allocated and associated with that key.
 * Basically hashes the keys into linked lists using the IntListIndexer class,
 * where all values in a list have
 * the same hashcode.  Does most of the work in implementing a separate chaining
 * version of a hashtable - the only thing missing is the values which are stored
 * in the individual implementations of the various hashtables.
 */

public class StringKeyIndexer implements Serializable {
    private final static long serialVersionUID = 1;

    private static final int DEFAULT_CAPACITY = 13;

    private String[] keys;                 // stores the keys to resolve hash conflicts.
    private IntListIndexer indexer;     // keeps key indexes in linked list indexed by hash
    private int capacity;               // current size of the keys array.


    /**
     * Constructs a StringKeyIndexer with a default capacity.
     */
    public StringKeyIndexer() {
        this(DEFAULT_CAPACITY);
    }

    /**
     * Constructs a StringKeyIndexer with a given initial capacity.
     * @param capacity the initial capacity.
     */
    public StringKeyIndexer(int capacity) {
        capacity = Prime.nextPrime(capacity);
        this.capacity = capacity;
        indexer = new IntListIndexer(capacity, capacity);
        keys = new String[capacity];
    }


    /**
     * Returns an index that will always be associated to the given key as long as
     * the key remains in the table. If the key already exists, then the index where
     * that key is stored is returned.  If the key is new, then a new index is allocated,
     * the key is stored at that index, and the new index is returned.
     * @param key the key to be stored.
     * @return index for key, or -1 if there was no room to put the key.
     * @exception IndexOutOfBoundsException thrown if this object is at maximum capacity.
     */
    public int put(String key) {
        // check if the key already exists.
        int index = findKey(key);

        // if not, then we need to add it
        if (index == -1) {
            // make sure there is enough room
            if (indexer.getSize() >= capacity) {
                // if not enough room, grow the key capacity.
                grow();
            }
            // now use the hashcode as the listID and get a new index
            // to put on that list.  Then store the key at the new index.
            int hashcode = (key.hashCode() & 0x7FFFFFFF) % capacity;
            index = indexer.add(hashcode);

            if (index < 0) {
                throw new IndexOutOfBoundsException("Maximum capacity reached");
            }
            keys[index] = key;
        }

        // return the index associated with the given key.
        return index;

    }

    /**
     * Returns the index for the given key, or
     * -1 if key is not in the table.
     * @param key the key for which to find an index.
     */
    public int get(String key) {
        return findKey(key);
    }

    /**
     * Removes the key from the table.
     * @param key the key to remove.
     * @return index of the key if the key was found, -1 if
     * key did not exist in the table
     */
    public int remove(String key) {
        int index = findKey(key);
        if(index == -1) {
            return -1;
        }

        int hashcode = (key.hashCode() & 0x7FFFFFFF) % capacity;
        indexer.remove(hashcode, index);
        keys[index] = null;
        return index;
    }

    /**
     * Returns the number of keys stored in the table.
     */
    public int getSize() {
        return indexer.getSize();
    }

    /**
     * Returns the current size of the key table.
     */
    public int getCapacity() {
        return capacity;
    }

    /**
     * Remove all keys.
     */
    public void clear() {
        indexer.clear();
    }

    /**
     * Returns an array containing all the keys stored in this object.
     */
    public String[] getKeys() {
        String[] keyArray = new String[getSize()];
        int pos = 0;

        int nLists = indexer.getNumLists();
        for(int i=0;i<nLists;i++) {
            int keyIndex = indexer.first(i);
            while(keyIndex >= 0) {
                keyArray[pos++] = keys[keyIndex];
                keyIndex = indexer.next(keyIndex);
            }
        }
        if (pos != getSize()) {
            throw new AssertException("Trouble in IntKeyIndexer.getKeys(), size = "+
                getSize()+"  pos= "+pos);
        }
        return keyArray;
    }

	/**
	 * Returns an iterator over all the keys.
	 * @return an iterator over all the keys.
	 */
    public Iterator<String> getKeyIterator() {
     	return new KeyIterator();
    }

    /**
     * Finds the index for a given key.
     * @param key the key 
     */
    private int findKey(String key) {
        int hashcode = (key.hashCode() & 0x7FFFFFFF) % capacity;

        int p = indexer.first(hashcode);

        while (p != -1) {
            if (keys[p].equals(key)) {
                return p;
            }
            p = indexer.next(p);
        }
        return -1;
    }


    /**
     *  Increases the size of the keys array and the indexer.
     *  This method needs to be very careful!  It is very important that the keys get
     *  mapped to the same key index even though they are stored in a different list
     *  in the indexer class (Which is indexed based on the hashcode (mod capacity) of
     *  the key.  Since this method can only be called when the indexer is full, we
     *  can assume that there are no gaps (freed indexes) in the keys array.  Therefore,
     *  if we clear everything and add them back in the same order that they were stored
     *  in the old keys array, they should be assigned the same index.  This is important
     *  since other containing classes may be storing lots of information based on this
     *  index and we don't want the indexing to change just because we had to grow.
     */

	 private void grow() {

        int newCapacity = Prime.nextPrime(indexer.getNewCapacity());
        indexer.growCapacity(newCapacity);
        indexer.growNumLists(newCapacity);
        indexer.clear();

		String[] oldKeys = keys;
        keys = new String[newCapacity];
        capacity = newCapacity;
		for(int i=0;i<oldKeys.length;i++) {
			put(oldKeys[i]);
		}
    }
    private class KeyIterator implements Iterator<String> {
        private int nLists;
        private int index;
        private int keyIndex;
        private String nextKey;

     	KeyIterator() {
        	nLists = indexer.getNumLists();
            index = 0;
            keyIndex = -1;
            findNext();
        }
     	
     	/* (non-Javadoc)
     	 * @see java.util.Iterator#hasNext()
     	 */
		@Override
		public boolean hasNext() {
        	return nextKey != null;
        }
		
		/* (non-Javadoc)
		 * @see java.util.Iterator#next()
		 */
        @Override
		public String next() {
        	if (hasNext()) {
            	String result = nextKey;
                findNext();
                return result;
            }
            return null;
        }
        
        /* (non-Javadoc)
         * @see java.util.Iterator#remove()
         */
        @Override
		public void remove() {
        	throw new UnsupportedOperationException();
        }
        
    	private void findNext() {
			while (keyIndex < 0) {
            	if (index >= nLists) {
                	nextKey = null;
                    return;
                }
            	keyIndex = indexer.first(index);
                index++;
            }
            nextKey = keys[keyIndex];
            keyIndex = indexer.next(keyIndex);
		}
    }
}
