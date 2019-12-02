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

import ghidra.util.ObjectStorage;
import ghidra.util.Saveable;

/**
 *
 * An ArrayList type object for ints.
 */
public class IntArrayList implements Serializable, Saveable {
    private final static long serialVersionUID = 1;

    public static final int MIN_SIZE = 4;
    int [] ints;
    int size = 0;

    private Class<?>[] classes = new Class<?>[] { Integer[].class };

    /** Creates new intArrayList */
    public IntArrayList() {
        ints = new int[MIN_SIZE];
    }

	/**
	 * Creates a new intArrayList using the values in the given array
	 * @param arr array of ints to initialize to.
	 */
    public IntArrayList(int [] arr) {
    	ints = arr;
    	size = arr.length;
    }
    
	/**
	 * Adds a new int value at the end of the list.
	 * @param value the int value to add.
	 */
	public void add(int value) {
		add(size, value);
	}

    /**
     * Puts the given int value in the int array at
     * the given index
     * 
     * @param index Index into the array.
     * @param value value to store
     * 
     * @throws IndexOutOfBoundsException
     * 			if the index is negative OR index &gt; size
     */
    public void add(int index, int value) {
    	if (index < 0 || index > size) {
    		throw new IndexOutOfBoundsException();
    	}
        if (size == ints.length) {
            growArray();
        }
        System.arraycopy(ints, index, ints, index+1, size-index);
        ints[index] = value;
		size++;
    }

    /**
     * Removes the value at the given index decreasing the array list size by 1.
     * @param index the index to remove.
     * @throws IndexOutOfBoundsException if the index is negative
     */
    public void removeValueAt(int index) {
    	if (index < 0 || index >= size) {
    		throw new IndexOutOfBoundsException();
    	}
        System.arraycopy(ints, index+1, ints, index, size-index-1);
		size--;
		if (size < ints.length / 4) {
			shrinkArray();
		}
    }

    /**
     * Removes the first occurrence of the given
     * value.
     * @param value the value to be removed.
     */
    public void removeValue(int value) {
    	for (int i = 0 ; i < size ; ++i) {
    		if (ints[i] == value) {
    			removeValueAt(i);
    			return;
    		}
    	}
    }

    /** Returns the int at the given index
     * @param index index into the array
     * @return The int value at the given index. A 0 will
     * be returned for any index not initialized to
     * another value.
     * @throws IndexOutOfBoundsException if the index is negative or greater than the list size.
     */
    public int get(int index) {
    	if (index < 0 || index >= size) {
    		throw new IndexOutOfBoundsException();
    	}
        return ints[index];
    }

	/**
	 * Sets the array value at index to value.
	 * @param index the index to set.
	 * @param value the value to store.
	 */
	public void set(int index, int value) {
    	if (index < 0 || index >= size) {
    		throw new IndexOutOfBoundsException();
    	}
        ints[index] = value;
	}

	/**
	 * Clears the entire array of data.
	 */
	public void clear() {
		size = 0;
		ints = new int[MIN_SIZE];
	}

	/**
	 * Returns the size of this virtual array.
	 * @return int the size of this virtual array.
	 */
	public int size() {
		return size;
	}

	/**
	 * Converts to a primitive array.
	 * @return int[] int array for results.
	 */
	public int [] toArray() {
		int [] tmparr = new int[size];
		System.arraycopy(ints,0,tmparr,0,size);
		return tmparr;
	}

    /**
     * Doubles the size of the array.
     * @param size The new capacity of the array.
     */
    private void growArray() {
        int [] newints = new int[ints.length*2];
        System.arraycopy(ints,0,newints,0,ints.length);
        ints = newints;
    }

    private void shrinkArray() {
    	int newsize = ints.length/2;
    	if (newsize < MIN_SIZE) {
    		return;
    	}
        int [] newints = new int[newsize];
        System.arraycopy(ints,0,newints,0,size);
        ints = newints;
    }


	/**
	 * @see Saveable#restore(ObjectStorage)
	 */
	@Override
	public void restore(ObjectStorage objStorage) {
		ints = objStorage.getInts();
		size = ints.length;
	}

	/**
	 * @see Saveable#save(ObjectStorage)
	 */
	@Override
	public void save(ObjectStorage objStorage) {
		objStorage.putInts(toArray());
	}
	
	@Override
	public Class<?>[] getObjectStorageFields() {
        return classes;
	}
	
	/**
	 * @see ghidra.util.Saveable#getSchemaVersion()
	 */
	@Override
	public int getSchemaVersion() {
		return 0;
	}

	/**
	 * @see ghidra.util.Saveable#isUpgradeable(int)
	 */
	@Override
	public boolean isUpgradeable(int oldSchemaVersion) {
		return false;
	}

	/**
	 * @see ghidra.util.Saveable#upgrade(ghidra.util.ObjectStorage, int, ghidra.util.ObjectStorage)
	 */
	@Override
	public boolean upgrade(ObjectStorage oldObjStorage, int oldSchemaVersion, ObjectStorage currentObjStorage) {
		return false;
	}

	@Override
	public boolean isPrivate() {
		return false;
	}
}
