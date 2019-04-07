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
 * Array of objects that grows as needed.
 */
public class ObjectArray implements Array, Serializable {
	private final static long serialVersionUID = 1;

    static final int MIN_SIZE = 4;
    Object[] objs;
    int lastNonZeroIndex = -1;

    /** Creates a new Object array of a default size. */
    public ObjectArray() {
        objs = new Object[MIN_SIZE];
    }
    
    /**
     * Creates a new object array that is initially the size specified.
     * @param size the initial size of the Object array.
     */
    public ObjectArray(int size) {
        objs = new Object[size < MIN_SIZE ? MIN_SIZE : size];
    }
    
    /** Puts the given Object in the Object array at
     * the given index
     * @param index Index into the array.
     * @param value value to store
     * @throws IndexOutOfBoundsException if the index is negative
     */    
    public void put(int index, Object value) {
        if (value == null) {
            remove(index);
            return;
        }
        
        if (index >= objs.length) {
            adjustArray(Math.max(index+1,objs.length*2));
        }
        objs[index] = value;
        if (index > lastNonZeroIndex) {
            lastNonZeroIndex = index;
        }
    }
    
    /** Sets the value at the given index to null.
     * @param index the index to set to null.
     * @throws IndexOutOfBoundsException if the index is negative
     */    
    public void remove(int index) {
		if (index >= objs.length) {
			return;
		}
        objs[index] = null;
        if (index == lastNonZeroIndex) {
            lastNonZeroIndex = findLastNonZeroIndex();
        }
        if (lastNonZeroIndex < objs.length/4) {
            adjustArray(lastNonZeroIndex * 2);
        }
        
    }
    
    /** Finds the index of the last non-null value.
     * @return The index of the last non-null value. 0 will be returned
     * if the array is empty.
     */    
    private int findLastNonZeroIndex() {
        for(int i=lastNonZeroIndex;i>=0;i--) {
            if (objs[i] != null) {
                return i;
            }
        }
        return -1;
    }
                
    
    
    /** Returns the Object at the given index
     * @param index index into the array
     * @return The Object value at the given index. A null will
     * be return for any index not initialized to
     * another value.
     * @throws IndexOutOfBoundsException if the index is negative
     */    
    public Object get(int index) {
        if (index < objs.length) {
            return objs[index];
        }
        return null;
    }
    
    /** Adjusts the size of the array.
     * @param size The new capacity of the array.
     */    
    private void adjustArray(int size) {
        if (size < MIN_SIZE) {
            size = MIN_SIZE;
        }
        Object[] newobjs = new Object[size];
        int len = Math.min(size,objs.length);
        System.arraycopy(objs,0,newobjs,0,len);
        objs = newobjs;
    }
    
    /**
     * @see ghidra.util.datastruct.Array#getLastNonEmptyIndex()
     */
    public int getLastNonEmptyIndex() {
        return lastNonZeroIndex;
    }
    
    /**
     * @see ghidra.util.datastruct.Array#copyDataTo(int, ghidra.util.datastruct.DataTable, int, int)
     */
    public void copyDataTo(int index, DataTable table, int toIndex, int toCol) {
    	table.putObject(toIndex, toCol, get(index));
    }
    
}
