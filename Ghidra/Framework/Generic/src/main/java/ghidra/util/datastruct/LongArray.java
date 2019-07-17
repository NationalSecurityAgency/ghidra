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
/*
 * LongArray.java
 *
 * Created on February 12, 2002, 3:59 PM
 */

package ghidra.util.datastruct;

import java.io.Serializable;

/**
 *
 * Array of longs that grows as needed.
 */
public class LongArray implements Array, Serializable {
	public final static long serialVersionUID = 1;

    public static final int MIN_SIZE = 4;
    long[] longs;
    int lastNonZeroIndex = -1;

    /** Creates new LongArray */
    public LongArray() {
        longs = new long[MIN_SIZE];
    }
    
    /** Puts the given long value in the long array at
     * the given index
     * @param index Index into the array.
     * @param value value to store
     * @throws IndexOutOfBoundsException if the index is negative
     */    
    public void put(int index, long value) {
        if (value == 0) {
            remove(index);
            return;
        }
        
        if (index >= longs.length) {
            adjustArray(Math.max(index+1,longs.length*2));
        }
        longs[index] = value;
        if (index > lastNonZeroIndex) {
            lastNonZeroIndex = index;
        }
    }
    
    /** Sets the value at the given index to 0.
     * @param index the index to set to 0.
     * @throws IndexOutOfBoundsException if the index is negative
     */    
    public void remove(int index) {
		if (index >= longs.length) {
			return;
		}
        longs[index] = 0;
        if (index == lastNonZeroIndex) {
            lastNonZeroIndex = findLastNonZeroIndex();
        }
        if (lastNonZeroIndex < longs.length/4) {
            adjustArray(lastNonZeroIndex * 2);
        }
        
    }
    
    /** Finds the index of the last non-zero value.
     * @return The index of the last non-zero value. 0 will be returned
     * if the array is empty.
     */    
    private int findLastNonZeroIndex() {
        for(int i=lastNonZeroIndex;i>=0;i--) {
            if (longs[i] != 0) {
                return i;
            }
        }
        return -1;
    }
                
    
    
    /** Returns the long at the given index
     * @param index index into the array
     * @return The long value at the given index. A 0 will
     * be returned for any index not initialized to
     * another value.
     * @throws IndexOutOfBoundsException if the index is negative
     */    
    public long get(int index) {
        if (index < longs.length) {
            return longs[index];
        }
        return 0;
    }
    
    /** Adjusts the size of the array.
     * @param size The new capacity of the array.
     */    
    private void adjustArray(int size) {
        if (size < MIN_SIZE) {
            size = MIN_SIZE;
        }
        long[] newlongs = new long[size];
        int len = Math.min(size,longs.length);
        System.arraycopy(longs,0,newlongs,0,len);
        longs = newlongs;
    }
    /**
     * 
     * @see ghidra.util.datastruct.Array#getLastNonEmptyIndex()
     */
    public int getLastNonEmptyIndex() {
        return lastNonZeroIndex;
    }
    
    /**
     * 
     * @see ghidra.util.datastruct.Array#copyDataTo(int, ghidra.util.datastruct.DataTable, int, int)
     */
    public void copyDataTo(int index, DataTable table, int toIndex, int toCol) {
    	table.putLong(toIndex, toCol, get(index));
    }
    
}
