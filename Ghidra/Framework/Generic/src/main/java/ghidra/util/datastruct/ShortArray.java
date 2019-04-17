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
 * ShortArray.java
 *
 * Created on February 12, 2002, 3:37 PM
 */

package ghidra.util.datastruct;

import java.io.Serializable;

/**
 *
 * Array of shorts that grows as needed.
 */
public class ShortArray implements Array, Serializable {
	private final static long serialVersionUID = 1;

    static final int MIN_SIZE = 4;
    short[] shorts;
    int lastNonZeroIndex = -1;

    /** Creates new shortArray */
    public ShortArray() {
        shorts = new short[MIN_SIZE];
    }
    
    /** Puts the given short value into the short array at
     * the given index
     * @param index Index into the array.
     * @param value value to store
     * @throws IndexOutOfBoundsException if the index is negative
     */    
    public void put(int index, short value) {
        if (value == 0) {
            remove(index);
            return;
        }
        
        if (index >= shorts.length) {
            adjustArray(Math.max(index+1,shorts.length*2));
        }
        shorts[index] = value;
        if (index > lastNonZeroIndex) {
            lastNonZeroIndex = index;
        }
    }
    
    /** Sets the value at the given index to 0.
     * @param index the index to set to 0.
     * @throws IndexOutOfBoundsException if the index is negative
     */    
    public void remove(int index) {
		if (index >= shorts.length) {
			return;
		}
        shorts[index] = (short)0;
        if (index == lastNonZeroIndex) {
            lastNonZeroIndex = findLastNonZeroIndex();
        }
        if (lastNonZeroIndex < shorts.length/4) {
            adjustArray(lastNonZeroIndex * 2);
        }
        
    }
    
    /** Finds the index of the last non-zero value.
     * @return The index of the last non-zero value. -1 will be returned
     * if the array is empty.
     */    
    private int findLastNonZeroIndex() {
        for(int i=lastNonZeroIndex;i>=0;i--) {
            if (shorts[i] != 0) {
                return i;
            }
        }
        return -1;
    }
                
    
    
    /** Returns the short at the given index
     * @param index index into the array
     * @return The short value at the given index. A 0 will
     * be return for any index not initialized to
     * another value.
     * @throws IndexOutOfBoundsException if the index is negative
     */    
    public short get(int index) {
        if (index < shorts.length) {
            return shorts[index];
        }
        return (short)0;
    }
    /** Adjusts the size of the array.
     * @param size The new capacity of the array.
     */    
    private void adjustArray(int size) {
        if (size < MIN_SIZE) {
            size = MIN_SIZE;
        }
        short[] newshorts = new short[size];
        int len = Math.min(size,shorts.length);
        System.arraycopy(shorts,0,newshorts,0,len);
        shorts = newshorts;
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
    	table.putShort(toIndex, toCol, get(index));
    }
}
