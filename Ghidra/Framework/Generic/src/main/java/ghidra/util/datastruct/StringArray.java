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
 * StringArray.java
 *
 * Created on February 14, 2002, 10:29 AM
 */

package ghidra.util.datastruct;

import java.io.Serializable;

/**
 *
 * Array of Strings that grows as needed.
 */
public class StringArray implements Array, Serializable {
	private final static long serialVersionUID = 1;

    static final int MIN_SIZE = 4;
    byte[] bytes;
    int[] starts;
    short[] lengths;
    int totalSpaceAllocated;
    int nextFree=1;
    int lastStart = -1;

    /** Creates new StringArray */
    public StringArray() {
        bytes = new byte[10];
        starts = new int[MIN_SIZE];
        lengths = new short[MIN_SIZE];
    }
    
    /** Puts the given String value in the String array at
     * the given index
     * @param index Index into the array.
     * @param value value to store
     */    
    public void put(int index, String value) {
        if (value == null) {
            remove(index);
            return;
        }
        
        if (index >= starts.length) {        
            adjustArraySizes(Math.max(index+1,starts.length*2));
        }
        if (index > lastStart) {
            lastStart = index;
        }
        int len = value.length();
        
        // is there already something here?
        if (starts[index] > 0) {
            // if so, does the new array fit in the already allocated space?
            if (lengths[index] >= len) {
                // if it does, subtract the difference the allocated space total
                totalSpaceAllocated -= lengths[index]-len;  
            }
            else {
                // otherwise, subtract the entire space from the allocated space total
                // and allocate new space
                totalSpaceAllocated -= lengths[index];
                starts[index] = allocSpace(len);
            }
        }
        else {
            starts[index] = allocSpace(len);
        }
        lengths[index] = (short)len;
        byte[] strBytes = value.getBytes();
        System.arraycopy(strBytes,0,bytes,starts[index],len);
    }
    /** Returns the String at the given index
     * @param index index into the array
     * @return The String  at the given index. A null will
     * be return for any index not initialized to
     * another value.
     */    
    public String get(int index) {
        try {
            int start = starts[index];
            int len = lengths[index];
            if (start > 0) {
                if (len > 0) {
                    return new String(bytes,start,len);
                }
                return "";
            }
        } catch (IndexOutOfBoundsException e) {
        }
        return null;
    }
    /** Removes the string at the given index
     * @param index index of the string to be removed
     */    
    public void remove(int index) {
        try {
            if (starts[index] > 0) {
                totalSpaceAllocated -= lengths[index];
                starts[index] = 0;
                if (totalSpaceAllocated < bytes.length / 4) {
                    adjustSpace(totalSpaceAllocated * 2);
                }
            }
        } catch (IndexOutOfBoundsException e) {
        }
        
        if (index == lastStart) {
            findLastStart();
            if (lastStart < starts.length / 4) {
                shrinkArrays(lastStart * 2);
            }
        }
    }
    /** finds the last array index
     */    
    private void findLastStart() {
        for(int i=lastStart;i>=0;i--) {
            if (starts[i] != 0) {
                lastStart = i;
                return;
            }
        }
        lastStart = -1;
    }
    
    /** Grows the array.  The new array capacity will be
     * the maximum of minCapacity and twice the current
     * capacity.
     * @param minCapacity The minimum size to grow the array.
     */    
    private void adjustArraySizes(int size) {
        if (size < MIN_SIZE) {
            size = MIN_SIZE;
        }
        
        int len = Math.min(size,starts.length);
        int[] newStarts = new int[size];
        short[] newLengths = new short[size];
            
        System.arraycopy(starts,0,newStarts,0,len);
        System.arraycopy(lengths,0,newLengths,0,len);
        starts = newStarts;
        lengths = newLengths;
    }

    /** Shrinks the starts and lengths array as items at the end of the list
     * are removed.
     * @param capacity the new size to make the arrays
     */    
    private void shrinkArrays(int capacity) {
        int size = Math.max(capacity, 4);
        int[] newStarts = new int[size];
        short[] newLengths = new short[size];
        System.arraycopy(starts,0,newStarts,0,newStarts.length);
        System.arraycopy(lengths,0,newLengths,0,newStarts.length);
        starts = newStarts;
        lengths = newLengths;
    }

    
    /** Allocs space for storing the array
     * @param size number of elements to allocate space for
     * @return Returns the start position in the buffer for the
     * storage for the array
     */    
    private int allocSpace(int size) {
        if (size > bytes.length - nextFree) {
            adjustSpace(2*(totalSpaceAllocated+size));
        }
        int ret = nextFree;
        nextFree += size;
        totalSpaceAllocated += size;
        return ret;
    }
    
    /** 
     * Adjusts the buffer size as the storage requirements change.
     * Every time the buffer is resized, arrays are compacted.
     * @param newSize the new size to adjust the buffer to
     */    
    private void adjustSpace(int newSize) {
        if (newSize < 10) {
            newSize = 10;
        }
        byte[] newBytes = new byte[newSize];
        int pos = 1;
        for(int i=0;i<starts.length;i++) {
            if (starts[i] > 0) {
            	int len = lengths[i] & 0xFFFF;
                System.arraycopy(bytes,starts[i],newBytes,pos,len);
                starts[i] = pos;
                pos += len;
            }
        }
        nextFree = pos;
        bytes = newBytes;
    }
    
    /**
     * Returns the index of the last non-null or non-zero element in the array.
     */
    public int getLastNonEmptyIndex() {
        return lastStart;
    }
    
    /**
     * 
     * @see ghidra.util.datastruct.Array#copyDataTo(int, ghidra.util.datastruct.DataTable, int, int)
     */
    public void copyDataTo(int index, DataTable table, int toIndex, int toCol) {
    	table.putString(toIndex, toCol, get(index));
    }
}

