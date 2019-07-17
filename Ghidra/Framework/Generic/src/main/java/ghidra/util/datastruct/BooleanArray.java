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
 * Data structure to set bits to indicate in use.
 * 
 */
public class BooleanArray implements Array, Serializable {
    private final static long serialVersionUID = 1;
    private static final int MIN_SIZE = 4;
    private static final int[]  ONBITS = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };
    private static final int[] OFFBITS = {0xFE, 0xFD, 0xFB, 0xF7, 0xEF, 0xDF, 0xBF, 0x7F };
    int lastNonZeroIndex = -1;
    private byte[] bytes;

    /**
     * 
     * Constructor
     */
    public BooleanArray() {
        bytes = new byte[MIN_SIZE];
    }


    /** Puts the given boolean value in the boolean array at
     * the given index
     * @param index Index into the array.
     * @param value value to store
     * @throws IndexOutOfBoundsException if the index is negative
     */
    public void put(int index, boolean value) {
        int byteNum = index/8;
        int bitNum = index % 8;

        if (byteNum >= bytes.length) {
            if (value == false) {
                return;
            }
            adjustArray(Math.max(byteNum+1,bytes.length*2));
        }

        if (value) {
            bytes[byteNum] |= ONBITS[bitNum];
            if (index > lastNonZeroIndex) {
                lastNonZeroIndex = index;
            }
        }
        else {
            bytes[byteNum] &= OFFBITS[bitNum];
            if (index == lastNonZeroIndex) {
                lastNonZeroIndex = findLastNonZeroIndex();
            }
            if (lastNonZeroIndex/8 < bytes.length / 4) {
                adjustArray(lastNonZeroIndex/4); // lastNonZeroIndex/8 * 2
            }
        }
    }
    private int findLastNonZeroIndex() {

        for(int i=lastNonZeroIndex/8;i>=0;i--) {
            if (bytes[i] != 0) {
                for(int j=7;j>=0;j--) {
                    if ((bytes[i] & ONBITS[j]) != 0) {
                        return i*8 + j;
                    }
                }
            }
        }
        return -1;
    }
    /** Sets the value at the given index to 0.
     * @param index the index to set to 0.
     */
    public void remove(int index) {
        put(index,false);
    }
    /** Returns the boolean at the given index
     * @param index index into the array
     * @return The boolean value at the given index. A false will
     * be return for any non-negative index not initialized to
     * another value.
     * @throws IndexOutOfBoundsException if the index is negative
     */
    public boolean get(int index) {
        int byteNum = index/8;
        int bitNum = index % 8;
        if (byteNum < bytes.length) {
            return (bytes[byteNum] & ONBITS[bitNum]) != 0;
        }
        return false;
    }
    /** Adjusts the size of the array.
     * @param size The size to grow the array.
     */
    private void adjustArray(int size) {
        if (size < MIN_SIZE) {
            size = MIN_SIZE;
        }

        byte[] newBytes = new byte[size];
        int len = Math.min(size,bytes.length);
        System.arraycopy(bytes,0,newBytes,0,len);
        bytes = newBytes;
    }

    /**
     * Returns the index of the last non-null or non-zero element in the array.
     */
    public int getLastNonEmptyIndex() {
        return lastNonZeroIndex;
    }

	/**
	 * 
	 * @see ghidra.util.datastruct.Array#copyDataTo(int, ghidra.util.datastruct.DataTable, int, int)
	 */
    public void copyDataTo(int index, DataTable table, int toIndex, int toCol) {
    	table.putBoolean(toIndex, toCol, get(index));
    }

}

