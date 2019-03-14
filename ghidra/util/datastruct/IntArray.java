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
 * IntArray.java
 *
 * Created on February 12, 2002, 3:41 PM
 */

package ghidra.util.datastruct;
import java.io.Serializable;
/**
 *
 * Array of ints that grows as needed.
 */
public class IntArray implements Array, Serializable {
    private final static long serialVersionUID = 1;
    public static final int MIN_SIZE = 4;
    int[] ints;
    int lastNonZeroIndex = -1;

    /** Creates new intArray */
    public IntArray() {
        ints = new int[MIN_SIZE];
    }

    /** Puts the given int value in the int array at
     * the given index
     * @param index Index into the array.
     * @param value value to store
     * @throws IndexOutOfBoundsException if the index is negative
     */
    public void put(int index, int value) {
        if (value == 0) {
            remove(index);
            return;
        }

        if (index >= ints.length) {
            adjustArray(Math.max(index+1,ints.length*2));
        }
        ints[index] = value;
        if (index > lastNonZeroIndex) {
            lastNonZeroIndex = index;
        }
    }

    /** Sets the value at the given index to 0.
     * @param index the index to set to 0.
     * @throws IndexOutOfBoundsException if the index is negative
     */
    public void remove(int index) {
		if (index >= ints.length) {
			return;
		}
        ints[index] = 0;
        if (index == lastNonZeroIndex) {
            lastNonZeroIndex = findLastNonZeroIndex();
        }
        if (lastNonZeroIndex < ints.length/4) {
            adjustArray(lastNonZeroIndex * 2);
        }

    }

    /** Finds the index of the last non-zero value.
     * @return The index of the last non-zero value. -1 will be return
     * if the array is empty.
     */
    private int findLastNonZeroIndex() {
        for(int i=lastNonZeroIndex;i>=0;i--) {
            if (ints[i] != 0) {
                return i;
            }
        }
        return -1;
    }



    /** Returns the int at the given index
     * @param index index into the array
     * @return The int value at the given index. A 0 will
     * be return for any index not initialized to
     * another value.
     * @throws IndexOutOfBoundsException if the index is negative
     */
    public int get(int index) {
        if (index < ints.length) {
            return ints[index];
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
        int[] newints = new int[size];
        int len = Math.min(size,ints.length);
        System.arraycopy(ints,0,newints,0,len);
        ints = newints;
    }
	/**
	 * @see ghidra.util.datastruct.Array#getLastNonEmptyIndex()
	 */
    public int getLastNonEmptyIndex() {
        return lastNonZeroIndex;
    }

	/**
	 * @see ghidra.util.datastruct.Array#copyDataTo(int, DataTable, int, int)
	 */
    public void copyDataTo(int index, DataTable table, int toIndex, int toCol) {
    	table.putInt(toIndex, toCol, get(index));
    }

}
