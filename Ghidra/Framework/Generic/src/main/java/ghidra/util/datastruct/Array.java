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

/**
 * Base interface for Defining methods for managing a "virtual" array of some data type.
 * Any access of an Array with an index that has never been set will return 0 
 * (or something like that depending on the data type)
 * 
 * 
 */
public interface Array {

    /**
     * Removes the value at that index.  If the array is of primitive type (int, short, etc),
     * then "removing" the value is equivilent to setting the value to 0;
     * @param index int index into the array to remove.
     */
    void remove(int index);

    /**
     * Returns the index of the last non-null or non-zero element in the array.
     */
    int getLastNonEmptyIndex();

	/**
	 * Copies the underlying value for this array at the given index to the
	 * data table at the given index and column.  The data type at the column in
	 * the data table must be the same as the data in this array.
	 * @param index index into this array to copy the value from.
	 * @param table the data table object to copy the data to.
	 * @param toIndex the index into the destination data table to copy the
	 * value.
	 * @param toCol the data table column to store the value.  Must be the same
	 * type as this array.
	 */
    void copyDataTo(int index, DataTable table,int toIndex, int toCol);
}

