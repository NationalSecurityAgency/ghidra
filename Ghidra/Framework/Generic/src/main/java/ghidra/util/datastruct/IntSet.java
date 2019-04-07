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
 * Class for storing a set of integers
 */

public class IntSet {
	
	private IntKeyIndexer indexer;

	/**
	 * Constructs a new empty int set
	 * @param capacity the initial storage size, the set will grow if needed.
	 */
	public IntSet(int capacity) {
		indexer = new IntKeyIndexer(capacity);
	}
	
	/**
	 * Constructs a new IntSet and populates it with the given array of ints.
	 * @param values the array if ints to add to the set.
	 */
	public IntSet(int[] values) {
		this((values.length*3)/4);
		for(int i=0;i<values.length;i++) {
			add(values[i]);
		}
	}
	
	/**
	 * Returns the number of ints in the set.
	 * @return the number of ints in the set.
	 */
	public int size() {
		return indexer.getSize();
	}
	
	/**
	 * Returns true if the set is empty
	 */
	public boolean isEmpty() {
		return indexer.getSize() == 0;
	}
	
	/**
	 * Returns true if the set contains the given value.
	 * @param value the value to test if it is in the set.
	 * @return true if the value is in the set.
	 */
	public boolean contains(int value) {
		return indexer.get(value) >= 0;
	}
	
	/**
	 * Add the int value to the set.
	 * @param value the value to add to the set.
	 */
	public void add(int value) {
		indexer.put(value);
	}
	
	/**
	 * Removes the int value from the set.
	 * @param value the value to remove from the set.
	 * @return true if the value was in the set, false otherwise.
	 */
	public boolean remove(int value) {
		return indexer.remove(value) >= 0;
	}
	
	/**
	 * Removes all values from the set.
	 */
	public void clear() {
		indexer.clear();
	}
	
	/**
	 * Returns an array with all the values in the set.
	 */
	public int[] getValues() {
		return indexer.getKeys();
	}
}
