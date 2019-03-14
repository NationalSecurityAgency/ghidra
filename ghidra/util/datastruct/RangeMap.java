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

import ghidra.util.LongIterator;
import ghidra.util.exception.NoValueException;
import ghidra.util.prop.IntPropertySet;

import java.io.Serializable;

/**
 * Stores ranges of int values throughout "long" space. Every "long" index has
 * an associated int value (initially 0). Users can paint (set) ranges of
 * indexes to a given integer value, overwriting any value that currently exists
 * in that range.
 * 
 * This class is implemented using an IntPropertyMap.  The first index
 * (0) will always contain a value.  The value at any other given
 * index will either be the value stored at that index, or if no
 * value stored there, then the value stored at the nearest previous index
 * that contains a value.
 */
public class RangeMap implements Serializable {
    private final static long serialVersionUID = 1;
	
	IntPropertySet map;
	int defaultValue;
	
	/**
	 * Constructor for RangeMap with a default value of 0.
	 */
	public RangeMap() {
		this(0);
	}
	
	/**
	 * Creates a new range map with spcified default value.
	 * @param defaultValue the default value
	 */
	public RangeMap(int defaultValue) {
		map = new IntPropertySet("RangeMap");
		this.defaultValue = defaultValue;
		map.putInt(0, defaultValue);		
	}
	
	/**
	 * Clears all current values from the range map and resets the default value.
	 */
	public void clear() {
		map.removeRange(0, Long.MAX_VALUE);
		map.putInt(0,defaultValue);
	}
	
	/**
	 * Associates the given value with every index from start to end (inclusive)
	 * Any previous associates are overwritten.
	 * @param start the start index of the range to fill.
	 * @param end the end index of the range to fill
	 * @param value the value to put at every index in the range.
	 */
	public void paintRange(long start, long end, int value) {

		// first fix up the end of the range, unless the end goes to the END
		if (end != Long.MAX_VALUE) {
			int origEndValue = getValue(end+1);
			if (origEndValue != value) {
				map.putInt(end+1, origEndValue);
			}
			else {
				map.remove(end+1);
			}
		}

		
		// now remove any values stored from start to end
		LongIterator it = map.getPropertyIterator(start);
		while(it.hasNext()) {
			long next = it.next();
			if (next > end) break;
			map.remove(next);
		}


		if (start == 0) {
			map.putInt(0,value);
		} 
		else {
			int startValue = getValue(start);
			if (startValue != value) {
				map.putInt(start, value);
			}
		}			
	}

	/**
	 * Returns the int value associated with the given index.
	 * @param index the index at which to get the value.
	 */
	public int getValue(long index) {
		try {
			return map.getInt(index);
		}
		catch(NoValueException e) {
			try {
				index = map.getPreviousPropertyIndex(index);	
				return map.getInt(index);
			}
			catch(NoSuchIndexException ex) {
			}
			catch(NoValueException ex) {
			}
		}		
		return 0;
	}
	
	/**
	 * Returns the value range containing the given index. The value range indicates
	 * the int value and the start and end index for the range.
	 * @param index the index at which to get the associated value range
	 * @return the value range
	 */
	public ValueRange getValueRange(long index) {
		if (map.getSize() == 1) {
			return new ValueRange(0,Long.MAX_VALUE,0);
		}
		long start = 0;
		if (map.hasProperty(index)) {
			start = index;
		}
		else {
			try {
				start = map.getPreviousPropertyIndex(index);
			}catch(NoSuchIndexException e){}
		}
		long end = Long.MAX_VALUE;
		try {
			end = map.getNextPropertyIndex(start)-1;
		}catch(NoSuchIndexException e){}
		int value = 0;
		try {
			value = map.getInt(start);
		} catch (NoValueException e1) {}
		return new ValueRange(start, end, value);
	}
	
	/**
	 * Returns an iterator over all occupied ranges in the map.
	 * @param index the index to start the iterator
	 * @return an iterator over all occupied ranges in the map.
	 */
	public IndexRangeIterator getIndexRangeIterator(long index) {
		return new PropertySetIndexRangeIterator(map, index);
	}

	/**
	 * Returns an iterator over all indexes where the value changes.
	 * @param start the starting index to search.
	 * @param end the ending index to search.
	 * @return an iterator over all indexes where the value changes.
	 */
	public LongIterator getChangePointIterator(long start, long end) {
		return map.getPropertyIterator(start, end);	
	}


}
