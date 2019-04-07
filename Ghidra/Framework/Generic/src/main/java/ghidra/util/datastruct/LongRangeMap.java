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
import ghidra.util.prop.LongPropertySet;

import java.io.Serializable;

/**
 * Stores  ranges of long values throughout "long" space. Every "long" index has
 * an associated long value (initially 0). Users can paint (set) ranges of
 * indexes to a given integer value, overwriting any value that currently exists
 * in that range.
 * 
 * This class is implemented using a LongPropertySet.  The first index
 * (0) will always contain a value.  The value at any other given
 * index will either be the value stored at that index, or if no
 * value stored there, then the value stored at the nearest previous index
 * that contains a value.
 */
public class LongRangeMap implements Serializable {
    private final static long serialVersionUID = 1;
	
	LongPropertySet map;

	/**
	 * Constructor for RangeMap.
	 */
	public LongRangeMap() {
		map = new LongPropertySet("RangeMap");
		map.putLong(0, 0);		
	}

	/**
	 * Associates the given value with every index from start to end (inclusive)
	 * Any previous associates are overwritten.
	 * @param start the start index of the range to fill.
	 * @param end the end index of the range to fill
	 * @param value the value to put at every index in the range.
	 */
	public void paintRange(long start, long end, long value) {

		// first fix up the end of the range, unless the end goes to the END
		if (end != Long.MAX_VALUE) {
			long origEndValue = getValue(end+1);
			if (origEndValue != value) {
				map.putLong(end+1, origEndValue);
			}
			else {
				map.remove(end+1);
			}
		}

		
		// now remove any values stored from start to end
		LongIterator it = map.getPropertyIterator(start);
		while(it.hasNext()) {
			long next = it.next();
			if (next <= end) {
				map.remove(next);
			}
		}


		if (start == 0) {
			map.putLong(0,value);
		} 
		else {
			long startValue = getValue(start);
			if (startValue != value) {
				map.putLong(start, value);
			}
		}			
	}

	/**
	 * Returns the long value associated with the given index.
	 * @param index the index at which to get the value.
	 */
	public long getValue(long index) {
		try {
			return map.getLong(index);
		}
		catch(NoValueException e) {
			try {
				index = map.getPreviousPropertyIndex(index);	
				return map.getLong(index);
			}
			catch(NoSuchIndexException ex) {
			}
			catch(NoValueException ex) {
			}
		}		
		return 0;
	}

	/**
	 * Returns an index range iterator over all occupied ranges in the map
	 * @param index the index to start the iterator.
	 * @return IndexRangeIterator that iterates over all occupied ranges in th
	 * map.
	 */
	public IndexRangeIterator getIndexRangeIterator(long index) {
		return new PropertySetIndexRangeIterator(map, index);
	}

	/**
	 * Returns an iterator over all indexes where the value changes.  The value
	 * is considered to change when it goes from one value to another, or goes
	 * from no value to a value or goes from a value to no value.
	 * @param start the starting index to search.
	 * @param end the ending index to search.
	 * @return iterator over all indexes where value changes occur.
	 */
	public LongIterator getChangePointIterator(long start, long end) {
		return map.getPropertyIterator(start, end);	
	}

}
