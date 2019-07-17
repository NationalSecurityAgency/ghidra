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
package ghidra.util.prop;
import ghidra.util.LongIterator;
import ghidra.util.datastruct.NoSuchIndexException;

import java.util.NoSuchElementException;

/**
 * Class to iterate over indexes of a PropertyMap.
 */
class LongIteratorImpl implements LongIterator {

	private PropertySet pm;
	private long start;
	private long end;
	private long current;
	private boolean hasBoundaries;
	private boolean doesHaveNext;
	private boolean doesHavePrevious;

	LongIteratorImpl(PropertySet pm) {
		this(pm, 0, true);
	}
	/**
	 * Constructor for creating a LongIterator that iterates
     * over the entire range of properties.
     * @param pm the property map to be iterated
     * @param start the initial property map index position of the iterator
     * @param before If before is true, start will be the first index returned
     * from a call to next(); If before is false, start will be the first index returned
     * from a call to previous().
	 */
    LongIteratorImpl(PropertySet pm, long start, boolean before) {
		this.pm = pm;
    	this.start = before ? start : (start+1);
		current = start;
        init(true);
    }
	/**
	 * Constructor for creating a LongIterator that iterates
     * over a range of property indexes. This iterator will only
     * return property indexes within the given range (inclusive).
     * @param pm the property map to be iterated
     * @param start the initial property map index position of the iterator
     * @param end the last property map index position of the iterator
	 */
	LongIteratorImpl(PropertySet pm, long start, long end) {
		this(pm, start, end, true);
	}
	/**
	 * Constructor for creating a LongIterator that iterates
     * over a range of property indexes. This iterator will only
     * return property indexes within the given range (inclusive).
     * @param pm the property map to be iterated
     * @param start the initial property map index position of the iterator
     * @param end the last property map index position of the iterator
     * @param atStart If true, the iterator goes from start to end. 
     * Otherwise, from end to start.
	 */
	LongIteratorImpl(PropertySet pm, long start, long end, boolean atStart) {
		this.pm = pm;
		this.start =start;
		this.end = end;
		hasBoundaries = true;
		current = atStart ? start : end;
	    init(atStart);
	}
	/**
	 * Returns true if the iterator has more indexes.
	 */
    public boolean hasNext(){

		if (doesHaveNext) {
			return true;
		}
		findNext();
		return doesHaveNext;
	}
	/**
	 * Returns the next index in the iterator.
	 */
    public long next() {
		if (hasNext()) {
			doesHaveNext = false;
            doesHavePrevious = true;
			return current;
		}

		throw new NoSuchElementException("No more indexes.");
	}
	/**
	 * Return true if the iterator has a previous index.
	 */
    public boolean hasPrevious() {
        if (doesHavePrevious) {
			return true;
		}
		findPrevious();
		return doesHavePrevious;
    }

	/**
	 * Returns the previous index in the iterator.
	 */
    public long previous() {
        if (hasPrevious()) {
			doesHavePrevious = false;
            doesHaveNext = true;
			return current;
		}

		throw new NoSuchElementException("No more indexes.");
    }


	///////////////////////////////////////////////////////////
	/**
	 * Return whether there is a next index; if there is,
	 * "currentNext" has the value.
	 */
	private void findNext() {

		try {
			long nextIndex = pm.getNextPropertyIndex(current);
            if (hasBoundaries && nextIndex > end) {
                doesHaveNext = false;
                return;
            }
			current = nextIndex;
            doesHaveNext = true;
            doesHavePrevious = false;

		} catch (NoSuchIndexException e) {
			return;
		}
	}

	/**
	 * Return whether there is a previous index; if there is,
	 * "currentPrevious" has the value.
	 */
	private void findPrevious() {

		try {
			long prevIndex = pm.getPreviousPropertyIndex(current);
            if (hasBoundaries && prevIndex < start) {
                doesHavePrevious = false;
                return;
            }
			current = prevIndex;
            doesHavePrevious = true;
            doesHaveNext = false;
		} catch (NoSuchIndexException e) {
			return;
		}
	}

    /**
     * checks to see if the start index has a property so that the first
     * call to next() will return that index.
     */
    private void init(boolean atStart) {
        if (pm.hasProperty(current)) {
			if (atStart) {
	            doesHaveNext = true;
			}
			else {
				doesHavePrevious = true;
			}
        }
    }

}
