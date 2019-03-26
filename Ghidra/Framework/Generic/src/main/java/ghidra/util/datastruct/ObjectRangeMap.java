/* ###
 * IP: GHIDRA
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

import java.util.*;

/**
 * Associates objects with long index ranges.
 */
public class ObjectRangeMap <T> {
	private List<ObjectValueRange<T>> ranges;
	ObjectValueRange<T> lastRange;
	
	/**
	 * Constructs a new ObjectRangeMap
	 */
	public ObjectRangeMap() {
		ranges = new ArrayList<ObjectValueRange<T>>();
	}

	/**
	 * Returns an {@link IndexRangeIterator} over all ranges that have associated objects.
	 * @return an {@link IndexRangeIterator} over all ranges that have associated objects.
	 */
	public IndexRangeIterator getIndexRangeIterator() {
		return new SimpleIndexRangeIterator();
	}

	/**
	 * Returns an {@link IndexRangeIterator} over all ranges that have associated objects within
	 * the given range.  Object Ranges that overlap the beginning or end of the given range are
	 * included, but have thier start or end index adjusted to be in the given range.
	 * @param start the first index in the range to find all index ranges that have associated values.
	 * @param end the last index(inclusive) in the range to find all index ranges that have associated
	 *  values.
	 * @return an {@link IndexRangeIterator} over all ranges that have associated objects within the
	 * given range.
	 */
	public IndexRangeIterator getIndexRangeIterator(long start, long end) {
		return new RestrictedIndexRangeIterator(start, end);
	}
	
	/**
	 * Associates the given object with all indices in the given range. The object may be null,
	 * but an assocition is still established.  Use the clearRange() method to remove associations.
	 * @param start the start of the range.
	 * @param end the end (inclusive) of the range.
	 * @param object the object to associate with the given range.
	 */
	public synchronized void setObject(long start, long end, T object) {
		lastRange = null;
		ObjectValueRange<T> newRange = new ObjectValueRange<T>(start, end, object);
	
		// if ranges list is empty, just add the new entry
		if (ranges.isEmpty()) {
			ranges.add(newRange);
			return;
		}
		
		// Look at the stored range before the new range to see if it extends into the new range
		int previousIndex = getPositionOfRangeBefore(newRange);
		if ( previousIndex >= 0 ) {
			newRange = adjustPreviousRangeForOverlap(start, end, object, newRange, previousIndex);
		}

		int insertionIndex = Math.max(0, previousIndex+1);
		long newEnd = newRange.getEnd();
		removeCompletelyOverlappedRanges(insertionIndex, newEnd);
		
		newRange = adjustRemainingRangeForOverlap(object, newRange, insertionIndex, newEnd);

		ranges.add(insertionIndex, newRange);
	}

	private ObjectValueRange<T> adjustRemainingRangeForOverlap(T object, 
			ObjectValueRange<T> newRange, int insertionIndex, long newEnd) {
		
		if ( insertionIndex >= ranges.size() ) {
			return newRange; // no record to adjust
		}
		
		ObjectValueRange<T> range = ranges.get(insertionIndex);
		if ( range.getStart() > newEnd+1 ) { // no overlap
			return newRange;
		}
		
		if (valuesEqual(range.getValue(), object)) { // merge records
			ranges.remove(insertionIndex);
			newRange = new ObjectValueRange<T>(newRange.getStart(), range.getEnd(), object);
		}
		// overwrite the old record to start past the end of the new range
		else {
			ranges.set(insertionIndex, new ObjectValueRange<T>(newEnd+1, range.getEnd(), range.getValue()));
		}
			
		return newRange;
	}

	private void removeCompletelyOverlappedRanges(int insertionIndex, long newEnd) {
		while(insertionIndex < ranges.size()) {
			ObjectValueRange<T> range = ranges.get(insertionIndex);
			if (range.getEnd() > newEnd) {
				return;
			}
			ranges.remove(insertionIndex);
		}
	}

	private ObjectValueRange<T> adjustPreviousRangeForOverlap(long start, long end, T object, 
			ObjectValueRange<T> newRange, int pos) {
		
		ObjectValueRange<T> previousRange = ranges.get(pos);
		if ( previousRange.getEnd() < start-1 ) {
			return newRange;  // no overlap
		}
		
		long oldStart = previousRange.getStart();
		long oldEnd = previousRange.getEnd();
		T oldValue = previousRange.getValue();
		
		if (valuesEqual(previousRange.getValue(), object)) {  // same objects, merge
			ranges.remove(pos);
			newRange = new ObjectValueRange<T>(oldStart, Math.max(oldEnd, end), object);
		}		
		// break previous record into sub-ranges that exclude the new range
		else {  
			ranges.set(pos, new ObjectValueRange<T>(oldStart, start-1, oldValue));
			
			// previous range extends past the new range
			if (previousRange.getEnd() > end) {
				ranges.add(pos+1, new ObjectValueRange<T>(end+1, oldEnd, oldValue));
			}
		}
		
		return newRange;
	}

	/**
	 * Clears any object associations within the given range.
	 * @param start the first index in the range to be cleared.
	 * @param end the last index in the range to be cleared.
	 */
	public synchronized void clearRange(long start, long end) {
		lastRange = null;
		
		// check for range before that extends into cleared area
		int pos = getPositionOfRangeBefore(new ObjectValueRange<T>(start, end, null));
		if (pos >= 0) {
			ObjectValueRange<T> range = ranges.get(pos);
			if (range.getEnd() >= start) {				// truncate previous range if it needed
				ranges.set(pos, new ObjectValueRange<T>(range.getStart(), start-1, range.getValue()));
			}
			if (range.getEnd() > end) {					// create leftover if previous range extends
														// beyond cleared area.
				ranges.add(pos+1, new ObjectValueRange<T>(end+1, range.getEnd(), range.getValue()));
			}
		}
		
		// now clear ranges until we find one past the cleared area
		pos = Math.max(0, pos+1);  						// start at 0 or 1 past the previous range
		while(pos < ranges.size()) {
			ObjectValueRange<T> range = ranges.get(pos);
			if (range.getEnd() <= end) {				// range totally inside cleared area
				ranges.remove(pos);
			}
			else if (range.getStart() > end) {			// range totally past clear area - done
				break;
			}
			else {										// intersects, fixup start
				ranges.set(pos, new ObjectValueRange<T>(end+1, range.getEnd(), range.getValue()));
			}
		}
	}
	
	/**
	 * Returns true if the associated index has an associated object even if the assocated object
	 * is null. 
	 * @param index the index to check for an association.
	 * @return true if the associated index has an associated object even if the assocated object
	 * is null.
	 */
	public synchronized boolean contains(long index) {
		if (lastRange != null && lastRange.contains(index)) {
			return true;
		}
		
		int pos = getPositionOfRangeAtOrBefore(new ObjectValueRange<T>(index, index, null));		
		if (pos < 0) {
			return false;
		}
		lastRange = ranges.get(pos);
		
		return lastRange.contains(index);
	}
	
	/**
	 * Returns the object associated with the given index or null if no object is associated with
	 * the given index.  Note that null is a valid association so a null result could be either
	 * no association or an actual association of the index to null.  Use the contains() method
	 * first if the distinction is important.  If the contains() method returns true, the result
	 * is cached so the next call to getObject() will be fast. 
	 * @param index the index at which to retrieve an assocated object.
	 * @return the object (which can be null) associated with the given index or null if no such
	 * association exists.
	 */
	public synchronized T getObject(long index) {
		if (lastRange != null && lastRange.contains(index)) {
			return lastRange.getValue();
		}
		
		int pos = getPositionOfRangeAtOrBefore(new ObjectValueRange<T>(index, index, null));		
		if (pos < 0) {
			return null;
		}
		lastRange = ranges.get(pos);
		if (lastRange.contains(index)) {
			return lastRange.getValue();
		}
		return null;
	}
	
	
	int getPositionOfRangeAtOrBefore(ObjectValueRange<T> valueRange) {
		
		int pos = Collections.binarySearch(ranges, valueRange);
		
		if (pos >= 0) {
			return pos;
		}
		
		if (pos == -1) {	// index was less than first start range
			return -1;
		}
		
		pos = -pos-2;		// this is the range that is before;
		
		return Math.min(pos, ranges.size());
	}

	int getPositionOfRangeBefore(ObjectValueRange<T> valueRange) {
		
		int pos = Collections.binarySearch(ranges, valueRange);
		
		if (pos >= 0) {		// exact start match, return previous range
			return pos-1;
		}
		
		if (pos == -1) {	// index was less than first start range
			return -1;
		}
		
		pos = -pos-2;		// this is the range that is before;
		
		return Math.min(pos, ranges.size());
	}

	class SimpleIndexRangeIterator implements IndexRangeIterator {
		int pos = 0;

		public boolean hasNext() {
			return pos < ranges.size();
		}

		public IndexRange next() {
			ObjectValueRange<T> valueRange = ranges.get(pos++);
			return new IndexRange(valueRange.getStart(), valueRange.getEnd());
		}
		
	}
	private boolean valuesEqual(Object value, Object obj) {
		if (value == null) {
			return obj == null;
		}
		return value.equals(obj);
	}

	
	class RestrictedIndexRangeIterator implements IndexRangeIterator {
		private int pos = 0;
		private long end;
		private IndexRange nextRange;

		RestrictedIndexRangeIterator(long start, long end) {
			this.end = end;
			pos = getPositionOfRangeAtOrBefore(new ObjectValueRange<T>(start, end, null));
			if (pos >= 0) {
				ObjectValueRange<T> range = ranges.get(pos++);
				if (range.contains(start)) {
					nextRange = new IndexRange(start, Math.min(range.getEnd(), end));
				}
			}
			if (nextRange == null) {
				pos = Math.max(0, pos);
				getNextRange();
			}
		}
		
		public boolean hasNext() {
			return nextRange != null;
		}

		public IndexRange next() {
			IndexRange retRange = nextRange;
			if (nextRange != null) {
				getNextRange();
			}
			return retRange;
		}
		private void getNextRange() {
			nextRange = null;
			if (pos < ranges.size()) {
				ObjectValueRange<T> range = ranges.get(pos++);
				if (range.getStart() <= end) {
					nextRange = new IndexRange(range.getStart(), Math.min(range.getEnd(), end));
				}
			}
			
		}
		
	}
}
