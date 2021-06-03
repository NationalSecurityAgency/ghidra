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
package ghidra.program.database.register;

import ghidra.program.model.address.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Associates objects with address ranges.
 */
public class AddressRangeObjectMap<T> {
	private List<AddressValueRange<T>> ranges;
	AddressValueRange<T> lastRange;

	/**
	 * Constructs a new ObjectRangeMap
	 */
	public AddressRangeObjectMap() {
		ranges = new ArrayList<AddressValueRange<T>>();
	}

	/**
	 * Returns an {@link AddressRangeIterator} over all ranges that have associated objects.
	 * @return an {@link AddressRangeIterator} over all ranges that have associated objects.
	 */
	public AddressRangeIterator getAddressRangeIterator() {
		return new SimpleAddressRangeIterator();
	}

	/**
	 * Returns an {@link AddressRangeIterator} over all ranges that have associated objects within
	 * the given range.  Object Ranges that overlap the beginning or end of the given range are
	 * included, but have thier start or end index adjusted to be in the given range.
	 * @param start the first Address in the range to find all index ranges that have associated values.
	 * @param end the last Address(inclusive) in the range to find all index ranges that have associated
	 *  values.
	 * @return an {@link AddressRangeIterator} over all ranges that have associated objects within the
	 * given range.
	 */
	public AddressRangeIterator getAddressRangeIterator(Address start, Address end) {
		return new RestrictedIndexRangeIterator(start, end);
	}

	/**
	 * Move all values within an address range to a new range.
	 * @param fromAddr the first address of the range to be moved.
	 * @param toAddr the address where to the range is to be moved.
	 * @param length the number of addresses to move.
	 * @param monitor the task monitor.
	 * @throws CancelledException if the user canceled the operation via the task monitor.
	 */
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException {
		if (length <= 0) {
			return;
		}
		AddressRangeObjectMap<T> tmpMap = new AddressRangeObjectMap<T>();

		Address fromEndAddr = fromAddr.add(length - 1);
		for (AddressRange range : getAddressRangeIterator(fromAddr, fromEndAddr)) {
			monitor.checkCanceled();

			Address minAddr = range.getMinAddress();
			T value = getObject(minAddr);
			long offset = minAddr.subtract(fromAddr);
			minAddr = toAddr.add(offset);

			Address maxAddr = range.getMaxAddress();
			offset = maxAddr.subtract(fromAddr);
			maxAddr = toAddr.add(offset);

			tmpMap.setObject(minAddr, maxAddr, value);
		}
		clearRange(fromAddr, fromEndAddr);
		for (AddressRange range : tmpMap.getAddressRangeIterator()) {
			monitor.checkCanceled();
			T value = tmpMap.getObject(range.getMinAddress());
			setObject(range.getMinAddress(), range.getMaxAddress(), value);
		}
	}

	/**
	 * Associates the given object with all indices in the given range. The object may be null,
	 * but an association is still established.  Use the clearRange() method to remove associations.
	 * @param start the start of the range.
	 * @param end the end (inclusive) of the range.
	 * @param object the object to associate with the given range.
	 */
	public synchronized void setObject(Address start, Address end, T object) {
		lastRange = null;
		AddressValueRange<T> newRange = new AddressValueRange<T>(start, end, object);

		// if ranges list is empty, just add the new entry
		if (ranges.isEmpty()) {
			ranges.add(newRange);
			return;
		}

		// Look at the stored range before the new range to see if it extends into the new range
		int previousIndex = getPositionOfRangeBefore(newRange);
		if (previousIndex >= 0) {
			int oldSize = ranges.size();
			newRange = adjustPreviousRangeForOverlap(start, end, object, newRange, previousIndex);
			if (oldSize > ranges.size()) {  // if we removed the previous range
				previousIndex--;
			}
		}

		int insertionIndex = Math.max(0, previousIndex + 1);
		Address newEnd = newRange.getEnd();
		removeCompletelyOverlappedRanges(insertionIndex, newEnd);

		newRange = adjustRemainingRangeForOverlap(object, newRange, insertionIndex, newEnd);

		ranges.add(insertionIndex, newRange);
	}

	private AddressValueRange<T> adjustRemainingRangeForOverlap(T object,
			AddressValueRange<T> newRange, int insertionIndex, Address newEnd) {

		if (insertionIndex >= ranges.size()) {
			return newRange; // no record to adjust
		}

		AddressValueRange<T> range = ranges.get(insertionIndex);
		if (range.getStart().compareTo(newEnd.next()) > 0) { // no overlap
			return newRange;
		}

		if (valuesEqual(range.getValue(), object)) { // merge records
			ranges.remove(insertionIndex);
			newRange = new AddressValueRange<T>(newRange.getStart(), range.getEnd(), object);
		}
		// overwrite the old record to start past the end of the new range
		else {
			ranges.set(insertionIndex, new AddressValueRange<T>(newEnd.next(), range.getEnd(),
				range.getValue()));
		}

		return newRange;
	}

	private void removeCompletelyOverlappedRanges(int insertionIndex, Address newEnd) {
		while (insertionIndex < ranges.size()) {
			AddressValueRange<T> range = ranges.get(insertionIndex);
			if (range.getEnd().compareTo(newEnd) > 0) {
				return;
			}
			ranges.remove(insertionIndex);
		}
	}

	private AddressValueRange<T> adjustPreviousRangeForOverlap(Address start, Address end,
			T object, AddressValueRange<T> newRange, int pos) {

		AddressValueRange<T> previousRange = ranges.get(pos);
		if ((start.previous() == null) || (previousRange.getEnd().compareTo(start.previous()) < 0)) {
			return newRange;  // no overlap
		}

		Address oldStart = previousRange.getStart();
		Address oldEnd = previousRange.getEnd();
		T oldValue = previousRange.getValue();

		if (valuesEqual(previousRange.getValue(), object)) {  // same objects, merge
			ranges.remove(pos);
			newRange = new AddressValueRange<T>(oldStart, getMax(oldEnd, end), object);
		}
		// break previous record into sub-ranges that exclude the new range
		else {
			ranges.set(pos, new AddressValueRange<T>(oldStart, start.previous(), oldValue));

			// previous range extends past the new range
			if (previousRange.getEnd().compareTo(end) > 0) {
				ranges.add(pos + 1, new AddressValueRange<T>(end.next(), oldEnd, oldValue));
			}
		}

		return newRange;
	}

	/**
	 * Clears all objects from map
	 */
	public synchronized void clearAll() {
		ranges.clear();
		lastRange = null;
	}

	/**
	 * Clears any object associations within the given range.
	 * @param start the first index in the range to be cleared.
	 * @param end the last index in the range to be cleared.
	 */
	public synchronized void clearRange(Address start, Address end) {
		lastRange = null;

		// check for range before that extends into cleared area
		int pos = getPositionOfRangeBefore(new AddressValueRange<T>(start, end, null));
		if (pos >= 0) {
			AddressValueRange<T> range = ranges.get(pos);
			if (range.getEnd().compareTo(start) >= 0) {				// truncate previous range if it needed
				ranges.set(pos,
					new AddressValueRange<T>(range.getStart(), start.previous(), range.getValue()));
			}
			if (range.getEnd().compareTo(end) > 0) {					// create leftover if previous range extends
				// beyond cleared area.
				ranges.add(pos + 1,
					new AddressValueRange<T>(end.next(), range.getEnd(), range.getValue()));
			}
		}

		// now clear ranges until we find one past the cleared area
		pos = Math.max(0, pos + 1);  						// start at 0 or 1 past the previous range
		while (pos < ranges.size()) {
			AddressValueRange<T> range = ranges.get(pos);
			if (range.getEnd().compareTo(end) <= 0) {				// range totally inside cleared area
				ranges.remove(pos);
			}
			else if (range.getStart().compareTo(end) > 0) {			// range totally past clear area - done
				break;
			}
			else {										// intersects, fixup start
				ranges.set(pos,
					new AddressValueRange<T>(end.next(), range.getEnd(), range.getValue()));
			}
		}
	}

	/**
	 * Returns true if the associated address has an associated object even if the assocated object
	 * is null. 
	 * @param address the index to check for an association.
	 * @return true if the associated index has an associated object even if the assocated object
	 * is null.
	 */
	public synchronized boolean contains(Address address) {
		if (lastRange != null && lastRange.contains(address)) {
			return true;
		}

		int pos = getPositionOfRangeAtOrBefore(new AddressValueRange<T>(address, address, null));
		if (pos < 0) {
			return false;
		}
		lastRange = ranges.get(pos);

		return lastRange.contains(address);
	}

	/**
	 * Returns the object associated with the given index or null if no object is associated with
	 * the given index.  Note that null is a valid association so a null result could be either
	 * no association or an actual association of the index to null.  Use the contains() method
	 * first if the distinction is important.  If the contains() method returns true, the result
	 * is cached so the next call to getObject() will be fast. 
	 * @param address the index at which to retrieve an assocated object.
	 * @return the object (which can be null) associated with the given index or null if no such
	 * association exists.
	 */
	public synchronized T getObject(Address address) {
		if (address == null) {
			return null;
		}
		if (lastRange != null && lastRange.contains(address)) {
			return lastRange.getValue();
		}

		int pos = getPositionOfRangeAtOrBefore(new AddressValueRange<T>(address, address, null));
		if (pos < 0) {
			return null;
		}
		lastRange = ranges.get(pos);
		if (lastRange.contains(address)) {
			return lastRange.getValue();
		}
		return null;
	}

	public boolean isEmpty() {
		return ranges.isEmpty();
	}

	int getPositionOfRangeAtOrBefore(AddressValueRange<T> valueRange) {

		int pos = Collections.binarySearch(ranges, valueRange);

		if (pos >= 0) {
			return pos;
		}

		if (pos == -1) {	// index was less than first start range
			return -1;
		}

		pos = -pos - 2;		// this is the range that is before;

		return Math.min(pos, ranges.size());
	}

	int getPositionOfRangeBefore(AddressValueRange<T> valueRange) {

		int pos = Collections.binarySearch(ranges, valueRange);

		if (pos >= 0) {		// exact start match, return previous range
			return pos - 1;
		}

		if (pos == -1) {	// index was less than first start range
			return -1;
		}

		pos = -pos - 2;		// this is the range that is before;

		return Math.min(pos, ranges.size());
	}

	class SimpleAddressRangeIterator implements AddressRangeIterator {
		int pos = 0;

		@Override
		public Iterator<AddressRange> iterator() {
			return this;
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean hasNext() {
			return pos < ranges.size();
		}

		@Override
		public AddressRange next() {
			AddressValueRange<T> valueRange = ranges.get(pos++);
			return new AddressRangeImpl(valueRange.getStart(), valueRange.getEnd());
		}

	}

	private boolean valuesEqual(Object value, Object obj) {
		if (value == null) {
			return obj == null;
		}
		return value.equals(obj);
	}

	private Address getMin(Address addr1, Address addr2) {
		if (addr1.compareTo(addr2) <= 0) {
			return addr1;
		}
		return addr2;
	}

	private Address getMax(Address addr1, Address addr2) {
		if (addr1.compareTo(addr2) >= 0) {
			return addr1;
		}
		return addr2;
	}

	class RestrictedIndexRangeIterator implements AddressRangeIterator {
		private int pos = 0;
		private Address end;
		private AddressRange nextRange;

		RestrictedIndexRangeIterator(Address start, Address end) {
			this.end = end;
			pos = getPositionOfRangeAtOrBefore(new AddressValueRange<T>(start, end, null));
			if (pos >= 0) {
				AddressValueRange<T> range = ranges.get(pos++);
				if (range.contains(start)) {
					nextRange = new AddressRangeImpl(start, getMin(range.getEnd(), end));
				}
			}
			if (nextRange == null) {
				pos = Math.max(0, pos);
				getNextRange();
			}
		}

		@Override
		public Iterator<AddressRange> iterator() {
			return this;
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean hasNext() {
			return nextRange != null;
		}

		@Override
		public AddressRange next() {
			AddressRange retRange = nextRange;
			if (nextRange != null) {
				getNextRange();
			}
			return retRange;
		}

		private void getNextRange() {
			nextRange = null;
			if (pos < ranges.size()) {
				AddressValueRange<T> range = ranges.get(pos++);
				if (range.getStart().compareTo(end) <= 0) {
					nextRange = new AddressRangeImpl(range.getStart(), getMin(range.getEnd(), end));
				}
			}

		}

	}

	/**
	 * Get the value or hole range containing the specified address
	 * @param addr
	 */
	public AddressRange getAddressRangeContaining(Address addr) {

		if (lastRange != null && lastRange.contains(addr)) {
			return new AddressRangeImpl(lastRange.getStart(), lastRange.getEnd());
		}

		Address min = addr.getAddressSpace().getMinAddress();
		Address max = addr.getAddressSpace().getMaxAddress();

		int pos = getPositionOfRangeAtOrBefore(new AddressValueRange<T>(addr, addr, null));
		if (pos >= 0) {
			lastRange = ranges.get(pos);
			if (lastRange.getEnd().compareTo(addr) >= 0) {
				return new AddressRangeImpl(lastRange.getStart(), lastRange.getEnd());
			}
			if (min.getAddressSpace().equals(lastRange.getEnd().getAddressSpace())) {
				min = lastRange.getEnd().next();
			}
		}
		if (++pos < ranges.size()) {
			lastRange = ranges.get(pos);
			if (lastRange.getStart().compareTo(addr) == 0) {
				return new AddressRangeImpl(lastRange.getStart(), lastRange.getEnd());
			}
			if (max.getAddressSpace().equals(lastRange.getStart().getAddressSpace())) {
				max = lastRange.getStart().previous();
			}
		}
		return new AddressRangeImpl(min, max);
	}
}

/**
 * Associates an integer value with a numeric range.
 */
class AddressValueRange<T> implements Comparable<AddressValueRange<T>> {
	private Address start;
	private Address end;
	private T value;

	/**
	 * Constructor for numeric range with an associated value.
	 * @param start beginning of the range
	 * @param end end of the range
	 * @param value the value to associate with the range.
	 */
	public AddressValueRange(Address start, Address end, T value) {
		this.start = start;
		this.end = end;
		this.value = value;
	}

	/**
	 * Returns the beginning of the range.
	 */
	public Address getStart() {
		return start;
	}

	/**
	 * Returns the end of the range.
	 */
	public Address getEnd() {
		return end;
	}

	/**
	 * Returns the value associated with the range.
	 */
	public T getValue() {
		return value;
	}

	/**
	 * Determines whether or not the indicated index is in the range.
	 * @param address the index to check
	 * @return true if the index is in this range.
	 */
	public boolean contains(Address address) {
		return address.compareTo(start) >= 0 && address.compareTo(end) <= 0;
	}

	/**
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(AddressValueRange<T> otherRange) {
		return start.compareTo(otherRange.start);
	}

	@Override
	public String toString() {
		return start + ":" + end + "[" + value + "]";
	}
}
