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

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Associates objects with address ranges.
 * Optimized implementation using TreeMap for O(log n) operations.
 */
public class AddressRangeObjectMap<T> {
	private TreeMap<Address, AddressValueRange<T>> rangeMap;
	AddressValueRange<T> lastRange;

	/**
	 * Constructs a new ObjectRangeMap
	 */
	public AddressRangeObjectMap() {
		rangeMap = new TreeMap<Address, AddressValueRange<T>>();
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
		return new RestrictedAddressRangeIterator(start, end);
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
			monitor.checkCancelled();

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
			monitor.checkCancelled();
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
		
		if (start.compareTo(end) > 0) {
			return; // Invalid range
		}
		
		// Find and remove all overlapping ranges
		List<AddressValueRange<T>> toRemove = new ArrayList<>();
		List<AddressValueRange<T>> toAdd = new ArrayList<>();
		
		// Find overlapping ranges using subMap for efficiency
		Address searchStart = start;
		try {
			if (start.previous() != null) {
				searchStart = start.previous();
			}
		} catch (AddressOutOfBoundsException e) {
			// start is minimum address, use start itself
		}
		
		NavigableMap<Address, AddressValueRange<T>> overlapping = 
			rangeMap.tailMap(searchStart, true);
		
		for (Map.Entry<Address, AddressValueRange<T>> entry : overlapping.entrySet()) {
			AddressValueRange<T> existing = entry.getValue();
			
			// If this range starts after our end, we're done
			if (existing.getStart().compareTo(end) > 0) {
				break;
			}
			
			// Check for actual overlap
			if (existing.getEnd().compareTo(start) >= 0) {
				toRemove.add(existing);
				
				// Handle partial overlaps - create fragments for non-overlapping parts
				if (existing.getStart().compareTo(start) < 0) {
					// Part before our range
					try {
						toAdd.add(new AddressValueRange<T>(existing.getStart(), start.previous(), existing.getValue()));
					} catch (AddressOutOfBoundsException e) {
						// start is minimum address, no part before
					}
				}
				
				if (existing.getEnd().compareTo(end) > 0) {
					// Part after our range
					try {
						toAdd.add(new AddressValueRange<T>(end.next(), existing.getEnd(), existing.getValue()));
					} catch (AddressOutOfBoundsException e) {
						// end is maximum address, no part after
					}
				}
			}
		}
		
		// Remove overlapping ranges
		for (AddressValueRange<T> range : toRemove) {
			rangeMap.remove(range.getStart());
		}
		
		// Add back the non-overlapping fragments
		for (AddressValueRange<T> range : toAdd) {
			rangeMap.put(range.getStart(), range);
		}
		
		// Try to merge with adjacent ranges having the same value
		Address newStart = start;
		Address newEnd = end;
		
		// Check range before
		try {
			if (start.previous() != null) {
				Map.Entry<Address, AddressValueRange<T>> beforeEntry = rangeMap.floorEntry(start.previous());
				if (beforeEntry != null) {
					AddressValueRange<T> beforeRange = beforeEntry.getValue();
					if (beforeRange.getEnd().equals(start.previous()) && valuesEqual(beforeRange.getValue(), object)) {
						newStart = beforeRange.getStart();
						rangeMap.remove(beforeRange.getStart());
					}
				}
			}
		} catch (AddressOutOfBoundsException e) {
			// start is minimum address
		}
		
		// Check range after
		try {
			if (end.next() != null) {
				AddressValueRange<T> afterRange = rangeMap.get(end.next());
				if (afterRange != null && valuesEqual(afterRange.getValue(), object)) {
					newEnd = afterRange.getEnd();
					rangeMap.remove(afterRange.getStart());
				}
			}
		} catch (AddressOutOfBoundsException e) {
			// end is maximum address
		}
		
		// Add the new merged range
		AddressValueRange<T> newRange = new AddressValueRange<T>(newStart, newEnd, object);
		rangeMap.put(newStart, newRange);
	}

	/**
	 * Clears all objects from map
	 */
	public synchronized void clearAll() {
		rangeMap.clear();
		lastRange = null;
	}

	/**
	 * Clears any object associations within the given range.
	 * @param start the first index in the range to be cleared.
	 * @param end the last index in the range to be cleared.
	 */
	public synchronized void clearRange(Address start, Address end) {
		lastRange = null;
		
		if (start.compareTo(end) > 0) {
			return; // Invalid range
		}
		
		// Find overlapping ranges
		List<AddressValueRange<T>> toRemove = new ArrayList<>();
		List<AddressValueRange<T>> toAdd = new ArrayList<>();
		
		// Find overlapping ranges using subMap for efficiency
		Address searchStart = start;
		try {
			if (start.previous() != null) {
				searchStart = start.previous();
			}
		} catch (AddressOutOfBoundsException e) {
			// start is minimum address, use start itself
		}
		
		NavigableMap<Address, AddressValueRange<T>> overlapping = 
			rangeMap.tailMap(searchStart, true);
		
		for (Map.Entry<Address, AddressValueRange<T>> entry : overlapping.entrySet()) {
			AddressValueRange<T> existing = entry.getValue();
			
			// If this range starts after our end, we're done
			if (existing.getStart().compareTo(end) > 0) {
				break;
			}
			
			// Check for actual overlap
			if (existing.getEnd().compareTo(start) >= 0) {
				toRemove.add(existing);
				
				// Handle partial overlaps - keep non-overlapping parts
				if (existing.getStart().compareTo(start) < 0) {
					// Part before cleared range
					try {
						toAdd.add(new AddressValueRange<T>(existing.getStart(), start.previous(), existing.getValue()));
					} catch (AddressOutOfBoundsException e) {
						// start is minimum address, no part before
					}
				}
				
				if (existing.getEnd().compareTo(end) > 0) {
					// Part after cleared range
					try {
						toAdd.add(new AddressValueRange<T>(end.next(), existing.getEnd(), existing.getValue()));
					} catch (AddressOutOfBoundsException e) {
						// end is maximum address, no part after
					}
				}
			}
		}
		
		// Remove overlapping ranges
		for (AddressValueRange<T> range : toRemove) {
			rangeMap.remove(range.getStart());
		}
		
		// Add back the non-overlapping fragments
		for (AddressValueRange<T> range : toAdd) {
			rangeMap.put(range.getStart(), range);
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

		Map.Entry<Address, AddressValueRange<T>> entry = rangeMap.floorEntry(address);
		if (entry == null) {
			return false;
		}
		
		lastRange = entry.getValue();
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

		// Use TreeMap's floorEntry to efficiently find the range that might contain this address
		Map.Entry<Address, AddressValueRange<T>> entry = rangeMap.floorEntry(address);
		if (entry == null) {
			return null;
		}
		
		lastRange = entry.getValue();
		if (lastRange.contains(address)) {
			return lastRange.getValue();
		}
		return null;
	}

	public boolean isEmpty() {
		return rangeMap.isEmpty();
	}

	class SimpleAddressRangeIterator implements AddressRangeIterator {
		private Iterator<AddressValueRange<T>> iterator;

		public SimpleAddressRangeIterator() {
			this.iterator = rangeMap.values().iterator();
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
			return iterator.hasNext();
		}

		@Override
		public AddressRange next() {
			AddressValueRange<T> valueRange = iterator.next();
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

	class RestrictedAddressRangeIterator implements AddressRangeIterator {
		private final Address start;
		private final Address end;
		private AddressRange nextRange;
		private final Iterator<AddressValueRange<T>> iterator;

		RestrictedAddressRangeIterator(Address start, Address end) {
			this.start = start;
			this.end = end;
			
			// Find the first range that could intersect with our range
			NavigableMap<Address, AddressValueRange<T>> subMap = rangeMap.tailMap(start, false);
			
			// Check if there's a range that starts before our start but might contain it
			Map.Entry<Address, AddressValueRange<T>> floorEntry = rangeMap.floorEntry(start);
			if (floorEntry != null && floorEntry.getValue().contains(start)) {
				// Create a new map that includes this range
				TreeMap<Address, AddressValueRange<T>> combinedMap = new TreeMap<>();
				combinedMap.put(floorEntry.getKey(), floorEntry.getValue());
				combinedMap.putAll(subMap);
				this.iterator = combinedMap.values().iterator();
			} else {
				this.iterator = subMap.values().iterator();
			}
			
			getNextRange();
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
			while (iterator.hasNext()) {
				AddressValueRange<T> range = iterator.next();
				
				// Skip ranges that start after our end
				if (range.getStart().compareTo(end) > 0) {
					break;
				}
				
				// Skip ranges that end before our start  
				if (range.getEnd().compareTo(start) < 0) {
					continue;
				}
				
				// Found an overlapping range - create the intersection
				Address intersectStart = getMax(range.getStart(), start);
				Address intersectEnd = getMin(range.getEnd(), end);
				nextRange = new AddressRangeImpl(intersectStart, intersectEnd);
				break;
			}
		}
	}

	/**
	 * Get the value or hole range containing the specified address
	 * @param addr the address
	 * @return the range containing the address (either a value range or a hole range)
	 */
	public AddressRange getAddressRangeContaining(Address addr) {
		if (lastRange != null && lastRange.contains(addr)) {
			return new AddressRangeImpl(lastRange.getStart(), lastRange.getEnd());
		}

		Address min = addr.getAddressSpace().getMinAddress();
		Address max = addr.getAddressSpace().getMaxAddress();

		Map.Entry<Address, AddressValueRange<T>> entry = rangeMap.floorEntry(addr);
		if (entry != null) {
			lastRange = entry.getValue();
			if (lastRange.getEnd().compareTo(addr) >= 0) {
				return new AddressRangeImpl(lastRange.getStart(), lastRange.getEnd());
			}
			if (min.getAddressSpace().equals(lastRange.getEnd().getAddressSpace())) {
				try {
					min = lastRange.getEnd().next();
				} catch (AddressOutOfBoundsException e) {
					// lastRange.getEnd() is max address, no hole after it
					return null;
				}
			}
		}
		
		Map.Entry<Address, AddressValueRange<T>> nextEntry = rangeMap.higherEntry(addr);
		if (nextEntry != null) {
			lastRange = nextEntry.getValue();
			if (max.getAddressSpace().equals(lastRange.getStart().getAddressSpace())) {
				try {
					max = lastRange.getStart().previous();
				} catch (AddressOutOfBoundsException e) {
					// lastRange.getStart() is min address, use max as is
				}
			}
		}
		
		return new AddressRangeImpl(min, max);
	}
}

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
