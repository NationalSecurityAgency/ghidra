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
package ghidra.program.database.util;

import java.io.IOException;
import java.util.*;

import db.DBRecord;
import db.RecordIterator;
import ghidra.program.database.map.AddressKeyRecordIterator;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.*;
import ghidra.util.Lock;

/**
 * An iterator over ranges that have a defined values in the AddressRangeMapDB
 * <P>
 * NOTE: this iterator is complicated by the fact that there can exist a record that represents
 * an address range that "wraps around" from the max address to the 0 address, where this record
 * actually represents two address ranges. This is cause by changing the image base which shifts
 * all records up or down. That shift can cause a record to have a wrapping range where the start
 * address is larger than the end address. If such a record exists, it is found during construction
 * and the lower address range is extracted from the record and is stored as a special "start range"
 * that should be emitted before any other ranges in that space. The upper range of a wrapping
 * record will be handled more naturally during the iteration process. When a wrapping record is
 * encountered during the normal iteration, only the upper range is used and it will be in the
 * correct address range ordering.
 */
class AddressRangeMapIterator implements AddressRangeIterator {

	private AddressRangeMapDB rangeMap;
	private AddressMap addressMap;
	private Lock lock;
	private int expectedModCount;

	private DBRecord nextRecord;
	private RecordIterator recordIterator;

	// this is the range from a wrapping address record that needs to be emitted before any other
	// ranges in the default space. It is discovered during construction if it exists
	private AddressRange startRange;

	// these will be null if iterating over all records
	private Address iteratorStart;
	private Address iteratorEnd;

	/**
	 * Constructs an AddressRangeIterator over all ranges that have a defined value
	 * @param rangeMap the AddressRangeMapDB to iterate over
	 * @throws IOException if a database I/O exception occurs
	 */
	AddressRangeMapIterator(AddressRangeMapDB rangeMap) throws IOException {
		this.rangeMap = rangeMap;
		this.lock = rangeMap.getLock();
		this.addressMap = rangeMap.getAddressMap();
		this.expectedModCount = rangeMap.getModCount();
		this.recordIterator = new AddressKeyRecordIterator(rangeMap.getTable(), addressMap);
		startRange = checkForStartRangeFromWrappingAddressRecord();
	}

	/**
	 * Constructs an AddressRangeIterator over all ranges greater than the given start address
	 * that have a defined value. If start is in the middle of a defined range, the first
	 * range will be truncated to start with the given start address.
	 * @param rangeMap the AddressRangeMapDB to iterate over
	 * @param start the address where the iterator should start
	 * @throws IOException if a database I/O exception occurs
	 */
	AddressRangeMapIterator(AddressRangeMapDB rangeMap, Address start) throws IOException {
		this(rangeMap, start, null);
	}

	/**
	 * Constructs an AddressRangeIterator over all ranges between the given start address and the
	 * given end address that have a defined value. If start is in the middle of a defined range,
	 * the first range returned will truncated to start with the given start address. 
	 * If the endAddress is in the middle of a defined range, the last range will be truncated to
	 * end with the given end address
	 * @param rangeMap the AddressRangeMapDB to iterate over
	 * @param start the address where the iterator should start
	 * @param end the address where the iterator should end
	 * @throws IOException if a database I/O exception occurs
	 */
	AddressRangeMapIterator(AddressRangeMapDB rangeMap, Address start, Address end)
			throws IOException {
		this.rangeMap = rangeMap;
		this.lock = rangeMap.getLock();
		this.addressMap = rangeMap.getAddressMap();
		this.expectedModCount = rangeMap.getModCount();
		this.iteratorStart = start;
		this.iteratorEnd = getIteratorEnd(end);

		// adjust start address to start of previous range if it contains this address
		// so the iterator will include it
		AddressRange range = rangeMap.getAddressRangeContaining(iteratorStart);
		this.recordIterator = new AddressKeyRecordIterator(rangeMap.getTable(), addressMap,
			range.getMinAddress(), iteratorEnd, range.getMinAddress(), true);

		startRange = trimRange(checkForStartRangeFromWrappingAddressRecord());
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return this;
	}

	@Override
	public boolean hasNext() {
		lock.acquire();
		try {
			if (expectedModCount != rangeMap.getModCount()) {
				throw new ConcurrentModificationException();
			}
			if (nextRecord != null) {
				return true;
			}
			if (startRange != null) {
				return true;
			}
			if (recordIterator != null) {
				try {
					return recordIterator.hasNext();
				}
				catch (IOException e) {
					rangeMap.dbError(e);
				}
			}
			return false;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public AddressRange next() {
		lock.acquire();
		try {
			if (expectedModCount != rangeMap.getModCount()) {
				throw new ConcurrentModificationException();
			}
			if (nextRecord != null) {
				DBRecord record = nextRecord;
				nextRecord = null;
				return getAddressRange(record);
			}
			if (recordIterator == null || !recordIterator.hasNext()) {
				if (startRange != null) {
					// there are no more items in the underlying iterator, so if we have a 
					// discovered start range, as described in the class header, then return that
					AddressRange range = startRange;
					startRange = null;
					return range;
				}
				return null;
			}
			return getAddressRange(recordIterator.next());
		}
		catch (IOException e) {
			rangeMap.dbError(e);
			return null;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Computes an address range for the given record. If a wrapping record (a record whose start
	 * address is greater than its end address, so it really represents two ranges) is encountered,
	 * it only returns the high range. The low range is specially found in the constructor and 
	 * returned before any other ranges in that same address space are returned.
	 * @param record the record to convert to an address range
	 * @return the address range represented by the given record
	 */
	private AddressRange getAddressRange(DBRecord record) {
		List<AddressRange> ranges = rangeMap.getRangesForRecord(record);
		if (ranges.isEmpty()) {
			return null;
		}

		// Normally, there is only one range for a record. If it is an address wrapping record
		// caused by an image base change, then the record will produce two ranges. While iterating
		// we always want the last (higher) range. 
		AddressRange range = ranges.get(ranges.size() - 1);

		// if there is a "start range" discovered in the constructor and this is the first
		// range we see in the default space (the space with image base), then we need to return
		// the start range and save this record for next time.
		if (startRange != null && hasSameSpace(startRange.getMinAddress(), range.getMinAddress())) {
			range = startRange;
			startRange = null;

			// save current record into next record so we process it again next time
			nextRecord = record;
		}

		return trimRange(range);
	}

	private boolean hasSameSpace(Address address1, Address address2) {
		AddressSpace space1 = address1.getAddressSpace();
		AddressSpace space2 = address2.getAddressSpace();
		return space1.equals(space2);
	}

	/**
	 * Look for a start range that needs to be issued before any other ranges in the default
	 * space.
	 * <P> 
	 * Because of a changed image base, it is possible that a single record can represent
	 * multiple ranges, as described in the class header. This is the code that will look for that
	 * case and correct the ordering.
	 *  
	 * @return the start range that needs to be issued before any other ranges in this space. 
	 * @throws IOException if a database I/O error occurs
	 */
	private AddressRange checkForStartRangeFromWrappingAddressRecord()
			throws IOException {

		DBRecord record = rangeMap.getAddressWrappingRecord();
		if (record == null) {
			return null;
		}

		List<AddressRange> ranges = rangeMap.getRangesForRecord(record);
		// we want the lower range - the upper range will be handle later during iteration
		return ranges.get(0);
	}

	private Address getIteratorEnd(Address end) {
		if (end != null) {
			return end;	// non-null end was supplied, use that
		}
		AddressFactory factory = addressMap.getAddressFactory();
		AddressSet allAddresses = factory.getAddressSet();
		return allAddresses.getMaxAddress();
	}

	/**
	 * Make sure the range is within the iterator's given start and end range. This really only
	 * matters for the first and last range returned by the iterator, but it hard to know when
	 * the given range is the first or last, just just trim all returned ranges.
	 * @param range the range to be trimmed
	 * @return the trimmed address range
	 */
	private AddressRange trimRange(AddressRange range) {
		if (range == null) {
			return null;
		}
		// if no iterator bounds set, no trimming needed
		if (iteratorStart == null) {
			return range;
		}

		if (range.compareTo(iteratorStart) > 0 && range.compareTo(iteratorEnd) < 0) {
			return range;
		}

		Address start = Address.max(range.getMinAddress(), iteratorStart);
		Address end = Address.min(range.getMaxAddress(), iteratorEnd);
		if (start.compareTo(end) <= 0) {
			return new AddressRangeImpl(start, end);
		}
		return null;
	}

}
