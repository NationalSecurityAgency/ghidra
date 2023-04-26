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
import java.util.ArrayList;
import java.util.List;

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.map.AddressKeyRecordIterator;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.*;
import ghidra.util.Lock;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * <code>AddressRangeMapDB</code> provides a generic value range map backed by a database table.
 * Values can be stored for ranges of addresses. When a value is stored for a range, it replaces
 * any previous values for that range. It is kind of like painting. If you first paint a region
 * red, but then later paint a region in the middle of the red region green, you end up with
 * three regions - a green region surrounded by two red regions.
 * <P>
 * This is implemented by storing records for each contiguous range with the same value.
 * <ul>
 * 		<li>The key is the encoded start address of the range.
 * 		<li>The TO_COL column of the record stores the encoded end address of the range.
 * 		<li>The VALUE_COL column of the record stores the value for the range.
 * </ul>
 * <P>
 * This implementation is complicated by several issues. 
 * <ol>
 * 	   <li>Addresses stored in Ghidra database records are encoded as long keys (see 
 * 		  {@link AddressMap}). 
 * 		  Encoded addresses do not necessarily encode to keys that have the same ordering. 
 * 	      Therefore, all comparisons must be done in address space and not in the encoded space.
 * 		  Also, record iterators must use the {@link AddressKeyRecordIterator} which will return
 * 		  records in address order versus encoded key order.
 *     <li>The default space's image base can be changed after records have been created. This can
 *        cause the address ranges represented by a record to wrap around. For example, suppose
 *        the image base is 0 and you paint a range from address 0 to 0x20, which say maps to
 *        keys 0 and 20, respectively. Now suppose the image base changes to 0xfffffffe, which 
 *        means key 0 maps to address 0xfffffffe and key 0x20 maps to address 0x1e,(the addresses
 *        have been effectively shifted down by 2). So now the stored record has a start key of
 *        0 and an end key of 0x20 which now maps to start address of 0xfffffffe and an end 
 *        address of 0x1e. For our purposes, it is important that we don't just flip the start
 *        and end address which be a very large range instead of a small range. Instead, we need 
 *        to interpret that as 2 ranges (0xfffffffe - 0xffffffff) and (0 - 0x1e). So all methods
 *        in this class have be coded to handle this special case. To simplify the painting
 *        logic, any wrapping record will first be split into two records before painting. However
 *        we can only do this during a write operation (when we can make changes). Since the getter
 *        methods and iterators cannot modify the database, they have to deal with wrapping
 *        records on the fly.
 */
public class AddressRangeMapDB implements DBListener {
	public static final String RANGE_MAP_TABLE_PREFIX = "Range Map - ";
	static final int TO_COL = 0;
	static final int VALUE_COL = 1;
	private static final String[] COLUMN_NAMES = new String[] { "To", "Value" };
	private static final int[] INDEXED_COLUMNS = new int[] { VALUE_COL };

	private final DBHandle dbHandle;
	private final AddressMap addressMap;
	private final ErrorHandler errHandler;
	private final Field valueField;
	private final boolean indexed;
	private final Lock lock;

	private String tableName;
	private Schema rangeMapSchema;
	private Table rangeMapTable;

	// caching
	private Field lastValue;
	private AddressRange lastRange;

	private int modCount;

	// we only need to check for wrapping record first time we paint or if the image base changes
	private boolean alreadyCheckedForWrappingRecord = false;

	/**
	 * Construct a generic range map
	 * @param dbHandle database handle
	 * @param addressMap the address map 
	 * @param lock the program lock
	 * @param name map name used in naming the underlying database table
	 * This name must be unique across all range maps
	 * @param errHandler database error handler
	 * @param valueField specifies the type for the values stored in this map
	 * @param indexed if true, values will be indexed allowing use of the 
	 * getValueRangeIterator method
	 */
	public AddressRangeMapDB(DBHandle dbHandle, AddressMap addressMap, Lock lock, String name,
			ErrorHandler errHandler, Field valueField, boolean indexed) {
		this.dbHandle = dbHandle;
		this.addressMap = addressMap;
		this.lock = lock;
		this.errHandler = errHandler;
		this.valueField = valueField;
		this.indexed = indexed;
		tableName = RANGE_MAP_TABLE_PREFIX + name;
		findTable();
		dbHandle.addListener(this);
	}

	/**
	 * Tests if an AddressRangeMap table exists with the given name
	 * @param dbHandle the database handle
	 * @param name the name to test for
	 * @return true if the a table exists for the given name
	 */
	public static boolean exists(DBHandle dbHandle, String name) {
		return dbHandle.getTable(RANGE_MAP_TABLE_PREFIX + name) != null;
	}

	/**
	 * Set the name associated with this range map
	 * @param newName the new name for this range map
	 * @return true if successful, else false
	 * @throws DuplicateNameException if there is already range map with that name
	 */
	public boolean setName(String newName) throws DuplicateNameException {
		String newTableName = RANGE_MAP_TABLE_PREFIX + newName;
		if (rangeMapTable == null || rangeMapTable.setName(newTableName)) {
			tableName = newTableName;
			return true;
		}
		return false;
	}

	/**
	 * Returns true if this map is empty
	 * @return true if this map is empty
	 */
	public boolean isEmpty() {
		lock.acquire();
		try {
			return rangeMapTable == null || rangeMapTable.getRecordCount() == 0;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Returns the number of records contained within this map.
	 * NOTE: This number will be greater or equal to the number of
	 * address ranges contained within the map.
	 * @return record count
	 */
	public int getRecordCount() {
		return rangeMapTable != null ? rangeMapTable.getRecordCount() : 0;
	}

	/**
	 * Returns the value associated with the given address
	 * @param address the address of the value
	 * @return value or null no value exists
	 */
	public Field getValue(Address address) {
		lock.acquire();
		try {
			if (rangeMapTable == null) {
				return null;
			}
			// check last cached range
			if (lastRange != null && lastRange.contains(address)) {
				return lastValue;
			}

			DBRecord record = findRecordContaining(address);
			List<AddressRange> ranges = getRangesForRecord(record);
			for (AddressRange range : ranges) {
				if (range.contains(address)) {
					lastRange = range;
					lastValue = record.getFieldValue(VALUE_COL);
					return lastValue;
				}
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	/**
	 * Associates the given value with every address from start to end (inclusive)
	 * Any previous associates are overwritten. 
	 * @param startAddress the start address.
	 * @param endAddress the end address.
	 * @param value value to be painted, or null for value removal.
	 * @throws IllegalArgumentException if the start and end addresses are not in the same
	 * address space
	 * @throws IllegalArgumentException if the end address is greater then the start address
	 */
	public void paintRange(Address startAddress, Address endAddress, Field value) {
		if (!startAddress.hasSameAddressSpace(endAddress)) {
			throw new IllegalArgumentException("Addresses must be in the same space!");
		}
		if (startAddress.compareTo(endAddress) > 0) {
			throw new IllegalArgumentException("Start address must be <= end address!");
		}

		lock.acquire();
		try {
			clearCache();
			++modCount;

			if (rangeMapTable == null) {
				if (value == null) {
					return;
				}
				createTable();
			}
			doPaintRange(startAddress, endAddress, value);
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
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
		if (length <= 0 || rangeMapTable == null) {
			return;
		}

		DBHandle tmpDb = null;
		AddressRangeMapDB tmpMap = null;
		lock.acquire();
		try {
			tmpDb = dbHandle.getScratchPad();
			tmpMap = new AddressRangeMapDB(tmpDb, addressMap, lock, "TEMP", errHandler, valueField,
				indexed);

			Address fromEndAddr = fromAddr.add(length - 1);
			for (AddressRange range : getAddressRanges(fromAddr, fromEndAddr)) {
				monitor.checkCancelled();

				Address minAddr = range.getMinAddress();
				Field value = getValue(minAddr);
				long offset = minAddr.subtract(fromAddr);
				minAddr = toAddr.add(offset);

				Address maxAddr = range.getMaxAddress();
				offset = maxAddr.subtract(fromAddr);
				maxAddr = toAddr.add(offset);

				tmpMap.paintRange(minAddr, maxAddr, value);
			}
			clearRange(fromAddr, fromEndAddr);
			for (AddressRange range : tmpMap.getAddressRanges()) {
				monitor.checkCancelled();
				Field value = tmpMap.getValue(range.getMinAddress());
				paintRange(range.getMinAddress(), range.getMaxAddress(), value);
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			if (tmpMap != null) {
				try {
					tmpDb.deleteTable(tmpMap.tableName);
				}
				catch (IOException e) {
					// ignore
				}
			}
			lock.release();
		}
	}

	/**
	 * Remove values from the given range.
	 * @param startAddr the start address.
	 * @param endAddr the end address.
	 */
	public void clearRange(Address startAddr, Address endAddr) {
		paintRange(startAddr, endAddr, null);
	}

	/**
	 * Returns set of addresses where a values has been set 
	 * @return set of addresses where a values has been set
	 */
	public AddressSet getAddressSet() {
		lock.acquire();
		try {
			AddressSet set = new AddressSet();
			AddressRangeIterator addressRanges = getAddressRanges();
			for (AddressRange addressRange : addressRanges) {
				set.add(addressRange);
			}
			return set;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Returns set of addresses where the given value has been set
	 * @param value the value to search for
	 * @return set of addresses where the given value has been set
	 */
	public AddressSet getAddressSet(Field value) {
		AddressSet set = new AddressSet();
		if (rangeMapTable == null) {
			return set;
		}
		lock.acquire();
		try {
			RecordIterator it = rangeMapTable.indexIterator(VALUE_COL, value, value, true);
			while (it.hasNext()) {
				DBRecord record = it.next();
				List<AddressRange> rangesForRecord = getRangesForRecord(record);
				rangesForRecord.forEach(r -> set.addRange(r.getMinAddress(), r.getMaxAddress()));
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return set;
	}

	/**
	 * Returns an address range iterator over all ranges in the map where a value has been set
	 * @return AddressRangeIterator that iterates over all occupied ranges in the map
	 */
	public AddressRangeIterator getAddressRanges() {
		if (rangeMapTable == null) {
			return new EmptyAddressRangeIterator();
		}
		try {
			return new AddressRangeMapIterator(this);
		}
		catch (IOException e) {
			dbError(e);
			return null;
		}
	}

	/**
	 * Returns an address range iterator over all ranges in the map where a value has been set
	 * starting with the given address
	 * @param startAddress The address at which to start iterating ranges
	 * @return AddressRangeIterator that iterates over all occupied ranges in the map from the
	 * given start address
	 */
	public AddressRangeIterator getAddressRanges(Address startAddress) {
		if (rangeMapTable == null) {
			return new EmptyAddressRangeIterator();
		}
		try {
			return new AddressRangeMapIterator(this, startAddress);
		}
		catch (IOException e) {
			dbError(e);
			return null;
		}
	}

	/**
	 * Returns an address range iterator over all ranges in the map where a value has been set
	 * starting with the given address and ending with the given end address
	 * @param startAddress the address at which to start iterating ranges
	 * @param endAddr the address at which to end the iterator
	 * @return AddressRangeIterator that iterates over all occupied ranges in the map from the
	 * given start address
	 */
	public AddressRangeIterator getAddressRanges(Address startAddress, Address endAddr) {
		if (rangeMapTable == null) {
			return new EmptyAddressRangeIterator();
		}
		try {
			return new AddressRangeMapIterator(this, startAddress, endAddr);
		}
		catch (IOException e) {
			dbError(e);
			return null;
		}
	}

	@Override
	public void dbRestored(DBHandle dbh) {
		lock.acquire();
		try {
			clearCache();
			findTable();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void dbClosed(DBHandle dbh) {
		// do nothing
	}

	@Override
	public void tableDeleted(DBHandle dbh, Table table) {
		if (table == rangeMapTable) {
			lock.acquire();
			try {
				clearCache();
				rangeMapTable = null;
			}
			finally {
				lock.release();
			}
		}
	}

	@Override
	public void tableAdded(DBHandle dbh, Table table) {
		if (tableName.equals(table.getName())) {
			rangeMapTable = table;
		}
	}

	/**
	 * Deletes the database table used to store this range map.
	 */
	public void dispose() {
		lock.acquire();
		try {
			if (rangeMapTable != null) {
				try {
					dbHandle.deleteTable(tableName);
				}
				catch (IOException e) {
					errHandler.dbError(e);
				}
				clearCache();
				rangeMapTable = null;
			}
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Notification that that something may have changed (undo/redo/image base change) and we need
	 * to invalidate our cache and possibly have a wrapping record again.
	 */
	public void invalidate() {
		lock.acquire();
		try {
			clearCache();
			alreadyCheckedForWrappingRecord = false;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Returns the bounding address range for the given address where all addresses in that
	 * range have the same value (this also works for now value. i.e finding a gap)
	 * @param address the address to find a range for
	 * @return an address range that contains the given address and has all the same value
	 */
	public AddressRange getAddressRangeContaining(Address address) {

		lock.acquire();
		try {
			// check cache
			if (lastRange != null && lastRange.contains(address)) {
				return lastRange;
			}

			// look for a stored value range that contains that address
			AddressRange range = findValueRangeContainingAddress(address);
			if (range == null) {
				// so the address doesn't have a value, find its containing gap range
				range = findGapRange(address);
			}
			return range;
		}
		catch (IOException e) {
			dbError(e);
			return null;
		}
		finally {
			lock.release();
		}
	}

	private AddressRange findValueRangeContainingAddress(Address address) throws IOException {
		DBRecord record = findRecordContaining(address);
		List<AddressRange> rangesForRecord = getRangesForRecord(record);
		for (AddressRange range : rangesForRecord) {
			if (range.contains(address)) {
				lastRange = range;
				lastValue = record.getFieldValue(VALUE_COL);
				return range;
			}
		}
		return null;
	}

	// note this method assumes the address has already been determined to not be in 
	// a range that has a value
	private AddressRange findGapRange(Address address) throws IOException {
		// initialize to entire address space
		Address gapStart = address.getAddressSpace().getMinAddress();
		Address gapEnd = address.getAddressSpace().getMaxAddress();

		// adjust if there is a wrapping record
		if (address.hasSameAddressSpace(addressMap.getImageBase())) {
			DBRecord wrappingRecord = getAddressWrappingRecord();
			if (wrappingRecord != null) {
				// if there is a wrapping address, subtract those ranges from our defaults
				gapStart = getEndAddress(wrappingRecord).add(1);
				gapEnd = getStartAddress(wrappingRecord).subtract(1);
			}
		}

		// if previous record exists, then gap start is really one past the end of that range
		DBRecord record = getRecordAtOrBefore(address);
		if (record != null) {
			Address endAddress = getEndAddress(record);
			if (endAddress.hasSameAddressSpace(address) && endAddress.compareTo(address) < 0) {
				gapStart = endAddress.add(1);
			}
		}

		// if a follow on record exists in our space, then gap end will be just before this range
		record = getRecordAfter(address);
		if (record != null) {
			Address startAddress = getStartAddress(record);
			if (startAddress.hasSameAddressSpace(address) &&
				startAddress.compareTo(address) > 0) {
				gapEnd = startAddress.subtract(1);
			}
		}

		return new AddressRangeImpl(gapStart, gapEnd);
	}

	/**
	 * Returns a list of AddressRanges that this record represents. This record's key is the 
	 * encoded start key and it "TO_COL" has the end address key. But since a non-zero image base
	 * can cause that key range to be backwards in address space which means it represents a range
	 * that starts in the upper addresses and then "wraps" to a lower address, resulting in two
	 * address ranges, one and the bottom of the address space and one at the top of the address
	 * space.
	 * @param record a record that represents a contiguous range (in key space) of same values 
	 * @return a list of AddressRanges that this record represents.
	 */
	List<AddressRange> getRangesForRecord(DBRecord record) {
		List<AddressRange> ranges = new ArrayList<>(2);
		if (record == null) {
			return ranges;
		}
		Address start = addressMap.decodeAddress(record.getKey());
		Address end = addressMap.decodeAddress(record.getLongValue(TO_COL));
		if (start.compareTo(end) <= 0) {
			ranges.add(new AddressRangeImpl(start, end));
		}
		else {
			// the key range spans the address boundary because of non zero image base
			// so this record represents two address ranges, one at the start and one at the end
			AddressSpace space = start.getAddressSpace();
			ranges.add(new AddressRangeImpl(space.getMinAddress(), end));
			ranges.add(new AddressRangeImpl(start, space.getMaxAddress()));
		}

		return ranges;
	}

	private void doPaintRange(Address paintStart, Address paintEnd, Field value)
			throws IOException {
		// Eliminating wrapping records makes the following logic much simpler
		splitAddressWrappingRecordIfExists();

		// examine the record before start to see if it merges with or is truncated by the new range
		paintStart = checkRecordBeforeRange(paintStart, paintEnd, value);
		if (paintStart == null) {
			// a returned null startAddr means the new range is already painted with that value
			return;
		}

		// eliminate ranges that are being painted over. Last range may need to be truncated
		paintEnd = fixupIntersectingRecords(paintStart, paintEnd, value);

		// see if there is a range just after this range that can be merged
		paintEnd = possiblyMergeWithNextRecord(paintEnd, value);

		// insert new range entry if value was specified, otherwise this was really a delete
		if (value != null) {
			createRecord(paintStart, paintEnd, value);
		}

		// remove table if empty
		if (rangeMapTable.getRecordCount() == 0) {
			dbHandle.deleteTable(tableName);
			rangeMapTable = null;
		}
	}

	private void splitAddressWrappingRecordIfExists() throws IOException {
		if (alreadyCheckedForWrappingRecord) {
			return;
		}
		alreadyCheckedForWrappingRecord = true;

		DBRecord wrappingRecord = getAddressWrappingRecord();
		if (wrappingRecord == null) {
			return;
		}

		List<AddressRange> ranges = getRangesForRecord(wrappingRecord);

		if (ranges.size() != 2) {
			throw new AssertException("wrapping records should have two ranges!");
		}

		Field value = getValue(wrappingRecord);

		// replace wrapping record with two non wrapping records
		rangeMapTable.deleteRecord(wrappingRecord.getKey());
		createRecord(ranges.get(0), value);
		createRecord(ranges.get(1), value);

	}

	/**
	 * Checks the record before our paint to see how it is affected. Returns a possible new start
	 * address for our paint if it gets merged. Returns null if it turns out we don't need to
	 * paint at all.
	 * 
	 * @param paintStart the start of the paint range
	 * @param paintEnd the end of the paint range
	 * @param value the value to associate with the range
	 * @return a new start address for the paint or null if we don't need to paint at all
	 * @throws IOException if a database I/O exception occurs
	 */
	private Address checkRecordBeforeRange(Address paintStart, Address paintEnd, Field value)
			throws IOException {
		DBRecord record = getRecordBefore(paintStart);
		if (record == null) {
			return paintStart;
		}

		Address recordStart = getStartAddress(record);
		Address recordEnd = getEndAddress(record);
		Field recordValue = getValue(record);

		// if the previous record is in different address space, nothing to do, start doesn't change
		if (!recordEnd.hasSameAddressSpace(paintStart)) {
			return paintStart;
		}

		// if it has the same value as the new record, there are 3 cases:
		// 		the previous range extends past new range -> no need to paint the new range at all
		// 	    the previous range ends just before or into the new range -> delete old range and make new range 
		//				have previous range start
		// 		the previous range ends before this range -> no effect just leave the start the same
		if (recordValue.equals(value)) {
			// see if existing range already completely covers new range.
			if (recordEnd.compareTo(paintEnd) >= 0) {
				// return null to indicate no painting is needed
				return null;
			}

			if (recordEnd.isSuccessor(paintStart) || paintStart.compareTo(recordEnd) <= 0) {
				// otherwise, merge by deleting previous record and changing start to record's start
				rangeMapTable.deleteRecord(record.getKey());
				return recordStart;
			}
			// otherwise previous range is completely before, so has no effect
			return paintStart;
		}

		// different values, 3 cases to deal with
		// 	case 1: the previous range is before the new range -> do nothing
		//	case 2: the previous range ends inside the new range -> truncate previous range
		//  case 3: the previous range extends past the new range -> truncate previous ragne and
		// 			create a new region past where we are now painting

		// case 1, previous range is completely before new range, so nothing to do
		if (recordEnd.compareTo(paintStart) < 0) {
			return paintStart;
		}

		// in case 2 or 3 we need to truncate the previous record
		record.setLongValue(TO_COL, addressMap.getKey(paintStart.subtract(1), true));
		rangeMapTable.putRecord(record);

		// in case 3, we need to create a new record for the part of the previous record that
		// extends past our new range
		if (recordEnd.compareTo(paintEnd) > 0) {
			createRecord(paintEnd.add(1), recordEnd, recordValue);
		}

		return paintStart;
	}

	/**
	 * Removes any records that are being painted over and maybe merges with or truncates the
	 * last record that starts in our paint range
	 * @param startAddr the start of the paint range
	 * @param endAddr the end of the paint range
	 * @param value the value we are painting
	 * @return the new end address for our paint. if we find a record with our value that
	 * extends past our end, we delete it and extend our end range.
	 * @throws IOException if a database I/O error occurs
	 */
	private Address fixupIntersectingRecords(Address startAddr, Address endAddr, Field value)
			throws IOException {
		RecordIterator it = new AddressKeyRecordIterator(rangeMapTable, addressMap, startAddr,
			endAddr, startAddr, true);

		while (it.hasNext()) {
			DBRecord record = it.next();
			it.delete(); // all the records that start in the paint region need to be deleted
			Address recordEndAddress = getEndAddress(record);
			if (recordEndAddress.compareTo(endAddr) > 0) {
				Field recordValue = getValue(record);
				if (recordValue.equals(value)) {
					// since the last record has same value, it extends our paintRange
					return recordEndAddress;
				}
				// the last record extended past the paint range with a different value,
				// create a remainder record
				createRecord(endAddr.add(1), recordEndAddress, recordValue);
			}
		}
		return endAddr;

	}

	/**
	 * checks if there is a record just past our paint region that we can merge with. If we find
	 * one, delete it and adjust our end address to its end address
	 * @param endAddr the end of our paint region
	 * @param value the value we are painting
	 * @return the new end address for our paint
	 */
	private Address possiblyMergeWithNextRecord(Address endAddr, Field value) throws IOException {
		if (endAddr.equals(endAddr.getAddressSpace().getMaxAddress())) {
			// if the end is already the max, then no need to check for  follow-on record
			return endAddr;
		}
		Address next = endAddr.add(1);
		DBRecord record = rangeMapTable.getRecord(addressMap.getKey(next, false));
		if (record != null && getValue(record).equals(value)) {
			rangeMapTable.deleteRecord(record.getKey());
			return getEndAddress(record);
		}
		return endAddr;
	}

	/** 
	 * Clears the "last range" cache
	 */
	private void clearCache() {
		lock.acquire();
		try {
			lastRange = null;
			lastValue = null;
		}
		finally {
			lock.release();
		}
	}

	DBRecord getAddressWrappingRecord() throws IOException {
		Address maxAddress = addressMap.getImageBase().getAddressSpace().getMaxAddress();
		DBRecord record = getRecordAtOrBefore(maxAddress);
		if (record == null) {
			return null;
		}

		Address start = getStartAddress(record);
		Address end = getEndAddress(record);

		// a wrapping record's end will be before its start
		if (start.compareTo(end) > 0) {
			return record;
		}

		return null;
	}

	private Address getStartAddress(DBRecord record) {
		return addressMap.decodeAddress(record.getKey());
	}

	private Field getValue(DBRecord record) {
		return record.getFieldValue(VALUE_COL);
	}

	private Address getEndAddress(DBRecord record) {
		return addressMap.decodeAddress(record.getLongValue(TO_COL));
	}

	private void createRecord(AddressRange range, Field value) throws IOException {
		createRecord(range.getMinAddress(), range.getMaxAddress(), value);
	}

	private void createRecord(Address startAddr, Address endAddr, Field value) throws IOException {
		long start = addressMap.getKey(startAddr, true);
		long end = addressMap.getKey(endAddr, true);
		DBRecord rec = rangeMapSchema.createRecord(start);
		rec.setLongValue(TO_COL, end);
		rec.setField(VALUE_COL, value);
		rangeMapTable.putRecord(rec);
	}

	private DBRecord findRecordContaining(Address address) throws IOException {
		DBRecord record = getRecordAtOrBefore(address);
		if (recordContainsAddress(record, address)) {
			return record;
		}
		record = getAddressWrappingRecord();
		if (recordContainsAddress(record, address)) {
			return record;
		}
		return null;
	}

	private boolean recordContainsAddress(DBRecord record, Address address) {
		List<AddressRange> rangesForRecord = getRangesForRecord(record);
		for (AddressRange addressRange : rangesForRecord) {
			if (addressRange.contains(address)) {
				return true;
			}
		}
		return false;
	}

	private DBRecord getRecordAfter(Address address) throws IOException {
		if (rangeMapTable == null) {
			return null;
		}
		RecordIterator it = new AddressKeyRecordIterator(rangeMapTable, addressMap, address, true);
		if (it.hasNext()) {
			return it.next();
		}
		return null;
	}

	private DBRecord getRecordAtOrBefore(Address address) throws IOException {
		if (rangeMapTable == null) {
			return null;
		}
		RecordIterator it = new AddressKeyRecordIterator(rangeMapTable, addressMap, address, false);
		if (it.hasPrevious()) {
			return it.previous();
		}
		return null;
	}

	private DBRecord getRecordBefore(Address address) throws IOException {
		if (rangeMapTable == null) {
			return null;
		}
		RecordIterator it = new AddressKeyRecordIterator(rangeMapTable, addressMap, address, true);
		if (it.hasPrevious()) {
			return it.previous();
		}
		return null;
	}

	private void findTable() {
		rangeMapTable = dbHandle.getTable(tableName);
		if (rangeMapTable != null) {
			rangeMapSchema = rangeMapTable.getSchema();
			Field[] fields = rangeMapSchema.getFields();
			if (fields.length != 2 || !fields[VALUE_COL].isSameType(valueField)) {
				errHandler.dbError(
					new IOException("Existing range map table has unexpected value class"));
			}
			if (indexed) {
				int[] indexedCols = rangeMapTable.getIndexedColumns();
				if (indexedCols.length != 1 || indexedCols[0] != VALUE_COL) {
					errHandler.dbError(new IOException("Existing range map table is not indexed"));
				}
			}
		}
	}

	private void createTable() throws IOException {
		rangeMapSchema =
			new Schema(0, "From", new Field[] { LongField.INSTANCE, valueField }, COLUMN_NAMES);
		if (indexed) {
			rangeMapTable = dbHandle.createTable(tableName, rangeMapSchema, INDEXED_COLUMNS);
		}
		else {
			rangeMapTable = dbHandle.createTable(tableName, rangeMapSchema);
		}
	}

	AddressMap getAddressMap() {
		return addressMap;
	}

	Table getTable() {
		return rangeMapTable;
	}

	Lock getLock() {
		return lock;
	}

	int getModCount() {
		return modCount;
	}

	void dbError(IOException e) {
		Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		errHandler.dbError(e);
	}

}
