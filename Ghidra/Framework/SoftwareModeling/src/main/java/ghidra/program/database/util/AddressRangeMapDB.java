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
import java.util.ConcurrentModificationException;
import java.util.Iterator;

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.map.AddressKeyRecordIterator;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.*;
import ghidra.util.Lock;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>RangeMapDB</code> provides a generic value range map backed by a database table.
 * A given range may be occupied by at most a single value which is painted over 
 * that range.
 */
public class AddressRangeMapDB implements DBListener {

	private String tableName;
	private DBHandle dbHandle;
	private AddressMap addrMap;
	private ErrorHandler errHandler;
	private Field valueField;
	private boolean indexed;
	private Table rangeMapTable;
	private Schema rangeMapSchema;

	private Address lastStart;
	private Address lastEnd;
	private Field lastValue;
	private AddressRange lastRange;

	private int modCount;

	public static final String RANGE_MAP_TABLE_PREFIX = "Range Map - ";

	// Column for Range Map table (key is the From value)
	private static final int TO_COL = 0;
	private static final int VALUE_COL = 1;

	private static final String[] COLUMN_NAMES = new String[] { "To", "Value" };
	private static final int[] INDEXED_COLUMNS = new int[] { VALUE_COL };
	private final Lock lock;

	/**
	 * Construct a generic range map.
	 * @param dbHandle database handle.
	 * @param name map name used in naming the underlying database table.  
	 * This name must be unique across all range maps.
	 * @param errHandler database error handler.
	 * @param valueField Field to be used for stored values.
	 * @param indexed if true, values will be indexed allowing use of the 
	 * getValueRangeIterator method.
	 */
	public AddressRangeMapDB(DBHandle dbHandle, AddressMap addrMap, Lock lock, String name,
			ErrorHandler errHandler, Field valueField, boolean indexed) {
		this.dbHandle = dbHandle;
		this.addrMap = addrMap;
		this.lock = lock;
		this.errHandler = errHandler;
		this.valueField = valueField;
		this.indexed = indexed;
		tableName = RANGE_MAP_TABLE_PREFIX + name;
		findTable();
		dbHandle.addListener(this);
	}

	/**
	 * Set the name associated with this range map.
	 * @param newName
	 * @return true if successful, else false
	 * @throws DuplicateNameException
	 */
	public boolean setName(String newName) throws DuplicateNameException {
		String newTableName = RANGE_MAP_TABLE_PREFIX + newName;
		if (rangeMapTable == null || rangeMapTable.setName(newTableName)) {
			tableName = newTableName;
			return true;
		}
		return false;
	}

	public static boolean exists(DBHandle dbHandle, String name) {
		return dbHandle.getTable(RANGE_MAP_TABLE_PREFIX + name) != null;
	}

	/**
	 * Returns true if this map is empty
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

	/**
	 * Returns the value associated with the given address.
	 * @param addr the address of the value
	 * @return value or null no value exists
	 */
	public Field getValue(Address addr) {
		lock.acquire();
		try {
			if (rangeMapTable != null) {
				if (lastStart != null && addr.compareTo(lastStart) >= 0 &&
					addr.compareTo(lastEnd) <= 0) {
					return lastValue;
				}
				try {
					long index = addrMap.getKey(addr, false);
					DBRecord rec = rangeMapTable.getRecordAtOrBefore(index);
					if (rec != null) {
						Address startAddr = addrMap.decodeAddress(rec.getKey());
						Address endAddr = addrMap.decodeAddress(rec.getLongValue(TO_COL));
						if (addr.compareTo(startAddr) >= 0 && addr.compareTo(endAddr) <= 0) {
							Field value = rec.getFieldValue(VALUE_COL);
							lastStart = startAddr;
							lastEnd = endAddr;
							lastValue = value;
							lastRange = new AddressRangeImpl(lastStart, lastEnd);
							return value;
						}
					}
				}
				catch (IOException e) {
					errHandler.dbError(e);
				}
			}
			return null;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Associates the given value with every index from start to end (inclusive)
	 * Any previous associates are overwritten.
	 * @param startAddr the start address.
	 * @param endAddr the end address.
	 * @param value value to be painted, or null for value removal.
	 */
	public void paintRange(Address startAddr, Address endAddr, Field value) {
		lock.acquire();
		try {
			lastStart = startAddr;
			lastEnd = endAddr;
			lastValue = value;
			lastRange = null;
			if (startAddr.compareTo(endAddr) > 0)
				throw new IllegalArgumentException();

			++modCount;
			for (KeyRange range : addrMap.getKeyRanges(startAddr, endAddr, true)) {
				paintRange(range.minKey, range.maxKey, value);
			}

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
		if (length <= 0)
			return;
		DBHandle tmpDb = null;
		AddressRangeMapDB tmpMap = null;
		lock.acquire();
		try {
			tmpDb = dbHandle.getScratchPad();
			tmpMap = new AddressRangeMapDB(tmpDb, addrMap, lock, "TEMP", errHandler, valueField,
				indexed);

			Address fromEndAddr = fromAddr.add(length - 1);
			for (AddressRange range : getAddressRanges(fromAddr, fromEndAddr)) {
				monitor.checkCanceled();

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
				monitor.checkCanceled();
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
	 * Paint over a range of address keys which fall within the same key base
	 * @param start
	 * @param end
	 * @param value
	 */
	private void paintRange(long start, long end, Field value) {

		try {
			if (rangeMapTable == null) {
				if (value == null)
					return;
				createTable();
			}

			// fix up the start of the range, unless the range starts at a key-range MIN
			if (!addrMap.isKeyRangeMin(start)) {
				DBRecord rec = rangeMapTable.getRecordBefore(start);
				if (rec != null) {
					long to = rec.getLongValue(TO_COL);
					if (addrMap.hasSameKeyBase(start, to)) {
						if (rec.fieldEquals(VALUE_COL, value)) {
							if (to >= (start - 1)) {
								if (to >= end)
									return; // range already painted
								// Combine with new range
								start = rec.getKey();
								rangeMapTable.deleteRecord(start);
							}
						}
						else if (to >= start) {
							// Truncate existing range
							rec.setLongValue(TO_COL, start - 1);
							rangeMapTable.putRecord(rec);

							if (to > end) {
								// Must split existing record
								rec.setKey(end + 1);
								rec.setLongValue(TO_COL, to);
								rangeMapTable.putRecord(rec);
							}
						}
					}
				}
			}

			// fix up the end of the range, unless the end goes to key-range MAX
			if (!addrMap.isKeyRangeMax(end)) {
				DBRecord rec = rangeMapTable.getRecord(end + 1);
				if (rec != null && rec.fieldEquals(VALUE_COL, value)) {
					end = rec.getLongValue(TO_COL);
					rangeMapTable.deleteRecord(rec.getKey());
				}
			}

			// fix records which overlap paint range
			RecordIterator iter = rangeMapTable.iterator(start, end, start);
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				iter.delete();
				long to = rec.getLongValue(TO_COL);
				if (to > end) {
					if (rec.fieldEquals(VALUE_COL, value)) {
						end = to;
					}
					else {
						rec.setKey(end + 1);
						rangeMapTable.putRecord(rec);
					}
				}
			}

			// insert new range entry if value was specified
			if (value != null) {
				DBRecord rec = rangeMapSchema.createRecord(start);
				rec.setLongValue(TO_COL, end);
				rec.setField(VALUE_COL, value);
				rangeMapTable.putRecord(rec);
			}

			// Check for empty table
			else {
				if (rangeMapTable.getRecordCount() == 0) {
					dbHandle.deleteTable(tableName);
					rangeMapTable = null;
				}
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
	}

	/**
	 * Remove values from the given range.
	 * @param startAddr the start address.
	 * @param endAddr the end address.
	 */
	public void clearRange(Address startAddr, Address endAddr) {
		lock.acquire();
		try {
			lastStart = startAddr;
			lastEnd = endAddr;
			lastValue = null;
			lastRange = null;
			if (startAddr.compareTo(endAddr) > 0)
				throw new IllegalArgumentException();

			++modCount;
			for (KeyRange range : addrMap.getKeyRanges(startAddr, endAddr, false)) {
				paintRange(range.minKey, range.maxKey, null);
			}
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Returns a complete address set where any value has been set. 
	 * @return address set
	 */
	public AddressSet getAddressSet() {
		lock.acquire();
		try {
			AddressSet set = new AddressSet();
			if (rangeMapTable != null) {
				try {
					RecordIterator iterator = rangeMapTable.iterator();
					while (iterator.hasNext()) {
						DBRecord rec = iterator.next();
						Address startAddr = addrMap.decodeAddress(rec.getKey());
						Address endAddr = addrMap.decodeAddress(rec.getLongValue(TO_COL));
						set.addRange(startAddr, endAddr);
					}
				}
				catch (IOException e) {
					errHandler.dbError(e);
				}
			}
			return set;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Returns a complete address set where the specified value has been set.
	 * @param value field value
	 * @return address set
	 */
	public AddressSet getAddressSet(Field value) {
		lock.acquire();
		try {
			AddressSet set = new AddressSet();
			if (rangeMapTable != null) {
				try {
					RecordIterator iterator =
						rangeMapTable.indexIterator(VALUE_COL, value, value, true);
					while (iterator.hasNext()) {
						DBRecord rec = iterator.next();
						Address startAddr = addrMap.decodeAddress(rec.getKey());
						Address endAddr = addrMap.decodeAddress(rec.getLongValue(TO_COL));
						set.addRange(startAddr, endAddr);
					}
				}
				catch (IOException e) {
					errHandler.dbError(e);
				}
			}
			return set;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Returns an address range iterator over all occupied ranges in the map.
	 * @return AddressRangeIterator that iterates over all occupied ranges in th
	 * map.
	 */
	public AddressRangeIterator getAddressRanges() {
		return new RangeIterator();
	}

	/**
	 * Returns an address range iterator over all occupied ranges in the map.
	 * The first range must have a FROM address at or after 
	 * the specified startAddr.
	 * @param startAddr the address to start the iterator.
	 * @return AddressRangeIterator that iterates over all occupied ranges in th
	 * map.
	 */
	public AddressRangeIterator getAddressRanges(Address startAddr) {
		return new RangeIterator(startAddr);
	}

	/**
	 * Returns an address range iterator over all occupied ranges whose
	 * FROM address falls within the range startAddr to endAddr.
	 * @param startAddr start of range
	 * @param endAddr end of range
	 * @return AddressRangeIterator
	 */
	public AddressRangeIterator getAddressRanges(Address startAddr, Address endAddr) {
		return new RangeIterator(startAddr, endAddr);
	}

	/**
	 * Returns an address range iterator for those ranges which contain the
	 * specified value.  This method may only be invoked for indexed maps.
	 * @param value
	 * @return AddressRangeIterator
	 */
	public AddressRangeIterator getValueRanges(Field value) {
		return new ValueRangeIterator(value);
	}

	/**
	 * Returns the bounding address-range containing addr and the the same value throughout.
	 * @param addr the contained address
	 * @return single value address-range containing addr
	 */
	public AddressRange getAddressRangeContaining(Address addr) {

		lock.acquire();
		try {
			if (lastRange != null && lastRange.contains(addr)) {
				return lastRange;
			}
			try {
				Address min = addr.getAddressSpace().getMinAddress();
				Address max = addr.getAddressSpace().getMaxAddress();
				if (rangeMapTable != null) {
					AddressKeyRecordIterator addressKeyRecordIterator =
						new AddressKeyRecordIterator(rangeMapTable, addrMap, min, addr, addr, true);
					if (addressKeyRecordIterator.hasPrevious()) {
						DBRecord rec = addressKeyRecordIterator.previous();
						Address fromAddr = addrMap.decodeAddress(rec.getKey());
						Address toAddr = addrMap.decodeAddress(rec.getLongValue(TO_COL));
						if (toAddr.compareTo(addr) >= 0) {
							lastRange = new AddressRangeImpl(fromAddr, toAddr);
							return lastRange;
						}
						min = toAddr.next();
					}
					addressKeyRecordIterator =
						new AddressKeyRecordIterator(rangeMapTable, addrMap, addr, max, addr, true);
					if (addressKeyRecordIterator.hasNext()) {
						DBRecord rec = addressKeyRecordIterator.next();
						Address fromAddr = addrMap.decodeAddress(rec.getKey());
						Address toAddr = addrMap.decodeAddress(rec.getLongValue(TO_COL));
						if (fromAddr.compareTo(addr) == 0) {
							lastRange = new AddressRangeImpl(fromAddr, toAddr);
							return lastRange;
						}
						max = fromAddr.previous();
					}
				}
				lastRange = new AddressRangeImpl(min, max);
			}
			catch (IOException e) {
				errHandler.dbError(e);
			}
			return lastRange;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * An address range iterator which returns all occupied ranges.
	 */
	private class RangeIterator implements AddressRangeIterator {

		private RecordIterator recIter;
		private DBRecord nextRec;

		private boolean checkStart;
		private long startIndex;

		private boolean checkEnd;
		private long endIndex;

		private int expectedModCount;

		/**
		 * Construct a new iterator which returns all occupied ranges.
		 */
		RangeIterator() {
			expectedModCount = modCount;
			if (rangeMapTable != null) {
				try {
					recIter = new AddressKeyRecordIterator(rangeMapTable, addrMap);
				}
				catch (IOException e) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
					errHandler.dbError(e);

				}
			}
		}

		/**
		 * Construct a new iterator which returns occupied ranges whose
		 * FROM address falls within the specified range.  If the specified
		 * 'startAddr' falls anywhere within a stored range, the FROM address of the 
		 * first range returned will be changed to 'startAddr'.
		 * 
		 * @param startAddr 
		 */
		RangeIterator(Address startAddr) {
			expectedModCount = modCount;
			if (rangeMapTable != null) {
				try {
					startIndex = addrMap.getKey(startAddr, false);
					if (startIndex != AddressMap.INVALID_ADDRESS_KEY) {
						DBRecord rec = rangeMapTable.getRecordBefore(startIndex);
						if (rec != null) {
							long to = rec.getLongValue(TO_COL);
							if (addrMap.hasSameKeyBase(startIndex, to) && to >= startIndex) {
								nextRec = rec;
								checkStart = true;
							}
						}
					}

					recIter = new AddressKeyRecordIterator(rangeMapTable, addrMap, startAddr, true);

				}
				catch (IOException e) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
					errHandler.dbError(e);

				}
			}
		}

		/**
		 * Construct a new iterator which returns occupied ranges whose
		 * FROM address falls within the specified range.  If the specified
		 * 'startAddr' falls anywhere within a stored range, the FROM address of the 
		 * first range returned will be changed to 'startAddr'.  Similarly, if the
		 * specified 'endAddr' falls within a stored range, the TO address of the
		 * last range returned will be changed to 'endAddr'.
		 * 
		 * @param startAddr 
		 * @param endAddr
		 */
		RangeIterator(Address startAddr, Address endAddr) {
			expectedModCount = modCount;
			if (rangeMapTable != null) {
				try {
					startIndex = addrMap.getKey(startAddr, false);
					if (startIndex != AddressMap.INVALID_ADDRESS_KEY) {
						DBRecord rec = rangeMapTable.getRecordBefore(startIndex);
						if (rec != null) {
							long to = rec.getLongValue(TO_COL);
							if (addrMap.hasSameKeyBase(startIndex, to) && to >= startIndex) {
								nextRec = rec;
								checkStart = true;
							}
						}
					}
					endIndex = addrMap.getKey(endAddr, false);
					checkEnd = (endIndex != AddressMap.INVALID_ADDRESS_KEY);

					recIter = new AddressKeyRecordIterator(rangeMapTable, addrMap, startAddr,
						endAddr, startAddr, true);

				}
				catch (IOException e) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
					errHandler.dbError(e);

				}
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

		/**
		 * @see ghidra.util.datastruct.IndexRangeIterator#hasNext()
		 */
		@Override
		public boolean hasNext() {
			lock.acquire();
			try {
				if (expectedModCount != modCount)
					throw new ConcurrentModificationException();
				if (nextRec != null) {
					return true;
				}
				if (recIter != null) {
					try {
						return recIter.hasNext();
					}
					catch (IOException e) {
						errHandler.dbError(e);
					}
				}
				return false;
			}
			finally {
				lock.release();
			}
		}

		/**
		 * @see ghidra.util.datastruct.IndexRangeIterator#next()
		 */
		@Override
		public AddressRange next() {
			lock.acquire();
			try {
				if (expectedModCount != modCount)
					throw new ConcurrentModificationException();
				AddressRange range = null;
				if (recIter != null) {
					try {
						DBRecord rec;
						if (nextRec != null) {
							rec = nextRec;
							nextRec = null;
						}
						else {
							rec = recIter.next();
						}
						if (rec != null) {
							Field value = rec.getFieldValue(VALUE_COL);
							long fromIndex = rec.getKey();
							long toIndex = rec.getLongValue(TO_COL);
							if (checkStart && addrMap.hasSameKeyBase(startIndex, fromIndex) &&
								fromIndex < startIndex) {
								fromIndex = startIndex;
							}
							Address rangeStart = addrMap.decodeAddress(fromIndex);
							Address rangeEnd;
							if (checkEnd && addrMap.hasSameKeyBase(endIndex, toIndex) &&
								toIndex > endIndex) {
								rangeEnd = addrMap.decodeAddress(endIndex);
							}
							else {
								rangeEnd = addrMap.decodeAddress(toIndex);

								// handle key-range boundaries where a key-base transition may occur
								// consume additional ranges as needed when value matches
								while (recIter.hasNext()) {
									nextRec = recIter.next();
									if (!value.equals(nextRec.getFieldValue(VALUE_COL))) {
										break;
									}
									Address nextAddr = rangeEnd.addWrap(1);
									Address nextFrom = addrMap.decodeAddress(rec.getKey());
									if (!nextAddr.equals(nextFrom)) {
										break;
									}
									toIndex = nextRec.getLongValue(TO_COL);
									nextRec = null; // next record consumed
									if (checkEnd && addrMap.hasSameKeyBase(endIndex, toIndex) &&
										toIndex > endIndex) {
										rangeEnd = addrMap.decodeAddress(endIndex);
										break;
									}
									rangeEnd = addrMap.decodeAddress(toIndex);
								}
							}

							lastStart = rangeStart;
							lastEnd = rangeEnd;
							lastValue = value;
							range = new AddressRangeImpl(rangeStart, rangeEnd);
						}
					}
					catch (IOException e) {
						errHandler.dbError(e);
					}
				}
				return range;
			}
			finally {
				lock.release();
			}
		}

	}

	/**
	 * An address range iterator which returns all ranges which contain 
	 * a specific value or range of values.
	 */
	private class ValueRangeIterator implements AddressRangeIterator {

		RecordIterator recIter;
		DBRecord nextRec;

		private int expectedModCount;

		/**
		 * Construct an index range iterator for those ranges 
		 * which contain the specified value.  A database error will
		 * occur if the value column is not indexed.
		 * @param value
		 */
		ValueRangeIterator(Field value) {
			expectedModCount = modCount;
			if (rangeMapTable != null) {
				try {
					recIter = rangeMapTable.indexIterator(VALUE_COL, value, value, true);
				}
				catch (IOException e) {
					errHandler.dbError(e);
				}
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

		/**
		 * @see ghidra.util.datastruct.IndexRangeIterator#hasNext()
		 */
		@Override
		public boolean hasNext() {
			lock.acquire();
			try {
				if (expectedModCount != modCount)
					throw new ConcurrentModificationException();
				if (nextRec != null) {
					return true;
				}
				if (recIter != null) {
					try {
						return recIter.hasNext();
					}
					catch (IOException e) {
						errHandler.dbError(e);
					}
				}
				return false;
			}
			finally {
				lock.release();
			}
		}

		/**
		 * @see ghidra.util.datastruct.IndexRangeIterator#next()
		 */
		@Override
		public AddressRange next() {
			lock.acquire();
			try {
				if (expectedModCount != modCount)
					throw new ConcurrentModificationException();
				AddressRange range = null;
				if (recIter != null) {
					try {
						DBRecord rec;
						if (nextRec != null) {
							rec = nextRec;
							nextRec = null;
						}
						else {
							rec = recIter.next();
						}

						if (rec != null) {
							Address rangeStart = addrMap.decodeAddress(rec.getKey());
							Address rangeEnd = addrMap.decodeAddress(rec.getLongValue(TO_COL));

							// handle key-range boundaries where a key-base transition may occur
							// consume additional ranges as needed
							while (recIter.hasNext()) {
								nextRec = recIter.next();
								Address nextAddr = rangeEnd.addWrap(1);
								Address nextFrom = addrMap.decodeAddress(rec.getKey());
								if (!nextAddr.equals(nextFrom)) {
									break;
								}
								rangeEnd = addrMap.decodeAddress(nextRec.getLongValue(TO_COL));
								nextRec = null; // next record consumed
							}

							lastStart = rangeStart;
							lastEnd = rangeEnd;
							lastValue = rec.getFieldValue(VALUE_COL);
							range = new AddressRangeImpl(rangeStart, rangeEnd);
						}
					}
					catch (IOException e) {
						errHandler.dbError(e);
					}
				}
				return range;
			}
			finally {
				lock.release();
			}
		}

	}

	@Override
	public void dbRestored(DBHandle dbh) {
		lastStart = null;
		lastEnd = null;
		lastValue = null;
		lastRange = null;
		findTable();
	}

	@Override
	public void dbClosed(DBHandle dbh) {
	}

	@Override
	public void tableDeleted(DBHandle dbh, Table table) {
		if (table == rangeMapTable) {
			lastStart = null;
			lastEnd = null;
			lastValue = null;
			lastRange = null;
			rangeMapTable = null;
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
				lastStart = null;
				lastEnd = null;
				lastValue = null;
				lastRange = null;
				rangeMapTable = null;
			}
		}
		finally {
			lock.release();
		}
	}

}
