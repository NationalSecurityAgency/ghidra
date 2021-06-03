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

import db.*;
import db.util.ErrorHandler;
import ghidra.util.datastruct.IndexRange;
import ghidra.util.datastruct.IndexRangeIterator;
import ghidra.util.exception.NotYetImplementedException;

/**
 * <code>SharedRangeMapDB</code> provides a long value range map backed by a database table.
 * This map allows values to share a given range with other values.
 * @deprecated This map class should not be used except by the OldFunctionMapDB class
 */
@Deprecated
public class SharedRangeMapDB {

	private DBHandle dbHandle;
	private ErrorHandler errHandler;
	Table rangeTable; // exposed for testing
	Table mapTable;   // exposed for testing

	//private int modCount;

	private final static String RANGES_TABLE_NAME_PREFIX = "Shared Ranges - ";
	private final static String MAP_TABLE_NAME_PREFIX = "Shared Map - ";

	private static final Schema RANGES_SCHEMA = createRangesSchema();
	private static final Schema MAP_SCHEMA = createMapSchema();

	// Ranges Table Columns (key is FROM index value)
	static final int RANGE_TO_COL = 0;

	// Map Columns (key is one-up ID value)
	static final int MAP_VALUE_COL = 0;       // is indexed
	static final int MAP_RANGE_KEY_COL = 1;   // is indexed

	private static final int[] MAP_INDEXED_COLS = new int[] { MAP_VALUE_COL, MAP_RANGE_KEY_COL };

	private static Schema createRangesSchema() {
		return new Schema(0, "From", new Field[] { LongField.INSTANCE }, new String[] { "To" });
	}

	private static Schema createMapSchema() {
		return new Schema(0, "Key", new Field[] { LongField.INSTANCE, LongField.INSTANCE },
			new String[] { "Value", "Range Key" });
	}

	/**
	 * Construct a shared range map.
	 * @param dbHandle database handle.
	 * @param name map name used in naming the underlying database table.  
	 * This name must be unqiue across all shared range maps.
	 * @param errHandler database error handler.
	 * @param create if true the underlying database tables will be created.
	 */
	public SharedRangeMapDB(DBHandle dbHandle, String name, ErrorHandler errHandler,
			boolean create) {
		this.dbHandle = dbHandle;
		this.errHandler = errHandler;
		String rangeTableName = RANGES_TABLE_NAME_PREFIX + name;
		String mapTableName = MAP_TABLE_NAME_PREFIX + name;
		if (create) {
			try {
				rangeTable = dbHandle.createTable(rangeTableName, RANGES_SCHEMA);
				mapTable = dbHandle.createTable(mapTableName, MAP_SCHEMA, MAP_INDEXED_COLS);
			}
			catch (IOException e) {
				errHandler.dbError(e);
			}
		}
		else {
			rangeTable = dbHandle.getTable(rangeTableName);
			if (rangeTable == null) {
				errHandler.dbError(new IOException("Table not found: " + rangeTableName));
			}
			mapTable = dbHandle.getTable(mapTableName);
			if (mapTable == null) {
				errHandler.dbError(new IOException("Table not found: " + mapTableName));
			}
		}
	}

	/**
	 * Frees resources used by this map.
	 */
	public void dispose() {
		synchronized (dbHandle) {
			if (rangeTable != null) {
				try {
					dbHandle.deleteTable(rangeTable.getName());
					dbHandle.deleteTable(mapTable.getName());
				}
				catch (IOException e) {
					errHandler.dbError(e);
				}
				rangeTable = null;
				mapTable = null;
			}
		}
	}

	/**
	 * Add a value to this map over the specified range.
	 * @param start the start of the range.
	 * @param end the end of the range.
	 * @param value the value to associate with the range.
	 */
	public void add(long start, long end, long value) {
		synchronized (dbHandle) {
			//++modCount;
			try {
				// Consoldate existing ranges for this value which overlap
				Field[] mapKeys = mapTable.findRecords(new LongField(value), MAP_VALUE_COL);
				for (int i = 0; i < mapKeys.length; i++) {

					// Get next range
					Field mapKey = mapKeys[i];
					DBRecord mapRec = mapTable.getRecord(mapKey);
					long rangeKey = mapRec.getLongValue(MAP_RANGE_KEY_COL);
					DBRecord rangeRec = rangeTable.getRecord(rangeKey);

					// Consoldate range if it overlaps
					long min = rangeKey;
					long max = rangeRec.getLongValue(RANGE_TO_COL);
					if (min <= start) {
						if (max >= end) {
							return;
						}
						else if (max >= (start - 1)) {
							mapTable.deleteRecord(mapKey);
							consolidateRange(rangeKey, max);
							start = min;
						}
					}
					else if (min <= (end + 1)) {
						mapTable.deleteRecord(mapKey);
						consolidateRange(rangeKey, max);
						if (max > end) {
							end = max;
						}
					}
				}

				// Handle existing range which overlaps start index.
				DBRecord rangeRec = rangeTable.getRecordBefore(start);
				if (rangeRec != null) {
					//long startRange = rangeRec.getKey();
					long endRange = rangeRec.getLongValue(RANGE_TO_COL);
					if (endRange >= start) {
						rangeRec = splitRange(rangeRec, start - 1);
						if (endRange >= end) {
							if (endRange > end) {
								splitRange(rangeRec, end);
							}
							insertMapEntry(start, value);
							return;
						}
						insertMapEntry(start, value);
						start = endRange + 1;
					}
				}

				// Handle existing overlapping ranges
				RecordIterator iter = rangeTable.iterator(start, end, start);
				while (iter.hasNext()) {
					rangeRec = iter.next();
					long startRange = rangeRec.getKey();
					long endRange = rangeRec.getLongValue(RANGE_TO_COL);
					if (startRange > start) {
						// create missing range
						insertRangeEntry(start, startRange - 1);
						insertMapEntry(start, value);
						start = startRange;
					}
					if (endRange >= end) {
						if (endRange > end) {
							splitRange(rangeRec, end);
						}
						insertMapEntry(start, value);
						return;
					}
					if (startRange != start) {
						rangeRec = splitRange(rangeRec, endRange - 1);
					}
					insertMapEntry(start, value);
					start = endRange + 1;
				}

				// create missing range
				insertRangeEntry(start, end);
				insertMapEntry(start, value);

			}
			catch (IOException e) {
				errHandler.dbError(e);
			}
		}
	}

	/**
	 * Insert a new Map entry.
	 * @param rangeKey
	 * @param value
	 */
	private void insertMapEntry(long rangeKey, long value) throws IOException {
		DBRecord rec = MAP_SCHEMA.createRecord(mapTable.getMaxKey() + 1);
		rec.setLongValue(MAP_RANGE_KEY_COL, rangeKey);
		rec.setLongValue(MAP_VALUE_COL, value);
		mapTable.putRecord(rec);
	}

	/**
	 * Insert a new Range entry.
	 * @param start
	 * @param end
	 */
	private void insertRangeEntry(long start, long end) throws IOException {
		DBRecord rec = RANGES_SCHEMA.createRecord(start);
		rec.setLongValue(RANGE_TO_COL, end);
		rangeTable.putRecord(rec);
	}

	/**
	 * Split a Range record and all related Map entries at a newEnd index.
	 * A new Range record is created at newEnd+1 to the end of the original 
	 * range.  New Map entries are created for this new range.
	 * @param rangeRecord
	 * @param newEnd
	 * @return Record
	 * @throws IOException
	 */
	private DBRecord splitRange(DBRecord rangeRecord, long newEnd) throws IOException {

		// Split range record
		DBRecord newRange = RANGES_SCHEMA.createRecord(newEnd + 1);
		newRange.setField(RANGE_TO_COL, rangeRecord.getFieldValue(RANGE_TO_COL));
		rangeRecord.setLongValue(RANGE_TO_COL, newEnd);
		rangeTable.putRecord(rangeRecord);
		rangeTable.putRecord(newRange);

		// Split related map records
		Field[] mapKeys = mapTable.findRecords(rangeRecord.getKeyField(), MAP_RANGE_KEY_COL);
		for (int i = 0; i < mapKeys.length; i++) {
			DBRecord mapRec = mapTable.getRecord(mapKeys[i]);
			mapRec.setKey(mapTable.getMaxKey() + 1);
			mapRec.setField(MAP_RANGE_KEY_COL, newRange.getKeyField());
			mapTable.putRecord(mapRec);
		}

		return newRange;
	}

	/**
	 * Get a sorted array of map values for a given set of map keys.
	 * @param mapKeys
	 * @return long[]
	 * @throws IOException
	 */
	private Field[] getMapValues(Field[] mapKeys) throws IOException {

		Field[] values = new Field[mapKeys.length];
		for (int i = 0; i < mapKeys.length; i++) {
			DBRecord rec = mapTable.getRecord(mapKeys[i]);
			values[i] = rec.getFieldValue(MAP_VALUE_COL);
		}
		Arrays.sort(values);
		return values;
	}

	/**
	 * If other values are mapped to a specified range, perform a consolidation
	 * on that range if possible.  If no reference exists, delete the range.
	 * @param rangeKey
	 * @param end end of range (must agree with record).
	 */
	private void consolidateRange(long rangeKey, long end) throws IOException {

		// Find map entries which occupy range
		Field[] mapKeys = mapTable.findRecords(new LongField(rangeKey), MAP_RANGE_KEY_COL);
		Field[] values = getMapValues(mapKeys);

		// Delete range if not occupied
		if (mapKeys.length == 0) {
			rangeTable.deleteRecord(rangeKey);
			return;
		}

		// Consolidate previous range if possible
		DBRecord rangeRec = rangeTable.getRecordBefore(rangeKey);
		if (rangeRec != null && rangeRec.getLongValue(RANGE_TO_COL) == (rangeKey - 1)) {
			Field[] keys = mapTable.findRecords(rangeRec.getKeyField(), MAP_RANGE_KEY_COL);
			// Can consolidate if range occupied by the same set of values
			if (Arrays.equals(getMapValues(keys), values)) {

				// Combine ranges
				rangeTable.deleteRecord(rangeKey);
				rangeRec.setLongValue(RANGE_TO_COL, end);
				rangeTable.putRecord(rangeRec);

				// Delete Map entries on old rangeKey
				for (int i = 0; i < mapKeys.length; i++) {
					mapTable.deleteRecord(mapKeys[i]);
				}

				rangeKey = rangeRec.getKey();
			}
		}

		// Consolidate next range if possible
		rangeRec = rangeTable.getRecordAfter(end);
		if (rangeRec != null && rangeRec.getKey() == (end + 1)) {
			Field[] keys = mapTable.findRecords(rangeRec.getKeyField(), MAP_RANGE_KEY_COL);
			// Can consolidate if range occupied by the same set of values
			if (Arrays.equals(getMapValues(keys), values)) {

				// Combine ranges
				rangeTable.deleteRecord(rangeRec.getKey());
				rangeRec.setKey(rangeKey);
				rangeTable.putRecord(rangeRec);

				// Delete Map entries on old rangeKey
				for (int i = 0; i < keys.length; i++) {
					mapTable.deleteRecord(keys[i]);
				}
			}
		}

	}

	/**
	 * Remove a value from this map.
	 * @param value the value to remove.
	 */
	public void remove(long value) {
		synchronized (dbHandle) {
			//++modCount;
			try {
				Field[] mapKeys = mapTable.findRecords(new LongField(value), MAP_VALUE_COL);
				for (int i = 0; i < mapKeys.length; i++) {

					// Remove Map entry
					Field mapKey = mapKeys[i];
					DBRecord mapRec = mapTable.getRecord(mapKey);
					mapTable.deleteRecord(mapKey);

					// Consolidate Range
					long rangeKey = mapRec.getLongValue(MAP_RANGE_KEY_COL);
					DBRecord rangeRec = rangeTable.getRecord(rangeKey);
					consolidateRange(rangeKey, rangeRec.getLongValue(RANGE_TO_COL));
				}
			}
			catch (IOException e) {
				errHandler.dbError(e);
			}
		}
	}

	/**
	 * Get a LongField value iterator over the specified range.
	 * List is pre-calculated such that any changes made to the map
	 * after invoking this method will not be reflected by the iterator
	 * and invalid function keys may be returned.
	 * The implementation assumes a small set of values exist over the 
	 * range.
	 * @param start
	 * @param end
	 * @return Iterator of unique LongField values occuring within the
	 * specified range.
	 */
	public Iterator<Field> getValueIterator(long start, long end) {
		synchronized (dbHandle) {
			return new ValueIterator(start, end);
		}
	}

	/**
	 * Get an index range iterator for a specified value.
	 * @param value the value for which to iterator indexes over.
	 * @return IndexRangeIterator
	 */
	public IndexRangeIterator getValueRangeIterator(long value) {
		synchronized (dbHandle) {
			try {
				return new RangeIterator(value);
			}
			catch (IOException e) {
				errHandler.dbError(e);
			}
			return null;
		}
	}

	/**
	 * Iterates over all values which occur within the given range.
	 */
	private class ValueIterator implements Iterator<Field> {

		private RecordIterator mapRecIter;
		private Field nextValue;
		private HashSet<Field> returnedValues = new HashSet<Field>();

		ValueIterator(long start, long end) {
			try {

				// Adjust start index to pickup first range which contains start
				DBRecord rec = rangeTable.getRecordAtOrBefore(start);
				if (rec != null && rec.getLongValue(RANGE_TO_COL) >= start) {
					start = rec.getKey();
				}

				mapRecIter = mapTable.indexIterator(MAP_RANGE_KEY_COL, new LongField(start),
					new LongField(end), true);

			}
			catch (IOException e) {
				errHandler.dbError(e);
			}
		}

		/**
		 * @see java.util.Iterator#remove()
		 */
		@Override
		public void remove() {
			throw new NotYetImplementedException();
		}

		/**
		 * @see java.util.Iterator#hasNext()
		 */
		@Override
		public boolean hasNext() {
			synchronized (dbHandle) {
				try {
					while (nextValue == null) {
						DBRecord rec = mapRecIter.next();
						if (rec == null)
							break;
						nextValue = rec.getFieldValue(MAP_VALUE_COL);
						if (!returnedValues.add(nextValue)) {
							nextValue = null; // value already returned
						}
					}
				}
				catch (IOException e) {
					errHandler.dbError(e);
				}
				return (nextValue != null);
			}
		}

		/**
		 * @see java.util.Iterator#next()
		 */
		@Override
		public Field next() {
			synchronized (dbHandle) {
				if (nextValue != null || hasNext()) {
					Field v = nextValue;
					nextValue = null;
					return v;
				}
				return null;
			}
		}
	}

	/**
	 * Iterates over all ranges occupied by a given value.
	 */
	private class RangeIterator implements IndexRangeIterator {

		private RecordIterator recordIter;

		/**
		 * Construct an iterator which returns all ranges occupied
		 * by the specified value.
		 * @param value
		 * @throws IOException
		 */
		RangeIterator(long value) throws IOException {
			LongField val = new LongField(value);
			recordIter = mapTable.indexIterator(MAP_VALUE_COL, val, val, true);
		}

		/**
		 * @see ghidra.util.datastruct.IndexRangeIterator#hasNext()
		 */
		@Override
		public boolean hasNext() {
			synchronized (dbHandle) {
				try {
					return recordIter.hasNext();
				}
				catch (IOException e) {
					errHandler.dbError(e);
				}
				return false;
			}
		}

		/**
		 * @see ghidra.util.datastruct.IndexRangeIterator#next()
		 */
		@Override
		public IndexRange next() {
			synchronized (dbHandle) {
				try {
					DBRecord rec = recordIter.next();
					if (rec != null) {
						long rangeKey = rec.getLongValue(MAP_RANGE_KEY_COL);
						rec = rangeTable.getRecord(rangeKey);
						return new IndexRange(rec.getKey(), rec.getLongValue(RANGE_TO_COL));
					}
				}
				catch (IOException e) {
					errHandler.dbError(e);
				}
				return null;
			}
		}

	}

}
