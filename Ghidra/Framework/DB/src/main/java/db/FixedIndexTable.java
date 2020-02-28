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
package db;

import java.io.IOException;
import java.util.NoSuchElementException;

/**
 * The <code>FixedIndexTable</code> provides a secondary index on a fixed-length table column
 * (e.g., IntField, LongField, etc.).  For each unique secondary index value, an IndexBuffer is 
 * stored within an underlying index Table record.  The secondary index value is used as the long
 * key to access this record.  Within a single IndexBuffer is stored all primary keys which 
 * correspond to an index value.
 */
class FixedIndexTable extends IndexTable {

	private static final Class<?>[] fieldClasses = { BinaryField.class, 	// index data
	};

	private static final String[] fieldNames = { "IndexBuffer" };

	private static Schema indexSchema = new Schema(0, "IndexKey", fieldClasses, fieldNames);

	/**
	 * Construct a new secondary index which is based upon a field within the
	 * primary table specified by name.
	 * @param primaryTable primary table.
	 * @param colIndex identifies the indexed column within the primary table.
	 * @throws IOException thrown if an IO error occurs 
	 */
	FixedIndexTable(Table primaryTable, int colIndex) throws IOException {
		this(primaryTable, primaryTable.getDBHandle().getMasterTable().createTableRecord(
			primaryTable.getName(), indexSchema, colIndex));
	}

	/**
	 * Construct a new or existing secondary index. An existing index must have
	 * its root ID specified within the tableRecord.
	 * @param primaryTable primary table.
	 * @param indexTableRecord specifies the index parameters.
	 * @throws IOException thrown if an IO error occurs 
	 */
	FixedIndexTable(Table primaryTable, TableRecord indexTableRecord) throws IOException {
		super(primaryTable, indexTableRecord);
	}

	/**
	 * Find all primary keys which correspond to the specified indexed field
	 * value.
	 * @param indexValue the field value to search for.
	 * @return list of primary keys
	 * @throws IOException thrown if an IO error occurs 
	 */
	@Override
	long[] findPrimaryKeys(Field indexValue) throws IOException {
		if (!indexValue.getClass().equals(fieldType.getClass())) {
			throw new IllegalArgumentException("Incorrect indexed field type");
		}
		Record indexRecord = indexTable.getRecord(indexValue.getLongValue());
		if (indexRecord == null) {
			return emptyKeyArray;
		}
		IndexBuffer indexBuffer = new IndexBuffer(indexValue, indexRecord.getBinaryData(0));
		return indexBuffer.getPrimaryKeys();
	}

	/**
	 * Get the number of primary keys which correspond to the specified indexed field
	 * value.
	 * @param indexValue the field value to search for.
	 * @return key count
	 */
	@Override
	int getKeyCount(Field indexValue) throws IOException {
		if (!indexValue.getClass().equals(fieldType.getClass())) {
			throw new IllegalArgumentException("Incorrect indexed field type");
		}
		Record indexRecord = indexTable.getRecord(indexValue.getLongValue());
		if (indexRecord == null) {
			return 0;
		}
		IndexBuffer indexBuffer = new IndexBuffer(indexValue, indexRecord.getBinaryData(0));
		return indexBuffer.keyCount;
	}

	/*
	 * @see ghidra.framework.store.db.IndexTable#addEntry(ghidra.framework.store.db.Record)
	 */
	@Override
	void addEntry(Record record) throws IOException {
		Field indexField = record.getField(colIndex);
		long secondaryKey = indexField.getLongValue();
		Record indexRecord = indexTable.getRecord(secondaryKey);
		if (indexRecord == null) {
			indexRecord = indexSchema.createRecord(secondaryKey);
		}
		IndexBuffer indexBuffer = new IndexBuffer(indexField, indexRecord.getBinaryData(0));
		indexBuffer.addEntry(record.getKey());
		indexRecord.setBinaryData(0, indexBuffer.getData());
		indexTable.putRecord(indexRecord);
	}

	/*
	 * @see ghidra.framework.store.db.IndexTable#deleteEntry(ghidra.framework.store.db.Record)
	 */
	@Override
	void deleteEntry(Record record) throws IOException {
		Field indexField = record.getField(colIndex);
		long secondaryKey = indexField.getLongValue();
		Record indexRecord = indexTable.getRecord(secondaryKey);
		if (indexRecord != null) {
			IndexBuffer indexBuffer = new IndexBuffer(indexField, indexRecord.getBinaryData(0));
			indexBuffer.deleteEntry(record.getKey());
			byte[] data = indexBuffer.getData();
			if (data == null) {
				indexTable.deleteRecord(secondaryKey);
			}
			else {
				indexRecord.setBinaryData(0, data);
				indexTable.putRecord(indexRecord);
			}
		}
	}

	/**
	 * Get the index buffer associated with the specified index key
	 * @param indexKey index key
	 * @return index buffer or null if not found
	 * @throws IOException thrown if IO error occurs
	 */
	private IndexBuffer getIndexBuffer(Field indexKey) throws IOException {
		Record indexRec = indexTable.getRecord(indexKey.getLongValue());
		return indexRec != null ? new IndexBuffer(indexKey, indexRec.getBinaryData(0)) : null;
	}

	/*
	 * @see ghidra.framework.store.db.IndexTable#indexIterator()
	 */
	@Override
	DBFieldIterator indexIterator() throws IOException {
		return new IndexLongIterator();
	}

	/*
	 * @see ghidra.framework.store.db.IndexTable#indexIterator(ghidra.framework.store.db.Field, ghidra.framework.store.db.Field, boolean)
	 */
	@Override
	DBFieldIterator indexIterator(Field minField, Field maxField, boolean atMin)
			throws IOException {
		long min = minField != null ? minField.getLongValue() : Long.MIN_VALUE;
		long max = maxField != null ? maxField.getLongValue() : Long.MAX_VALUE;
		return new IndexLongIterator(min, max, atMin);
	}

	/*
	 * @see db.IndexTable#indexIterator(db.Field, db.Field, db.Field, boolean)
	 */
	@Override
	DBFieldIterator indexIterator(Field minField, Field maxField, Field startField, boolean before)
			throws IOException {
		if (startField == null) {
			throw new IllegalArgumentException("starting index value required");
		}
		long min = minField != null ? minField.getLongValue() : Long.MIN_VALUE;
		long max = maxField != null ? maxField.getLongValue() : Long.MAX_VALUE;
		return new IndexLongIterator(min, max, startField.getLongValue(), before);
	}

	/**
	 * Iterates over index field values within a specified range.
	 */
	class IndexLongIterator implements DBFieldIterator {

		private Field lastKey;
		private Field keyField;
		private DBLongIterator indexIterator;
		private boolean hasNext = false;
		private boolean hasPrev = false;

		/**
		 * Construct an index field iterator starting with the minimum index value.
		 */
		IndexLongIterator() throws IOException {
			indexIterator = indexTable.longKeyIterator();
		}

		/**
		 * Construct an index field iterator.  The iterator is positioned at index 
		 * value identified by startValue.
		 * @param startValue minimum index value or null if no minimum
		 * @param endValue maximum index value or null if no maximum
		 * @param atStart if true initial position is before startValue, else position
		 * is after endValue
		 * @throws IOException
		 */
		IndexLongIterator(long minValue, long maxValue, boolean atMin) throws IOException {

			long start = atMin ? minValue : maxValue;
			indexIterator = indexTable.longKeyIterator(minValue, maxValue, start);

			if (indexIterator.hasNext()) {
				indexIterator.next();
				if (atMin) {
					indexIterator.previous();
				}
			}
		}

		/**
		 * @param min
		 * @param max
		 * @param longValue
		 * @param before
		 */
		public IndexLongIterator(long minValue, long maxValue, long start, boolean before)
				throws IOException {

			indexIterator = indexTable.longKeyIterator(minValue, maxValue, start);

			if (indexIterator.hasNext()) {
				long val = indexIterator.next();
				if (before || val != start) {
					indexIterator.previous();
				}
			}
		}

		@Override
		public boolean hasNext() throws IOException {
			if (hasNext) {
				return true;
			}
			try {
				long key = indexIterator.next();
				keyField = fieldType.newField();
				keyField.setLongValue(key);
				hasNext = true;
				hasPrev = false;
			}
			catch (NoSuchElementException e) {
				return false;
			}
			return true;
		}

		@Override
		public boolean hasPrevious() throws IOException {
			if (hasPrev) {
				return true;
			}
			try {
				long key = indexIterator.previous();
				keyField = fieldType.newField();
				keyField.setLongValue(key);
				hasNext = false;
				hasPrev = true;
			}
			catch (NoSuchElementException e) {
				return false;
			}
			return true;
		}

		@Override
		public Field next() throws IOException {
			if (hasNext || hasNext()) {
				hasNext = false;
				hasPrev = true;
				lastKey = keyField;
				return keyField;
			}
			return null;
		}

		@Override
		public Field previous() throws IOException {
			if (hasPrev || hasPrevious()) {
				hasNext = true;
				hasPrev = false;
				lastKey = keyField;
				return keyField;
			}
			return null;
		}

		/**
		 * Delete all primary records which have the current
		 * index value (lastKey).
		 * @see db.DBFieldIterator#delete()
		 */
		@Override
		public boolean delete() throws IOException {
			if (lastKey == null) {
				return false;
			}
			synchronized (db) {
				IndexBuffer indexBuf = getIndexBuffer(lastKey);
				if (indexBuf != null) {
					long[] keys = indexBuf.getPrimaryKeys();
					for (long key : keys) {
						primaryTable.deleteRecord(key);
					}
					// The following does not actually delete the index record since it 
					// should already have been removed with the removal of all associated 
					// primary records.  Invoking this method allows the iterator to
					// recover from the index table change. 
					indexIterator.delete();
				}
				lastKey = null;
				return true;
			}
		}
	}

}
