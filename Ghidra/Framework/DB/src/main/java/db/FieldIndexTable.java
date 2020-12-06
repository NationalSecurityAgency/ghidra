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
import java.util.ArrayList;
import java.util.NoSuchElementException;

public class FieldIndexTable extends IndexTable {

	private static final Class<?>[] fieldClasses = {};

	private static final String[] fieldNames = {};

	private final Schema indexSchema;
	private final int indexColumn;

	/**
	 * Construct a new secondary index which is based upon a specific field within the
	 * primary table specified by name.
	 * @param primaryTable primary table.
	 * @param colIndex identifies the indexed column within the primary table.
	 * @throws IOException thrown if an IO error occurs 
	 */
	FieldIndexTable(Table primaryTable, int colIndex) throws IOException {
		this(primaryTable, primaryTable.getDBHandle().getMasterTable().createTableRecord(
			primaryTable.getName(), getIndexTableSchema(primaryTable, colIndex), colIndex));
	}

	/**
	 * Construct a new or existing secondary index. An existing index must have
	 * its root ID specified within the tableRecord.
	 * @param primaryTable primary table.
	 * @param indexTableRecord specifies the index parameters.
	 * @throws IOException thrown if an IO error occurs 
	 */
	FieldIndexTable(Table primaryTable, TableRecord indexTableRecord) throws IOException {
		super(primaryTable, indexTableRecord);
		this.indexSchema = indexTable.getSchema();
		this.indexColumn = indexTableRecord.getIndexedColumn();
	}

	private static Schema getIndexTableSchema(Table primaryTable, int colIndex) {
		byte fieldType = primaryTable.getSchema().getField(colIndex).getFieldType();
		IndexField indexKeyField = IndexField.getIndexField(fieldType);
		return new Schema(0, indexKeyField.getClass(), "IndexKey", fieldClasses, fieldNames);
	}

	/*
	 * @see ghidra.framework.store.db.IndexTable#findPrimaryKeys(ghidra.framework.store.db.Field)
	 */
	@Override
	long[] findPrimaryKeys(Field indexValue) throws IOException {
		IndexField indexField = IndexField.getIndexField(indexValue, Long.MIN_VALUE);
		DBFieldIterator iter = indexTable.fieldKeyIterator(indexField);
		ArrayList<IndexField> list = new ArrayList<>(20);
		while (iter.hasNext()) {
			IndexField f = (IndexField) iter.next();
			if (!f.hasSameIndex(indexField)) {
				break;
			}
			if (indexField.usesTruncatedFieldValue()) {
				// Must check actual record if index value was truncated
				Record rec = primaryTable.getRecord(f.getPrimaryKey());
				Field val = rec.getField(indexColumn);
				if (!indexValue.equals(val)) {
					continue;
				}
			}
			list.add(f);
		}
		long[] keys = new long[list.size()];
		for (int i = 0; i < keys.length; i++) {
			IndexField f = list.get(i);
			keys[i] = f.getPrimaryKey();
		}
		return keys;
	}

	/*
	 * @see ghidra.framework.store.db.IndexTable#getKeyCount(ghidra.framework.store.db.Field)
	 */
	@Override
	int getKeyCount(Field indexValue) throws IOException {
		return findPrimaryKeys(indexValue).length;
	}

	/*
	 * @see ghidra.framework.store.db.IndexTable#addEntry(ghidra.framework.store.db.Record)
	 */
	@Override
	void addEntry(Record record) throws IOException {
		Field indexedField = record.getField(colIndex);
		IndexField f = IndexField.getIndexField(indexedField, record.getKey());
		Record rec = indexSchema.createRecord(f);
		indexTable.putRecord(rec);
	}

	/*
	 * @see ghidra.framework.store.db.IndexTable#deleteEntry(ghidra.framework.store.db.Record)
	 */
	@Override
	void deleteEntry(Record record) throws IOException {
		Field indexedField = record.getField(colIndex);
		IndexField f = IndexField.getIndexField(indexedField, record.getKey());
		indexTable.deleteRecord(f);
	}

	/*
	 * @see ghidra.framework.store.db.IndexTable#indexIterator()
	 */
	@Override
	DBFieldIterator indexIterator() throws IOException {
		return new IndexFieldIterator();
	}

	/*
	 * @see ghidra.framework.store.db.IndexTable#indexIterator(ghidra.framework.store.db.Field, ghidra.framework.store.db.Field, boolean)
	 */
	@Override
	DBFieldIterator indexIterator(Field minField, Field maxField, boolean before)
			throws IOException {
		return new IndexFieldIterator(minField, maxField, before);
	}

	/*
	 * @see db.IndexTable#indexIterator(db.Field, db.Field, db.Field, boolean)
	 */
	@Override
	DBFieldIterator indexIterator(Field minField, Field maxField, Field startField, boolean before)
			throws IOException {
		return new IndexFieldIterator(minField, maxField, startField, before);
	}

	/**
	 * Iterates over index field values within a specified range.
	 * NOTE: Index fields which have been truncated may be returned out of order.
	 */
	class IndexFieldIterator implements DBFieldIterator {

		private IndexField min;
		private IndexField max;
		private IndexField lastKey;
		private IndexField indexKey;
		private DBFieldIterator indexIterator;
		private boolean hasNext = false;
		private boolean hasPrev = false;

		/**
		 * Construct an index field iterator starting with the minimum index value.
		 */
		IndexFieldIterator() throws IOException {
			this(null, null, true);
		}

		/**
		 * Construct an index field iterator.  The iterator is positioned at index 
		 * value identified by startValue.
		 * @param minValue minimum index value or null if no minimum
		 * @param maxValue maximum index value or null if no maximum
		 * @param before if true initial position is before minValue, else position
		 * after maxValue
		 * @throws IOException
		 */
		IndexFieldIterator(Field minValue, Field maxValue, boolean before) throws IOException {

			if (primaryTable.getSchema().getField(indexColumn).isVariableLength()) {
				throw new UnsupportedOperationException(
					"Due to potential truncation issues, operation not permitted on variable length fields");
			}

			min = minValue != null ? IndexField.getIndexField(minValue, Long.MIN_VALUE) : null;
			max = maxValue != null ? IndexField.getIndexField(maxValue, Long.MAX_VALUE) : null;

			IndexField start = null;
			if (before && minValue != null) {
				start = min;
			}
			else if (!before && maxValue != null) {
				start = max;
			}

			if (start != null) {
				indexIterator = indexTable.fieldKeyIterator(min, max, start);
			}
			else {
				indexIterator = indexTable.fieldKeyIterator(min, max, before);
			}

			if (indexIterator.hasNext()) {
				indexIterator.next();
				if (before) {
					indexIterator.previous();
				}
			}
		}

		/**
		 * @param minField
		 * @param maxField
		 * @param startField
		 * @param before
		 * @throws IOException
		 */
		public IndexFieldIterator(Field minValue, Field maxValue, Field startValue, boolean before)
				throws IOException {

			if (primaryTable.getSchema().getField(indexColumn).isVariableLength()) {
				throw new UnsupportedOperationException(
					"Due to potential truncation issues, operation not permitted on variable length fields");
			}

			if (startValue == null) {
				throw new IllegalArgumentException("starting index value required");
			}
			min = minValue != null ? IndexField.getIndexField(minValue, Long.MIN_VALUE) : null;
			max = maxValue != null ? IndexField.getIndexField(maxValue, Long.MAX_VALUE) : null;

			IndexField start =
				IndexField.getIndexField(startValue, before ? Long.MIN_VALUE : Long.MAX_VALUE);

			indexIterator = indexTable.fieldKeyIterator(min, max, start);

			if (indexIterator.hasNext()) {
				IndexField f = (IndexField) indexIterator.next();
				if (before || !f.getIndexField().equals(startValue)) {
					indexIterator.previous();
				}
			}
		}

		@Override
		public boolean hasNext() throws IOException {
			if (hasNext) {
				return true;
			}
			hasPrev = false;  // TODO ???
			indexKey = (IndexField) indexIterator.next();
			int skipCnt = 0;
			while (indexKey != null && indexKey.hasSameIndex(lastKey)) {
				if (++skipCnt > 10) {
					// Reinit iterator to skip large number of same index value
					indexIterator = indexTable.fieldKeyIterator(min, max,
						IndexField.getIndexField(indexKey.getIndexField(), Long.MAX_VALUE));
					skipCnt = 0;
				}
				indexKey = (IndexField) indexIterator.next();
			}

			if (indexKey == null) {
				return false;
			}

			hasNext = true;
			return true;
		}

		@Override
		public boolean hasPrevious() throws IOException {
			if (hasPrev) {
				return true;
			}
			hasNext = false;  // TODO ???
			indexKey = (IndexField) indexIterator.previous();
			int skipCnt = 0;
			while (indexKey != null && indexKey.hasSameIndex(lastKey)) {
				if (++skipCnt > 10) {
					// Reinit iterator to skip large number of same index value
					indexIterator = indexTable.fieldKeyIterator(min, max,
						IndexField.getIndexField(indexKey.getIndexField(), Long.MIN_VALUE));
					skipCnt = 0;
				}
				indexKey = (IndexField) indexIterator.previous();
			}

			if (indexKey == null) {
				return false;
			}

			hasPrev = true;
			return true;
		}

		@Override
		public Field next() throws IOException {
			if (hasNext || hasNext()) {
				hasNext = false;
				hasPrev = true;
				lastKey = indexKey;
				Field f = indexKey.getIndexField();
				return f.newField(f);
			}
			return null;
		}

		@Override
		public Field previous() throws IOException {
			if (hasPrev || hasPrevious()) {
				hasNext = true;
				hasPrev = false;
				lastKey = indexKey;
				Field f = indexKey.getIndexField();
				return f.newField(f);
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
				long[] keys = findPrimaryKeys(lastKey.getIndexField());
				for (long key : keys) {
					primaryTable.deleteRecord(key);
				}
				lastKey = null;
				return true;
			}
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.framework.store.db.IndexTable#hasRecord(ghidra.framework.store.db.Field)
	 */
	@Override
	boolean hasRecord(Field field) throws IOException {
		IndexField indexField = IndexField.getIndexField(field, Long.MIN_VALUE);
		DBFieldIterator iter = indexTable.fieldKeyIterator(indexField);
		while (iter.hasNext()) {
			IndexField f = (IndexField) iter.next();
			if (!f.hasSameIndex(indexField)) {
				return false;
			}
			if (indexField.usesTruncatedFieldValue()) {
				// Must check actual record if index value was truncated
				Record rec = primaryTable.getRecord(f.getPrimaryKey());
				Field val = rec.getField(indexColumn);
				if (!field.equals(val)) {
					continue; // skip
				}
			}
			return true;
		}
		return false;
	}

	/**
	 * Iterate over all primary keys sorted based upon the associated index key.
	 * @return primary key iterator
	 * @throws IOException thrown if IO error occurs
	 */
	@Override
	DBLongIterator keyIterator() throws IOException {
		return new PrimaryKeyIterator();
	}

	/**
	 * Iterate over all primary keys sorted based upon the associated index key.
	 * The iterator is initially positioned before the first index buffer whose index key 
	 * is greater than or equal to the specified startField value.
	 * @param startField index key value which determines initial position of iterator
	 * @return primary key iterator
	 * @throws IOException thrown if IO error occurs
	 */
	@Override
	DBLongIterator keyIteratorBefore(Field startField) throws IOException {
		return new PrimaryKeyIterator(startField, false);
	}

	/**
	 * Iterate over all primary keys sorted based upon the associated index key.
	 * The iterator is initially positioned after the index buffer whose index key 
	 * is equal to the specified startField value or immediately before the first 
	 * index buffer whose index key is greater than the specified startField value.
	 * @param startField index key value which determines initial position of iterator
	 * @return primary key iterator
	 * @throws IOException thrown if IO error occurs
	 */
	@Override
	DBLongIterator keyIteratorAfter(Field startField) throws IOException {
		return new PrimaryKeyIterator(startField, true);
	}

	/**
	 * Iterate over all primary keys sorted based upon the associated index key.
	 * The iterator is initially positioned before the primaryKey within the index buffer 
	 * whose index key is equal to the specified startField value or immediately before the first 
	 * index buffer whose index key is greater than the specified startField value.
	 * @param startField index key value which determines initial position of iterator
	 * @param primaryKey initial position within index buffer if index key matches startField value.
	 * @return primary key iterator
	 * @throws IOException thrown if IO error occurs
	 */
	@Override
	DBLongIterator keyIteratorBefore(Field startField, long primaryKey) throws IOException {
		return new PrimaryKeyIterator(null, null, startField, primaryKey, false);
	}

	/**
	 * Iterate over all primary keys sorted based upon the associated index key.
	 * The iterator is initially positioned after the primaryKey within the index buffer 
	 * whose index key is equal to the specified startField value or immediately before the first 
	 * index buffer whose index key is greater than the specified startField value.
	 * @param startField index key value which determines initial position of iterator
	 * @param primaryKey initial position within index buffer if index key matches startField value.
	 * @return primary key iterator
	 * @throws IOException thrown if IO error occurs
	 */
	@Override
	DBLongIterator keyIteratorAfter(Field startField, long primaryKey) throws IOException {
		return new PrimaryKeyIterator(null, null, startField, primaryKey, true);
	}

	/**
	 * Iterate over all primary keys sorted based upon the associated index key.
	 * The iterator is limited to range of index keys of startField through endField, inclusive.
	 * If atStart is true, the iterator is initially positioned before the first index 
	 * buffer whose index key is greater than or equal to the specified startField value. 
	 * If atStart is false, the iterator is initially positioned after the first index 
	 * buffer whose index key is less than or equal to the specified endField value. 
	 * @param startField minimum index key value
	 * @param endField maximum index key value
	 * @param atStart if true, position iterator before start value. 
	 * Otherwise, position iterator after end value.
	 * @return primary key iterator
	 * @throws IOException thrown if IO error occurs
	 */
	@Override
	DBLongIterator keyIterator(Field startField, Field endField, boolean atStart)
			throws IOException {
		return new PrimaryKeyIterator(startField, endField, atStart ? startField : endField,
			atStart ? Long.MIN_VALUE : Long.MAX_VALUE, !atStart);
	}

	/**
	 * @see db.IndexTable#keyIterator(db.Field, db.Field, db.Field, boolean)
	 */
	@Override
	DBLongIterator keyIterator(Field minField, Field maxField, Field startField, boolean before)
			throws IOException {
		return new PrimaryKeyIterator(minField, maxField, startField,
			before ? Long.MIN_VALUE : Long.MAX_VALUE, !before);
	}

	/**
	 * Iterates over primary keys which correspond to index field values within a specified range.
	 * NOTE: Primary keys corresponding to index fields which have been truncated may be returned out of order.
	 */
	private class PrimaryKeyIterator implements DBLongIterator {

		private IndexField min;
		private IndexField max;
		private DBFieldIterator indexIterator;

		private boolean hasNext = false;
		private boolean hasPrev = false;
		private IndexField key;
		private IndexField lastKey;

		/**
		 * Construct a key iterator starting with the minimum secondary key.
		 */
		PrimaryKeyIterator() throws IOException {
			indexIterator = indexTable.fieldKeyIterator();
		}

		/**
		 * Construct a key iterator.  The iterator is positioned immediately before 
		 * the key associated with the first occurance of the startValue.
		 * @param startValue indexed field value.
		 * @param after if true the iterator is positioned immediately after
		 * the last occurance of the specified startValue position.
		 */
		PrimaryKeyIterator(Field startValue, boolean after) throws IOException {
			this(null, null, startValue, after ? Long.MAX_VALUE : Long.MIN_VALUE, after);
		}

		/**
		 * Construct a key iterator.  The iterator is positioned immediately before 
		 * or after the key associated with the specified startValue/primaryKey.
		 * @param minValue minimum index value or null if no minimum
		 * @param maxValue maximum index value or null if no maximum
		 * @param startValue starting index value.
		 * @param primaryKey starting primary key value (ignored if startValue is null).
		 * @param after if true iterator is positioned immediately after 
		 * the startValue/primaryKey,
		 * otherwise immediately before.
		 * @throws IOException
		 */
		PrimaryKeyIterator(Field minValue, Field maxValue, Field startValue, long primaryKey,
				boolean after) throws IOException {

			min = minValue != null ? IndexField.getIndexField(minValue, Long.MIN_VALUE) : null;
			max = maxValue != null ? IndexField.getIndexField(maxValue, Long.MAX_VALUE) : null;

			IndexField start = null;
			if (after && startValue == null && maxValue == null) {
				indexIterator = indexTable.fieldKeyIterator(min, max, !after);
				if (indexIterator.hasNext()) {
					indexIterator.next(); // must step beyond max indexed value
				}
			}
			else {
				start =
					startValue != null ? IndexField.getIndexField(startValue, primaryKey) : null;
				indexIterator = indexTable.fieldKeyIterator(min, max, start);
				if (indexIterator.hasNext()) {
					Field f = indexIterator.next();
					if (!after || !f.equals(start)) {
						indexIterator.previous();
					}
				}
			}
		}

		/**
		 * If min or max index values was truncated, a comparison of the actual 
		 * indexed field value (i.e., primary table value) is done with the min and/or max values.
		 * @param f index field from index table iterator
		 * @return true if field value corresponding to f is outside the min/max range.
		 * It is assumed that the underlying table iterator will not return index values 
		 * out of range which do not have the same truncated index value.
		 * @throws IOException
		 */
		private boolean indexValueOutOfRange(IndexField f) throws IOException {
			Field val = null;
			if (min != null && min.usesTruncatedFieldValue() && min.hasSameIndex(f)) {
				Record rec = primaryTable.getRecord(f.getPrimaryKey());
				val = rec.getField(indexColumn);
				if (val.compareTo(min.getNonTruncatedIndexField()) < 0) {
					return true;
				}
			}
			if (max != null && max.usesTruncatedFieldValue() && max.hasSameIndex(f)) {
				if (val == null) {
					Record rec = primaryTable.getRecord(f.getPrimaryKey());
					val = rec.getField(indexColumn);
				}
				if (val.compareTo(min.getNonTruncatedIndexField()) > 0) {
					return true;
				}
			}
			return false;
		}

		/* (non-Javadoc)
		 * @see ghidra.framework.store.db.DBLongIterator#hasNext()
		 */
		@Override
		public boolean hasNext() throws IOException {
			if (hasNext) {
				return true;
			}
			while (indexIterator.hasNext()) {
				hasPrev = false;
				key = (IndexField) indexIterator.next();
				if (!indexValueOutOfRange(key)) {
					hasNext = true;
					break;
				}
			}
			return hasNext;
		}

		/* (non-Javadoc)
		 * @see ghidra.framework.store.db.DBLongIterator#hasPrevious()
		 */
		@Override
		public boolean hasPrevious() throws IOException {
			if (hasPrev) {
				return true;
			}
			while (indexIterator.hasPrevious()) {
				hasNext = false;
				key = (IndexField) indexIterator.previous();
				if (!indexValueOutOfRange(key)) {
					hasPrev = true;
					break;
				}
			}
			return hasPrev;
		}

		/* (non-Javadoc)
		 * @see ghidra.framework.store.db.DBLongIterator#next()
		 */
		@Override
		public long next() throws IOException {
			if (hasNext()) {
				lastKey = key;
				hasNext = false;
				return key.getPrimaryKey();
			}
			throw new NoSuchElementException();
		}

		/* (non-Javadoc)
		 * @see ghidra.framework.store.db.DBLongIterator#previous()
		 */
		@Override
		public long previous() throws IOException {
			if (hasPrevious()) {
				lastKey = key;
				hasPrev = false;
				return key.getPrimaryKey();
			}
			throw new NoSuchElementException();
		}

		/* (non-Javadoc)
		 * @see ghidra.framework.store.db.DBLongIterator#delete()
		 */
		@Override
		public boolean delete() throws IOException {
			if (lastKey != null) {
				long primaryKey = lastKey.getPrimaryKey();
				lastKey = null;
				return primaryTable.deleteRecord(primaryKey);
			}
			return false;
		}
	}

}
