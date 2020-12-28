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

/**
 * <code>FieldIndexTable</code> provides a simplified index table whoose key is
 * a fixed or variable length {@link IndexField} which consists of a concatenation of 
 * the index field value and associated primary table key.
 */
public class FieldIndexTable extends IndexTable {

	private static final Field[] fields = {};

	private static final String[] fieldNames = {};

	private final IndexField indexKeyType;

	/**
	 * Construct a new secondary index which is based upon a specific field column within the
	 * primary table.
	 * @param primaryTable primary table
	 * @param colIndex field column index
	 * @throws IOException thrown if IO error occurs
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
		indexKeyType = (IndexField) indexTable.getSchema().getKeyFieldType();
	}

	/**
	 * Generate index table schema for specified primaryTable and index column
	 * @param primaryTable primary table
	 * @param colIndex index column
	 * @return index table schema
	 */
	private static Schema getIndexTableSchema(Table primaryTable, int colIndex) {
		Schema primarySchema = primaryTable.getSchema();
		Field indexedField = primarySchema.getField(colIndex);
		Field primaryKeyType = primarySchema.getKeyFieldType();
		IndexField indexKeyField = new IndexField(indexedField, primaryKeyType);
		return new Schema(0, indexKeyField, "IndexKey", fields, fieldNames);
	}

	@Override
	Field[] findPrimaryKeys(Field indexValue) throws IOException {

		IndexField indexField =
			indexKeyType.newIndexField(indexValue, getPrimaryTableKeyType().getMinValue());

		DBFieldIterator iter = indexTable.fieldKeyIterator(indexField);
		ArrayList<IndexField> list = new ArrayList<>(20);
		while (iter.hasNext()) {
			IndexField f = (IndexField) iter.next();
			if (!f.hasSameIndexValue(indexField)) {
				break;
			}
			if (indexField.usesTruncatedFieldValue()) {
				// Must check actual record if index value was truncated
				DBRecord rec = primaryTable.getRecord(f.getPrimaryKey());
				Field val = rec.getField(indexColumn);
				if (!indexValue.equals(val)) {
					continue;
				}
			}
			list.add(f);
		}
		Field[] keys = new Field[list.size()];
		for (int i = 0; i < keys.length; i++) {
			IndexField f = list.get(i);
			keys[i] = f.getPrimaryKey();
		}
		return keys;
	}

	@Override
	int getKeyCount(Field indexValue) throws IOException {
		return findPrimaryKeys(indexValue).length;
	}

	@Override
	void addEntry(DBRecord record) throws IOException {
		Field indexedField = record.getField(indexColumn);
		if (isSparseIndex && indexedField.isNull()) {
			return;
		}
		IndexField f = indexKeyType.newIndexField(indexedField, record.getKeyField());
		DBRecord rec = indexTable.getSchema().createRecord(f);
		indexTable.putRecord(rec);
	}

	@Override
	void deleteEntry(DBRecord record) throws IOException {
		Field indexedField = record.getField(indexColumn);
		if (isSparseIndex && indexedField.isNull()) {
			return;
		}
		IndexField f = indexKeyType.newIndexField(indexedField, record.getKeyField());
		indexTable.deleteRecord(f);
	}

	@Override
	DBFieldIterator indexIterator() throws IOException {
		return new IndexFieldIterator();
	}

	@Override
	DBFieldIterator indexIterator(Field minField, Field maxField, boolean before)
			throws IOException {
		return new IndexFieldIterator(minField, maxField, before);
	}

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
		 * @throws IOException an IO error occurred
		 */
		IndexFieldIterator() throws IOException {
			this(null, null, true);
		}

		/**
		 * Construct an index field iterator. 
		 * @param minValue minimum index value or null if no minimum
		 * @param maxValue maximum index value or null if no maximum
		 * @param before if true initial position is before minValue, else position
		 * after maxValue
		 * @throws IOException an IO error occurred
		 */
		IndexFieldIterator(Field minValue, Field maxValue, boolean before) throws IOException {

			if (primaryTable.getSchema().getField(indexColumn).isVariableLength()) {
				throw new UnsupportedOperationException(
					"Due to potential truncation issues, operation not permitted on variable length fields");
			}

			Field primaryKeyType = getPrimaryTableKeyType();
			min = minValue != null
					? indexKeyType.newIndexField(minValue, primaryKeyType.getMinValue())
					: null;
			max = maxValue != null
					? indexKeyType.newIndexField(maxValue, primaryKeyType.getMaxValue())
					: null;

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
		 * Construct an index field iterator.  The iterator is positioned at index 
		 * value identified by startValue.
		 * @param minValue minimum index value or null if no minimum
		 * @param maxValue maximum index value or null if no maximum
		 * @param startValue initial index value position
		 * @param before if true initial position is before minValue, else position
		 * after maxValue
		 * @throws IOException an IO error occurred
		 */
		IndexFieldIterator(Field minValue, Field maxValue, Field startValue, boolean before)
				throws IOException {

			if (primaryTable.getSchema().getField(indexColumn).isVariableLength()) {
				throw new UnsupportedOperationException(
					"Due to potential truncation issues, operation not permitted on variable length fields");
			}

			if (startValue == null) {
				throw new IllegalArgumentException("starting index value required");
			}

			Field primaryKeyType = getPrimaryTableKeyType();
			min = minValue != null
					? indexKeyType.newIndexField(minValue, primaryKeyType.getMinValue())
					: null;
			max = maxValue != null
					? indexKeyType.newIndexField(maxValue, primaryKeyType.getMaxValue())
					: null;

			IndexField start = indexKeyType.newIndexField(startValue,
				before ? primaryKeyType.getMinValue() : primaryKeyType.getMaxValue());

			indexIterator = indexTable.fieldKeyIterator(min, max, start);

			if (indexIterator.hasNext()) {
				IndexField f = (IndexField) indexIterator.next();
				if (before || !f.getIndexedField().equals(startValue)) {
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
			while (indexKey != null && indexKey.hasSameIndexValue(lastKey)) {
				if (++skipCnt > 10) {
					// Reinit iterator to skip large number of same index value
					indexIterator =
						indexTable.fieldKeyIterator(min, max, indexKeyType.newIndexField(
							indexKey.getIndexedField(), getPrimaryTableKeyType().getMaxValue()));
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
			while (indexKey != null && indexKey.hasSameIndexValue(lastKey)) {
				if (++skipCnt > 10) {
					// Reinit iterator to skip large number of same index value
					indexIterator =
						indexTable.fieldKeyIterator(min, max, indexKeyType.newIndexField(
							indexKey.getIndexedField(), getPrimaryTableKeyType().getMinValue()));
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
				return indexKey.getIndexedField();
			}
			return null;
		}

		@Override
		public Field previous() throws IOException {
			if (hasPrev || hasPrevious()) {
				hasNext = true;
				hasPrev = false;
				lastKey = indexKey;
				return indexKey.getIndexedField();
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
				Field[] keys = findPrimaryKeys(lastKey.getIndexedField());
				for (Field key : keys) {
					primaryTable.deleteRecord(key);
				}
				lastKey = null;
				return true;
			}
		}
	}

	@Override
	boolean hasRecord(Field field) throws IOException {
		IndexField indexField =
			indexKeyType.newIndexField(field, getPrimaryTableKeyType().getMinValue());
		DBFieldIterator iter = indexTable.fieldKeyIterator(indexField);
		while (iter.hasNext()) {
			IndexField f = (IndexField) iter.next();
			if (!f.hasSameIndexValue(indexField)) {
				return false;
			}
			if (indexField.usesTruncatedFieldValue()) {
				// Must check actual record if index value was truncated
				DBRecord rec = primaryTable.getRecord(f.getPrimaryKey());
				Field val = rec.getField(indexColumn);
				if (!field.equals(val)) {
					continue; // skip
				}
			}
			return true;
		}
		return false;
	}

	@Override
	DBFieldIterator keyIterator() throws IOException {
		return new PrimaryKeyIterator();
	}

	@Override
	DBFieldIterator keyIteratorBefore(Field startField) throws IOException {
		return new PrimaryKeyIterator(startField, false);
	}

	@Override
	DBFieldIterator keyIteratorAfter(Field startField) throws IOException {
		return new PrimaryKeyIterator(startField, true);
	}

	@Override
	DBFieldIterator keyIteratorBefore(Field startField, Field primaryKey) throws IOException {
		return new PrimaryKeyIterator(null, null, startField, primaryKey, false);
	}

	@Override
	DBFieldIterator keyIteratorAfter(Field startField, Field primaryKey) throws IOException {
		return new PrimaryKeyIterator(null, null, startField, primaryKey, true);
	}

	@Override
	DBFieldIterator keyIterator(Field startField, Field endField, boolean atStart)
			throws IOException {
		return new PrimaryKeyIterator(startField, endField, atStart ? startField : endField,
			atStart ? getPrimaryTableKeyType().getMinValue()
					: getPrimaryTableKeyType().getMaxValue(),
			!atStart);
	}

	@Override
	DBFieldIterator keyIterator(Field minField, Field maxField, Field startField, boolean before)
			throws IOException {
		return new PrimaryKeyIterator(minField, maxField, startField,
			before ? getPrimaryTableKeyType().getMinValue()
					: getPrimaryTableKeyType().getMaxValue(),
			!before);
	}

	/**
	 * Iterates over primary keys which correspond to index field values within a specified range.
	 * NOTE: Primary keys corresponding to index fields which have been truncated may be returned out of order.
	 */
	private class PrimaryKeyIterator implements DBFieldIterator {

		private IndexField min;
		private IndexField max;
		private DBFieldIterator indexIterator;

		private boolean hasNext = false;
		private boolean hasPrev = false;
		private IndexField key;
		private IndexField lastKey;

		/**
		 * Construct a key iterator starting with the minimum secondary key.
		 * @throws IOException thrown if IO error occurs
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
		 * @throws IOException thrown if IO error occurs
		 */
		PrimaryKeyIterator(Field startValue, boolean after) throws IOException {
			this(null, null, startValue, after ? getPrimaryTableKeyType().getMaxValue()
					: getPrimaryTableKeyType().getMinValue(),
				after);
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
		 * @throws IOException thrown if IO error occurs
		 */
		PrimaryKeyIterator(Field minValue, Field maxValue, Field startValue, Field primaryKey,
				boolean after) throws IOException {

			Field primaryKeyType = getPrimaryTableKeyType();
			min = minValue != null
					? indexKeyType.newIndexField(minValue, primaryKeyType.getMinValue())
					: null;
			max = maxValue != null
					? indexKeyType.newIndexField(maxValue, primaryKeyType.getMaxValue())
					: null;

			IndexField start = null;
			if (after && startValue == null && maxValue == null) {
				indexIterator = indexTable.fieldKeyIterator(min, max, !after);
				if (indexIterator.hasNext()) {
					indexIterator.next(); // must step beyond max indexed value
				}
			}
			else {
				start =
					startValue != null ? indexKeyType.newIndexField(startValue, primaryKey) : null;
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
		 * @throws IOException thrown if IO error occurs
		 */
		private boolean indexValueOutOfRange(IndexField f) throws IOException {
			Field val = null;
			if (min != null && min.usesTruncatedFieldValue() && min.hasSameIndexValue(f)) {
				DBRecord rec = primaryTable.getRecord(f.getPrimaryKey());
				val = rec.getField(indexColumn);
				if (val.compareTo(min.getNonTruncatedIndexField()) < 0) {
					return true;
				}
			}
			if (max != null && max.usesTruncatedFieldValue() && max.hasSameIndexValue(f)) {
				if (val == null) {
					DBRecord rec = primaryTable.getRecord(f.getPrimaryKey());
					val = rec.getField(indexColumn);
				}
				if (val.compareTo(min.getNonTruncatedIndexField()) > 0) {
					return true;
				}
			}
			return false;
		}

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

		@Override
		public Field next() throws IOException {
			if (hasNext()) {
				lastKey = key;
				hasNext = false;
				return key.getPrimaryKey();
			}
			throw new NoSuchElementException();
		}

		@Override
		public Field previous() throws IOException {
			if (hasPrevious()) {
				lastKey = key;
				hasPrev = false;
				return key.getPrimaryKey();
			}
			throw new NoSuchElementException();
		}

		@Override
		public boolean delete() throws IOException {
			if (lastKey != null) {
				Field primaryKey = lastKey.getPrimaryKey();
				lastKey = null;
				return primaryTable.deleteRecord(primaryKey);
			}
			return false;
		}
	}

}
