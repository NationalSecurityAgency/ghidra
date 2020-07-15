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

/**
 * The <code>VarIndexTable</code> provides a secondary index on a variable-length table column
 * (e.g., StringField).  For each unique secondary index value, an IndexBuffer is 
 * stored within an underlying index table record.  The secondary index value is used as the long
 * key to access this record.  Within a single IndexBuffer is stored all primary keys which 
 * correspond to an index value.
 */
class VarIndexTable extends IndexTable {

	private static final Class<?>[] fieldClasses = { BinaryField.class, 	// index data
	};

	private static final String[] fieldNames = { "IndexBuffer" };

	private Schema indexSchema;

	/**
	 * Construct a new secondary index which is based upon a field within the
	 * primary table specified by name.
	 * @param primaryTable primary table.
	 * @param colIndex identifies the indexed column within the primary table.
	 * @throws IOException thrown if an IO error occurs
	 */
	VarIndexTable(Table primaryTable, int colIndex) throws IOException {
		this(primaryTable,
			primaryTable.getDBHandle().getMasterTable().createTableRecord(primaryTable.getName(),
				new Schema(0, primaryTable.getSchema().getField(colIndex).getClass(), "IndexKey",
					fieldClasses, fieldNames),
				colIndex));
	}

	/**
	 * Construct a new or existing secondary index. An existing index must have
	 * its root ID specified within the tableRecord.
	 * @param primaryTable primary table.
	 * @param indexTableRecord specifies the index parameters.
	 * @throws IOException thrown if an IO error occurs 
	 */
	VarIndexTable(Table primaryTable, TableRecord indexTableRecord) throws IOException {
		super(primaryTable, indexTableRecord);
		this.indexSchema = indexTable.getSchema();
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
		Record indexRecord = indexTable.getRecord(indexValue);
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
	 * @throws IOException thrown if an IO error occurs
	 */
	@Override
	int getKeyCount(Field indexValue) throws IOException {
		if (!indexValue.getClass().equals(fieldType.getClass())) {
			throw new IllegalArgumentException("Incorrect indexed field type");
		}
		Record indexRecord = indexTable.getRecord(indexValue);
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
		Record indexRecord = indexTable.getRecord(indexField);
		if (indexRecord == null) {
			indexRecord = indexSchema.createRecord(indexField);
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
		Record indexRecord = indexTable.getRecord(indexField);
		if (indexRecord != null) {
			IndexBuffer indexBuffer = new IndexBuffer(indexField, indexRecord.getBinaryData(0));
			indexBuffer.deleteEntry(record.getKey());
			byte[] data = indexBuffer.getData();
			if (data == null) {
				indexTable.deleteRecord(indexField);
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
		Record indexRec = indexTable.getRecord(indexKey);
		return indexRec != null ? new IndexBuffer(indexKey, indexRec.getBinaryData(0)) : null;
	}

	/*
	 * @see ghidra.framework.store.db.IndexTable#indexIterator()
	 */
	@Override
	DBFieldIterator indexIterator() throws IOException {
		return new IndexVarFieldIterator();
	}

	/*
	 * @see ghidra.framework.store.db.IndexTable#indexIterator(ghidra.framework.store.db.Field, ghidra.framework.store.db.Field, boolean)
	 */
	@Override
	DBFieldIterator indexIterator(Field minField, Field maxField, boolean before)
			throws IOException {
		return new IndexVarFieldIterator(minField, maxField, before);
	}

	/*
	 * @see db.IndexTable#indexIterator(db.Field, db.Field, db.Field, boolean)
	 */
	@Override
	DBFieldIterator indexIterator(Field minField, Field maxField, Field startField, boolean before)
			throws IOException {
		return new IndexVarFieldIterator(minField, maxField, startField, before);
	}

	/**
	 * Iterates over index field values within a specified range.
	 */
	class IndexVarFieldIterator implements DBFieldIterator {

		private Field lastKey;
		private Field keyField;
		private DBFieldIterator indexIterator;
		private boolean hasNext = false;
		private boolean hasPrev = false;

		/**
		 * Construct an index field iterator starting with the minimum index value.
		 */
		IndexVarFieldIterator() throws IOException {
			this(null, null, true);
		}

		/**
		 * Construct an index field iterator.  The iterator is positioned at index 
		 * value identified by startValue.
		 * @param minValue minimum index value.  Null corresponds to minimum indexed value.
		 * @param maxValue maximum index value.  Null corresponds to maximum indexed value.
		 * @param before if true initial position is before minValue, else position
		 * is after maxValue. 
		 * @throws IOException
		 */
		IndexVarFieldIterator(Field minValue, Field maxValue, boolean before) throws IOException {

			indexIterator = indexTable.fieldKeyIterator(minValue, maxValue, before);

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
		 * @param minValue minimum index value.  Null corresponds to minimum indexed value.
		 * @param maxValue maximum index value.  Null corresponds to maximum indexed value.
		 * @param startValue identify initial position by value
		 * @param before if true initial position is before minValue, else position
		 * is after maxValue.
		 * @throws IOException
		 */
		IndexVarFieldIterator(Field minValue, Field maxValue, Field startValue, boolean before)
				throws IOException {

			if (startValue == null) {
				throw new IllegalArgumentException("starting index value required");
			}
			indexIterator = indexTable.fieldKeyIterator(minValue, maxValue, startValue);

			if (indexIterator.hasNext()) {
				Field f = indexIterator.next();
				if (before || !f.equals(startValue)) {
					indexIterator.previous();
				}
			}
		}

		@Override
		public boolean hasNext() throws IOException {
			if (hasNext) {
				return true;
			}
			Field key = indexIterator.next();
			if (key == null) {
				return false;
			}
			keyField = key;
			hasNext = true;
			hasPrev = false;
			return true;
		}

		@Override
		public boolean hasPrevious() throws IOException {
			if (hasPrev) {
				return true;
			}
			Field key = indexIterator.previous();
			if (key == null) {
				return false;
			}
			keyField = key;
			hasNext = false;
			hasPrev = true;
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
//					indexIterator.delete();
				}
				lastKey = null;
				return true;
			}
		}
	}

}
