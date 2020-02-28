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

import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>IndexTable</code> maintains a secondary index within a private Table instance.
 * This index facilitates the indexing of non-unique secondary keys within a
 * user Table.
 */
abstract class IndexTable {

	protected static final long[] emptyKeyArray = new long[0];

	/**
	 * Database Handle
	 */
	protected final DBHandle db;

	/**
	 * Master table record for this index table.
	 */
	protected final TableRecord indexTableRecord;

	/**
	 * Primary table
	 */
	protected Table primaryTable;

	/**
	 * Underlying table which contains secondary index data.
	 */
	protected Table indexTable;

	/**
	 * Field type associated with indexed column.
	 */
	protected final Field fieldType;

	/**
	 * Indexed column within primary table schema.
	 */
	protected final int colIndex;

	/**
	 * Construct a new or existing secondary index. An existing index must have
	 * its root ID specified within the tableRecord.
	 * @param primaryTable primary table.
	 * @param indexTableRecord specifies the index parameters.
	 * @throws IOException thrown if IO error occurs
	 */
	IndexTable(Table primaryTable, TableRecord indexTableRecord) throws IOException {
		if (!primaryTable.useLongKeys()) {
			throw new AssertException("Only long-key tables may be indexed");
		}
		this.db = primaryTable.getDBHandle();
		this.primaryTable = primaryTable;
		this.indexTableRecord = indexTableRecord;
		this.indexTable = new Table(primaryTable.getDBHandle(), indexTableRecord);
		this.colIndex = indexTableRecord.getIndexedColumn();
		fieldType = primaryTable.getSchema().getField(indexTableRecord.getIndexedColumn());
		primaryTable.addIndex(this);
	}

	/**
	 * Get the index table for a specified index TableRecord.
	 * @param db database handle
	 * @param indexTableRecord master table record for an index table
	 * @return IndexTable index table
	 * @throws IOException thrown if IO error occurs
	 */
	static IndexTable getIndexTable(DBHandle db, TableRecord indexTableRecord) throws IOException {
		String name = indexTableRecord.getName();
		Table primaryTable = db.getTable(name);
		if (primaryTable == null) {
			throw new AssertException("Table not found: " + name);
		}

		if (indexTableRecord.getSchema().getKeyFieldType() instanceof IndexField) {
			return new FieldIndexTable(primaryTable, indexTableRecord);
		}
		Field fieldType = primaryTable.getSchema().getField(indexTableRecord.getIndexedColumn());
		if (fieldType.isVariableLength()) {
			return new VarIndexTable(primaryTable, indexTableRecord);
		}
		return new FixedIndexTable(primaryTable, indexTableRecord);
	}

	/**
	 * Create a new index table for an empty primary table.
	 * @param primaryTable primary table to be indexed
	 * @param indexColumn primary table column to be indexed
	 * @return IndexTable new index table
	 * @throws IOException thrown if IO error occurs
	 */
	static IndexTable createIndexTable(Table primaryTable, int indexColumn) throws IOException {
		if (primaryTable.getRecordCount() != 0) {
			throw new AssertException();
		}
		return new FieldIndexTable(primaryTable, indexColumn);
	}

	/**
	 * Check the consistency of this index table.
	 * @return true if consistency check passed, else false
	 * @throws IOException 
	 * @throws CancelledException
	 */
	boolean isConsistent(TaskMonitor monitor) throws IOException, CancelledException {
		return indexTable.isConsistent(primaryTable.getSchema().getFieldNames()[colIndex], monitor);
	}

	/**
	 * Get the table number associated with the underlying index table.
	 * @return table number
	 */
	long getTableNum() {
		return indexTable.getTableNum();
	}

	/**
	 * Get the indexed column within the primary table schema.
	 * @return indexed column number
	 */
	int getColumnIndex() {
		return colIndex;
	}

	/**
	 * Get index table statistics
	 * @return statistics data
	 * @throws IOException thrown if IO error occurs
	 */
	TableStatistics getStatistics() throws IOException {
		TableStatistics stats = indexTable.getStatistics();
		stats.indexColumn = colIndex;
		return stats;
	}

	/**
	 * Determine if there is an occurance of the specified index key value.
	 * @param field index key value
	 * @return true if an index key value equal to field exists.
	 */
	boolean hasRecord(Field field) throws IOException {
		return indexTable.hasRecord(field);
	}

	/**
	 * Find all primary keys which correspond to the specified indexed field
	 * value.
	 * @param field the field value to search for.
	 * @return list of primary keys
	 */
	abstract long[] findPrimaryKeys(Field indexValue) throws IOException;

	/**
	 * Get the number of primary keys which correspond to the specified indexed field
	 * value.
	 * @param field the field value to search for.
	 * @return key count
	 */
	abstract int getKeyCount(Field indexValue) throws IOException;

	/**
	 * Add an entry to this index. Caller is responsible for ensuring that this
	 * is not a duplicate entry.
	 * @param record new record
	 * @throws IOException
	 */
	abstract void addEntry(Record record) throws IOException;

	/**
	 * Delete an entry from this index.
	 * @param record deleted record
	 * @throws IOException
	 */
	abstract void deleteEntry(Record record) throws IOException;

	/**
	 * Delete all records within this index table.
	 */
	void deleteAll() throws IOException {
		indexTable.deleteAll();
	}

	/**
	 * Iterate over all index keys.  Index keys are sorted in ascending order.
	 * @return index key iterator
	 * @throws IOException thrown if IO error occurs
	 */
	abstract DBFieldIterator indexIterator() throws IOException;

	/**
	 * Iterate over all the unique index field values within the specified range identified
	 * by minField and maxField.  Index values are returned in an ascending sorted order.
	 * @param minField minimum index column value, if null absolute minimum is used
	 * @param maxField maximum index column value, if null absolute maximum is used
	 * @param before if true initial position is before minField, else position
	 * is after endField
	 * @return index field iterator.
	 * @throws IOException
	 */
	abstract DBFieldIterator indexIterator(Field minField, Field maxField, boolean before)
			throws IOException;

	/**
	 * Iterate over all the unique index field values within the specified range identified
	 * by minField and maxField.  Index values are returned in an ascending sorted order with the 
	 * initial iterator position corresponding to the startField.
	 * @param minField minimum index column value, if null absolute minimum is used
	 * @param maxField maximum index column value, if null absolute maximum is used
	 * @param startField index column value corresponding to initial position of iterator
	 * @param before if true initial position is before startField value, else position
	 * is after startField value
	 * @return index field iterator.
	 * @throws IOException
	 */
	abstract DBFieldIterator indexIterator(Field minField, Field maxField, Field startField,
			boolean before) throws IOException;

	/**
	 * Iterate over all primary keys sorted based upon the associated index key.
	 * @return primary key iterator
	 * @throws IOException thrown if IO error occurs
	 */
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
	DBLongIterator keyIteratorAfter(Field startField, long primaryKey) throws IOException {
		return new PrimaryKeyIterator(null, null, startField, primaryKey, true);
	}

	/**
	 * Iterate over all primary keys sorted based upon the associated index key.
	 * The iterator is limited to range of index keys of minField through maxField, inclusive.
	 * If before is true, the iterator is initially positioned before the first index 
	 * buffer whose index key is greater than or equal to the specified minField value. 
	 * If before is false, the iterator is initially positioned after the first index 
	 * buffer whose index key is less than or equal to the specified maxField value. 
	 * @param minField minimum index key value
	 * @param maxField maximum index key value
	 * @param before if true, position iterator before minField value, 
	 * Otherwise, position iterator after maxField value.
	 * @return primary key iterator
	 * @throws IOException thrown if IO error occurs
	 */
	DBLongIterator keyIterator(Field minField, Field maxField, boolean before) throws IOException {

		Field startField = before ? minField : maxField;

		if (startField == null && !before) {

		}

		return new PrimaryKeyIterator(minField, maxField, before ? minField : maxField,
			before ? Long.MIN_VALUE : Long.MAX_VALUE, !before);
	}

	/**
	 * Iterate over all primary keys sorted based upon the associated index key.
	 * The iterator is limited to range of index keys of minField through maxField, inclusive.
	 * The iterator is initially positioned before or after the specified startField index value. 
	 * @param minField minimum index key value
	 * @param maxField maximum index key value
	 * @param startField starting indexed value position
	 * @param before if true positioned before startField value, else positioned after maxField value
	 * @return primary key iterator
	 * @throws IOException thrown if IO error occurs
	 */
	DBLongIterator keyIterator(Field minField, Field maxField, Field startField, boolean before)
			throws IOException {
		return new PrimaryKeyIterator(minField, maxField, startField,
			before ? Long.MIN_VALUE : Long.MAX_VALUE, !before);
	}

	/**
	 * Iterates over primary keys for a range of index field values.
	 */
	private class PrimaryKeyIterator implements DBLongIterator {

		private RecordIterator indexIterator;
		private int expectedModCount;

		private int index;
		private long indexPrimaryKey;
		private IndexBuffer indexBuffer;
		private boolean forward = true;
		private boolean reverse = true;
		private Field lastKey;

		private boolean hasPrev = false;
		private boolean hasNext = false;

		/**
		 * Construct a key iterator starting with the minimum secondary key.
		 */
		PrimaryKeyIterator() throws IOException {
			expectedModCount = indexTable.modCount;
			indexIterator = indexTable.iterator();
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
		 * @param primaryKey starting primary key value.
		 * @param after if true iterator is positioned immediately after 
		 * the startValue/primaryKey,
		 * otherwise immediately before.
		 * @throws IOException
		 */
		PrimaryKeyIterator(Field minValue, Field maxValue, Field startValue, long primaryKey,
				boolean after) throws IOException {
			expectedModCount = indexTable.modCount;
			indexIterator = indexTable.iterator(minValue, maxValue, startValue);

			if (hasNext()) {
				if (startValue.equals(indexBuffer.getIndexKey())) {
					index = indexBuffer.getIndex(primaryKey);
					if (index < 0) {
						index = -index - 1;
					}
					else if (after) {
						index++;
					}
					if (index == indexBuffer.keyCount) {
						--index;
						indexPrimaryKey = indexBuffer.getPrimaryKey(index);
						hasNext = false;
						hasPrev = true;
					}
				}
			}
		}

		@Override
		public boolean hasNext() throws IOException {
			if (hasNext) {
				return true;
			}
			synchronized (db) {

				// Handle concurrent modification if necessary
				// This is a slightly lazy approach which could miss keys added to the end of an index buffer
				if (indexBuffer != null && index < (indexBuffer.keyCount - 1) &&
					indexTable.modCount != expectedModCount) {

					// refetch index buffer which may have changed
					Field indexKey = indexBuffer.getIndexKey();
					Record indexRecord;
					if (indexKey.isVariableLength()) {
						indexRecord = indexTable.getRecord(indexKey);
					}
					else {
						indexRecord = indexTable.getRecord(indexKey.getLongValue());
					}
					if (indexRecord != null) {

						// recover position within index buffer
						indexBuffer = new IndexBuffer(indexKey, indexRecord.getBinaryData(0));
						index = indexBuffer.getIndex(indexPrimaryKey + 1);
						if (index < 0) {
							index = -index - 1;
							if (index == indexBuffer.keyCount) {
								// next must be found in next index buffer below
								indexBuffer = null;
							}
							else {
								indexPrimaryKey = indexBuffer.getPrimaryKey(index);
								hasNext = true;
							}
						}
						else {
							indexPrimaryKey = indexBuffer.getPrimaryKey(index);
							hasNext = true;
						}
					}
					else {
						// index buffer no longer exists - will need to get next buffer below
						indexBuffer = null;
					}
					hasPrev = false;
				}

				if (!hasNext) {
					// Goto next index buffer
					if ((indexBuffer == null || index >= (indexBuffer.keyCount) - 1)) {
						// get next index buffer
						Record indexRecord = indexIterator.next();
						if (indexRecord != null) {
							if (!forward) {
								indexRecord = indexIterator.next();
								forward = true;
							}
							reverse = false;
							if (indexRecord != null) {
								indexBuffer =
									new IndexBuffer(fieldType.newField(indexRecord.getKeyField()),
										indexRecord.getBinaryData(0));
								index = 0;
								indexPrimaryKey = indexBuffer.getPrimaryKey(index);
								hasNext = true;
								hasPrev = false;
							}
						}
					}

					// Step within current index buffer
					else {
						++index;
						indexPrimaryKey = indexBuffer.getPrimaryKey(index);
						hasNext = true;
						hasPrev = false;
					}
				}
				expectedModCount = indexTable.modCount;
				return hasNext;
			}
		}

		@Override
		public boolean hasPrevious() throws IOException {
			if (hasPrev) {
				return true;
			}
			synchronized (db) {

				// Handle concurrent modification if necessary
				// This is a slightly lazy approach which could miss keys added to the beginning of an index buffer
				if (indexBuffer != null && index > 0 && indexTable.modCount != expectedModCount) {

					// refetch index buffer which may have changed
					Field indexKey = indexBuffer.getIndexKey();
					Record indexRecord; // refetch index buffer which may have changed
					if (indexKey.isVariableLength()) {
						indexRecord = indexTable.getRecord(indexKey);
					}
					else {
						indexRecord = indexTable.getRecord(indexKey.getLongValue());
					}
					if (indexRecord != null) {

						// recover position within index buffer
						indexBuffer = new IndexBuffer(indexKey, indexRecord.getBinaryData(0));
						index = indexBuffer.getIndex(indexPrimaryKey - 1);
						if (index < 0) {
							index = -index - 1;
							if (index == 0) {
								// previous must be found in previous index buffer below
								indexBuffer = null;
							}
							else {
								--index;
								indexPrimaryKey = indexBuffer.getPrimaryKey(index);
								hasPrev = true;
							}
						}
						else {
							indexPrimaryKey = indexBuffer.getPrimaryKey(index);
							hasPrev = true;
						}
					}
					else {
						indexBuffer = null;
					}
					hasNext = false;
				}

				if (!hasPrev) {
					// Goto previous index buffer
					if ((indexBuffer == null || index == 0)) {
						// get previous index buffer
						Record indexRecord = indexIterator.previous();
						if (indexRecord != null) {
							if (!reverse) {
								indexRecord = indexIterator.previous();
								reverse = true;
							}
							forward = false;
							if (indexRecord != null) {
								indexBuffer =
									new IndexBuffer(fieldType.newField(indexRecord.getKeyField()),
										indexRecord.getBinaryData(0));
								index = indexBuffer.keyCount - 1;
								indexPrimaryKey = indexBuffer.getPrimaryKey(index);
								hasNext = false;
								hasPrev = true;
							}
						}
					}

					// Step within current index buffer
					else {
						--index;
						indexPrimaryKey = indexBuffer.getPrimaryKey(index);
						hasNext = false;
						hasPrev = true;
					}
				}
				expectedModCount = indexTable.modCount;
				return hasPrev;
			}
		}

		@Override
		public long next() throws IOException {
			if (hasNext || hasNext()) {
				long key = indexBuffer.getPrimaryKey(index);
				lastKey = new LongField(key);
				hasNext = false;
				hasPrev = true;
				return key;
			}
			throw new NoSuchElementException();
		}

		@Override
		public long previous() throws IOException {
			if (hasPrev || hasPrevious()) {
				long key = indexBuffer.getPrimaryKey(index);
				lastKey = new LongField(key);
				hasNext = true;
				hasPrev = false;
				return key;
			}
			throw new NoSuchElementException();
		}

		/**
		 * WARNING: This could be slow since the index buffer must be read
		 * after each record deletion.
		 * @see db.DBLongIterator#delete()
		 */
		@Override
		public boolean delete() throws IOException {
			if (lastKey == null) {
				return false;
			}
			synchronized (db) {
				long key = lastKey.getLongValue();
				primaryTable.deleteRecord(key);
				lastKey = null;
				return true;
			}
		}
	}

}
