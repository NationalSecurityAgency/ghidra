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

import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>IndexTable</code> maintains a secondary index within a private Table instance.
 * This index facilitates the indexing of non-unique secondary keys within a
 * user Table.
 */
abstract class IndexTable {

	protected static final Field[] emptyKeyArray = Field.EMPTY_ARRAY;

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
	 * Indexed column within primary table schema.
	 */
	protected final int indexColumn;
	protected final boolean isSparseIndex;

	/**
	 * Construct a new or existing secondary index. An existing index must have
	 * its root ID specified within the tableRecord.
	 * @param primaryTable primary table.
	 * @param indexTableRecord specifies the index parameters.
	 * @throws IOException thrown if IO error occurs
	 */
	IndexTable(Table primaryTable, TableRecord indexTableRecord) throws IOException {
		if (!primaryTable.useLongKeys() && !primaryTable.useFixedKeys()) {
			throw new AssertException("Only fixed-length key tables may be indexed");
		}
		this.db = primaryTable.getDBHandle();
		this.primaryTable = primaryTable;
		this.indexTableRecord = indexTableRecord;
		this.indexTable = new Table(primaryTable.getDBHandle(), indexTableRecord);
		this.indexColumn = indexTableRecord.getIndexedColumn();
		this.isSparseIndex = primaryTable.getSchema().isSparseColumn(indexColumn);
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

		Field keyFieldType = indexTableRecord.getSchema().getKeyFieldType();
		if (keyFieldType instanceof IndexField) {
			return new FieldIndexTable(primaryTable, indexTableRecord);
		}
		throw new AssertException(
			"Unexpected index field type: " + keyFieldType.getClass().getName());
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
	 * @param monitor task monitor
	 * @return true if consistency check passed, else false
	 * @throws IOException if IO error occurs
	 * @throws CancelledException if task cancelled
	 */
	boolean isConsistent(TaskMonitor monitor) throws IOException, CancelledException {
		return indexTable.isConsistent(primaryTable.getSchema().getFieldNames()[indexColumn],
			monitor);
	}

	/**
	 * Get the primary table key type
	 * @return primary table key type
	 */
	Field getPrimaryTableKeyType() {
		return primaryTable.getSchema().getKeyFieldType();
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
		return indexColumn;
	}

	/**
	 * Get index table statistics
	 * @return statistics data
	 * @throws IOException thrown if IO error occurs
	 */
	TableStatistics getStatistics() throws IOException {
		TableStatistics stats = indexTable.getStatistics();
		stats.indexColumn = indexColumn;
		return stats;
	}

	/**
	 * Determine if there is an occurance of the specified index key value.
	 * @param field index key value
	 * @return true if an index key value equal to field exists.
	 * @throws IOException if IO error occurs
	 */
	boolean hasRecord(Field field) throws IOException {
		return indexTable.hasRecord(field);
	}

	/**
	 * Find all primary keys which correspond to the specified indexed field
	 * value.
	 * @param indexValue the field value to search for.
	 * @return list of primary keys
	 * @throws IOException if IO error occurs
	 */
	abstract Field[] findPrimaryKeys(Field indexValue) throws IOException;

	/**
	 * Get the number of primary keys which correspond to the specified indexed field
	 * value.
	 * @param indexValue the field value to search for.
	 * @return key count
	 * @throws IOException if IO error occurs
	 */
	abstract int getKeyCount(Field indexValue) throws IOException;

	/**
	 * Add an entry to this index. Caller is responsible for ensuring that this
	 * is not a duplicate entry.
	 * @param record new record
	 * @throws IOException if IO error occurs
	 */
	abstract void addEntry(DBRecord record) throws IOException;

	/**
	 * Delete an entry from this index.
	 * @param oldRecord deleted record
	 * @throws IOException if IO error occurs
	 */
	abstract void deleteEntry(DBRecord oldRecord) throws IOException;

	/**
	 * Delete all records within this index table.
	 * @throws IOException if IO error occurs
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
	 * @throws IOException if IO error occurs
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
	 * @throws IOException if IO error occurs
	 */
	abstract DBFieldIterator indexIterator(Field minField, Field maxField, Field startField,
			boolean before) throws IOException;

	/**
	 * Iterate over all primary keys sorted based upon the associated index key.
	 * @return primary key iterator
	 * @throws IOException thrown if IO error occurs
	 */
	abstract DBFieldIterator keyIterator() throws IOException;

	/**
	 * Iterate over all primary keys sorted based upon the associated index key.
	 * The iterator is initially positioned before the first index buffer whose index key 
	 * is greater than or equal to the specified startField value.
	 * @param startField index key value which determines initial position of iterator
	 * @return primary key iterator
	 * @throws IOException thrown if IO error occurs
	 */
	abstract DBFieldIterator keyIteratorBefore(Field startField) throws IOException;

	/**
	 * Iterate over all primary keys sorted based upon the associated index key.
	 * The iterator is initially positioned after the index buffer whose index key 
	 * is equal to the specified startField value or immediately before the first 
	 * index buffer whose index key is greater than the specified startField value.
	 * @param startField index key value which determines initial position of iterator
	 * @return primary key iterator
	 * @throws IOException thrown if IO error occurs
	 */
	abstract DBFieldIterator keyIteratorAfter(Field startField) throws IOException;

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
	abstract DBFieldIterator keyIteratorBefore(Field startField, Field primaryKey)
			throws IOException;

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
	abstract DBFieldIterator keyIteratorAfter(Field startField, Field primaryKey)
			throws IOException;

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
	abstract DBFieldIterator keyIterator(Field minField, Field maxField, boolean before)
			throws IOException;

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
	abstract DBFieldIterator keyIterator(Field minField, Field maxField, Field startField,
			boolean before) throws IOException;

}
