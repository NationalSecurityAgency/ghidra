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

import db.Field.UnsupportedFieldException;

/**
 * <code>TableRecord</code> manages information about a table.  Each TableRecord 
 * corresponds to a stored record within the master table.
 */
class TableRecord implements Comparable<TableRecord> {

	private static final int NAME_COLUMN = 0;
	private static final int VERSION_COLUMN = 1;
	private static final int BUFFER_ID_COLUMN = 2;
	private static final int KEY_TYPE_COLUMN = 3;
	private static final int FIELD_TYPES_COLUMN = 4;
	private static final int FIELD_NAMES_COLUMN = 5;
	private static final int COLUMN_INDEXED_COLUMN = 6;
	private static final int MAX_KEY_COLUMN = 7;
	private static final int RECORD_COUNT_COLUMN = 8;

	private static Class<?>[] fieldClasses = { StringField.class, 	// name of table 
		IntField.class,    	// Schema version
		IntField.class,    	// Root buffer ID (first buffer)
		ByteField.class,		// Key field type 
		BinaryField.class, 	// Schema field types
		StringField.class,		// Schema key/field names
		IntField.class,		// indexing column  (-1 = primary)
		LongField.class,		// max primary key value ever used
		IntField.class 		// number of records
	};

	private static String[] tableRecordFieldNames = { "TableName", "SchemaVersion", "RootBufferId",
		"KeyType", "FieldTypes", "FieldNames", "IndexColumn", "MaxKey", "RecordCount" };

	private static Schema schema = new Schema(0, "TableNum", fieldClasses, tableRecordFieldNames);

	private Record record;

	private Table table;

	/**
	 * Construct a new master table record.
	 * @param tableNum table number assigned by master table
	 * @param name table name (index tables use same name as indexed table)
	 * @param tableSchema table schema
	 * @param indexedColumn primary table index key column, or -1 for primary table
	 */
	TableRecord(long tableNum, String name, Schema tableSchema, int indexedColumn) {
		record = schema.createRecord(tableNum);
		record.setString(NAME_COLUMN, name);
		record.setByteValue(KEY_TYPE_COLUMN, tableSchema.getKeyFieldType().getFieldType());
		record.setBinaryData(FIELD_TYPES_COLUMN, tableSchema.getFieldTypes());
		record.setString(FIELD_NAMES_COLUMN, tableSchema.getPackedFieldNames());
		record.setIntValue(VERSION_COLUMN, tableSchema.getVersion());
		record.setIntValue(COLUMN_INDEXED_COLUMN, indexedColumn);
		record.setLongValue(MAX_KEY_COLUMN, Long.MIN_VALUE);
		record.setIntValue(RECORD_COUNT_COLUMN, 0);
		record.setIntValue(BUFFER_ID_COLUMN, -1);   // first buffer not yet allocated
	}

	/**
	 * Construct an existing master table storage record.
	 * @param record master table storage record.
	 */
	TableRecord(Record record) {
		this.record = record;
	}

	/**
	 * Get the underlying storage record for this instance.
	 * @return master table storage record.
	 */
	Record getRecord() {
		return record;
	}

	/**
	 * Set the table instance associated with this master table record.
	 * @param table table instance
	 */
	void setTable(Table table) {
		this.table = table;
	}

	/**
	 * Set the storage record for this instance.
	 * Data is refreshed from the record provided.
	 * @param record master table storage record.
	 */
	void setRecord(Record record) {
		this.record = record;
		if (table != null) {
			table.tableRecordChanged();
		}
	}

	/**
	 * Mark this instance as invalid.
	 * This method should be invoked if the associated master table record
	 * is deleted.
	 */
	void invalidate() {
		if (table != null) {
			table.invalidate();
			table = null;
		}
		this.record = null;
	}

	/**
	 * Get the table number
	 * @return table number
	 */
	long getTableNum() {
		return record.getKey();
	}

	/**
	 * Get the table name
	 * @return table name
	 */
	String getName() {
		return record.getString(NAME_COLUMN);
	}

	/**
	 * Set the table name
	 * @param name
	 */
	void setName(String name) {
		record.setString(NAME_COLUMN, name);
	}

	/**
	 * Get the table schema
	 * @return table schema
	 * @throws UnsupportedFieldException if unsupported schema field encountered
	 */
	Schema getSchema() throws UnsupportedFieldException {
		return new Schema(record.getIntValue(VERSION_COLUMN), record.getByteValue(KEY_TYPE_COLUMN),
			record.getBinaryData(FIELD_TYPES_COLUMN), record.getString(FIELD_NAMES_COLUMN));
	}

	/**
	 * Get the table's root buffer ID
	 * @return root buffer ID
	 */
	int getRootBufferId() {
		return record.getIntValue(BUFFER_ID_COLUMN);
	}

	/**
	 * Set the tables root buffer ID
	 * @param id table's root buffer ID
	 */
	void setRootBufferId(int id) {
		record.setIntValue(BUFFER_ID_COLUMN, id);
	}

	/**
	 * Get the table's maximum long key value.
	 * @return table's maximum long key value.
	 */
	long getMaxKey() {
		return record.getLongValue(MAX_KEY_COLUMN);
	}

	/**
	 * Set table's maximum long key value.
	 * @param maxKey table's maximum long key value.
	 */
	void setMaxKey(long maxKey) {
		record.setLongValue(MAX_KEY_COLUMN, maxKey);
	}

	/**
	 * Get the table's current record count
	 * @return table's record count
	 */
	int getRecordCount() {
		return record.getIntValue(RECORD_COUNT_COLUMN);
	}

	/**
	 * Set the table's current record count
	 * @param count current record count
	 */
	void setRecordCount(int count) {
		record.setIntValue(RECORD_COUNT_COLUMN, count);
	}

	/**
	 * Get the column number which is indexed by this table.
	 * A value of -1 indicates that this is the primary table indexed
	 * by a long key value.  Positive values are used to specify that this 
	 * is a secondary index table, where the Index key corresponds to the
	 * specified column within the named table.
	 * @return int
	 */
	int getIndexedColumn() {
		return record.getIntValue(COLUMN_INDEXED_COLUMN);
	}

	/**
	 * Get the master table record storage schema
	 * @return master table record storage schema
	 */
	static Schema getTableRecordSchema() {
		return schema;
	}

	/**
	 * Compares the key associated with this table record with the 
	 * key of another table record (obj).
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(TableRecord otherRecord) {
		long myKey = record.getKey();
		long otherKey = otherRecord.record.getKey();
		if (myKey == otherKey) {
			return 0;
		}
		else if (myKey < otherKey) {
			return -1;
		}
		return 1;
	}

}
