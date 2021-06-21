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
import java.util.*;

import db.Field.UnsupportedFieldException;
import ghidra.util.Msg;
import ghidra.util.datastruct.IntObjectHashtable;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Table implementation class.
 * NOTE: Most public methods are synchronized on the associated DBHandle instance
 * to prevent concurrent modification by multiple threads.
 */
public class Table {

	private DBHandle db;

	private TableRecord tableRecord;

	private Schema schema;

	private NodeMgr nodeMgr;

	private int rootBufferId = -1;
	private int recordCount;
	private long maximumKey;

	private IntObjectHashtable<IndexTable> secondaryIndexes = new IntObjectHashtable<>();
	private int[] indexedColumns = new int[0];
	private boolean isIndexed = false;

	/**
	 * Modification counter
	 */
	int modCount = 0;

	/**
	 * Construct a new or existing Table.
	 * @param db database handle
	 * @param tableRecord master table record for this table.
	 * @throws UnsupportedFieldException if unsupported schema field encountered
	 */
	Table(DBHandle db, TableRecord tableRecord) throws UnsupportedFieldException {
		this.db = db;
		this.tableRecord = tableRecord;

		schema = tableRecord.getSchema();
		tableRecord.setTable(this);

		rootBufferId = tableRecord.getRootBufferId();
		recordCount = tableRecord.getRecordCount();
		maximumKey = tableRecord.getMaxKey();

		nodeMgr = new NodeMgr(this, db.getBufferMgr());
	}

	/**
	 * @return the database handle used by this table.
	 */
	DBHandle getDBHandle() {
		return db;
	}

	/**
	 * Determine if this table uses long keys.
	 * @return true if this table utilizes long keys. 
	 */
	public boolean useLongKeys() {
		return schema.useLongKeyNodes();
	}

	/**
	 * Determine if this table uses FixedField keys.
	 * @return true if this table utilizes FixedField keys. 
	 */
	public boolean useFixedKeys() {
		return schema.useFixedKeyNodes();
	}

	/**
	 * Callback notification indicating that the tableRecord has been
	 * changed by the masterTable.  This method is called via the MasterTable
	 * following an undo or redo.
	 */
	void tableRecordChanged() {
		rootBufferId = tableRecord.getRootBufferId();
		recordCount = tableRecord.getRecordCount();
		maximumKey = tableRecord.getMaxKey();
		++modCount;
	}

	/**
	 * Mark table as invalid.
	 * Subsequent table use may generate an exception.
	 */
	void invalidate() {
		boolean isIndexTable = tableRecord.getIndexedColumn() >= 0;
		tableRecord = null;
		rootBufferId = -1;
		nodeMgr = null;
		++modCount;
		if (!isIndexTable) {
			db.tableDeleted(this);
		}
	}

	/**
	 * Get this tables master table number.
	 * @return table number for this table.  Each table has a unique table 
	 * number within the master table.
	 */
	long getTableNum() {
		return tableRecord.getTableNum();
	}

	/**
	 * Get table statistics.
	 * @return list of diagnostic statistics data for this table and related index tables.
	 * @throws IOException database IO error
	 */
	public TableStatistics[] getAllStatistics() throws IOException {

		TableStatistics[] statList = new TableStatistics[indexedColumns.length + 1];

		statList[0] = getStatistics();

		for (int i = 0; i < indexedColumns.length; i++) {
			IndexTable indexTable = secondaryIndexes.get(indexedColumns[i]);
			statList[i + 1] = indexTable.getStatistics();
		}
		return statList;
	}

	private BTreeNode getBTreeNode(int bufferId) throws IOException {
		if (schema.useLongKeyNodes()) {
			return nodeMgr.getLongKeyNode(bufferId);
		}
		if (schema.useFixedKeyNodes()) {
			return nodeMgr.getFixedKeyNode(bufferId);
		}
		return nodeMgr.getVarKeyNode(bufferId);
	}

	private FieldKeyNode getFieldKeyNode(int bufferId) throws IOException {
		if (schema.useFixedKeyNodes()) {
			return nodeMgr.getFixedKeyNode(bufferId);
		}
		return nodeMgr.getVarKeyNode(bufferId);
	}

	/**
	 * Accumulate node statistics
	 * @param stats statistics collection object
	 * @param bufferId node buffer ID to examine
	 * @throws IOException thrown if IO error occurs
	 */
	private void accumulateNodeStatistics(TableStatistics stats, int bufferId) throws IOException {
		if (bufferId < 0) {
			return;
		}
		BTreeNode node = getBTreeNode(bufferId);
		++stats.bufferCount;

		int[] ids = node.getBufferReferences();

		if (node instanceof InteriorNode) {
			++stats.interiorNodeCnt;
			for (int id : ids) {
				accumulateNodeStatistics(stats, id);
			}
		}
		else {
			++stats.recordNodeCnt;
			for (int id : ids) {
				ChainedBuffer dbBuf = new ChainedBuffer(nodeMgr.getBufferMgr(), id);
				int cnt = dbBuf.getBufferCount();
				stats.chainedBufferCnt += cnt;
				stats.bufferCount += cnt;
			}
		}
		nodeMgr.releaseNodes(); // no need to hang on to buffers
	}

	/**
	 * Compile table statitics.
	 * @return table statistics data
	 * @throws IOException thrown if an IO error occurs
	 */
	public TableStatistics getStatistics() throws IOException {
		synchronized (db) {
			TableStatistics stats = new TableStatistics();
			stats.name = getName();
			try {
				accumulateNodeStatistics(stats, rootBufferId);
				stats.size = stats.bufferCount * nodeMgr.getBufferMgr().getBufferSize();
			}
			finally {
				nodeMgr.releaseNodes();
			}
			return stats;
		}
	}

	/**
	 * Add an existing secondary index.
	 * NOTE: Records for this table instance must not be modified until
	 * after all existing secondary indexes are added.  Failure to comply may
	 * result in an inconsistent index.
	 * @param indexTable secondary index table
	 */
	void addIndex(IndexTable indexTable) {
		secondaryIndexes.put(indexTable.getColumnIndex(), indexTable);
		indexedColumns = secondaryIndexes.getKeys();
		isIndexed = true;
	}

	/**
	 * Callback method for when a new record is added.
	 * Used for maintaining indexes only.  May be called before 
	 * the old record is actually inserted.
	 * @param record new record which has been added
	 * @throws IOException thrown if IO error occurs
	 */
	void insertedRecord(DBRecord record) throws IOException {
		// Add secondary index entries for new record
		for (int indexedColumn : indexedColumns) {
			IndexTable indexTable = secondaryIndexes.get(indexedColumn);
			indexTable.addEntry(record);
		}
	}

	/**
	 * Callback method for when an existing record is modified.
	 * Used for maintaining indexes only.  May be called before 
	 * the old record is actually updated.
	 * @param oldRecord old record
	 * @param newRecord new record
	 * @throws IOException thrown if IO error occurs
	 */
	void updatedRecord(DBRecord oldRecord, DBRecord newRecord) throws IOException {
		// Update secondary indexes which have been affected
		for (int colIx : indexedColumns) {
			Field oldField = oldRecord.getField(colIx);
			Field newField = newRecord.getField(colIx);
			if (!oldField.equals(newField)) {
				IndexTable indexTable = secondaryIndexes.get(colIx);
				indexTable.deleteEntry(oldRecord);
				indexTable.addEntry(newRecord);
			}
		}
	}

	/**
	 * Callback method for when existing records are deleted.
	 * Used for maintaining indexes only.  May be called before 
	 * the old record is actually deleted.
	 * @param oldRecord record which has been deleted
	 * @throws IOException thrown if IO error occurs
	 */
	void deletedRecord(DBRecord oldRecord) throws IOException {
		// Delete secondary index entries
		for (int indexedColumn : indexedColumns) {
			IndexTable indexTable = secondaryIndexes.get(indexedColumn);
			indexTable.deleteEntry(oldRecord);
		}
	}

	/**
	 * Rebuild table and associated indexes to ensure consistent state.
	 * @param monitor task monitor
	 * @throws IOException if unable to rebuild
	 * @throws CancelledException if task was cancelled
	 */
	public void rebuild(TaskMonitor monitor) throws IOException, CancelledException {
		synchronized (db) {

			db.checkTransaction();

			if (rootBufferId < 0) {
				return;
			}

			try {
				BTreeNode rootNode = getBTreeNode(rootBufferId);
				if (!rootNode.isConsistent(getName(), monitor)) {
					throw new IOException("Low level tree consistency error (" + getName() +
						"): Unable to rebuild database");
				}
			}
			catch (IOException t) {
				throw new IOException("Low level tree consistency error (" + getName() +
					"): failed to fetch root buffer: " + t.getMessage());
			}
			finally {
				nodeMgr.releaseNodes();
			}

			// Rebuild table indexes
			try {
				// Remove all index records
				for (int indexedColumn : indexedColumns) {
					IndexTable indexTable = secondaryIndexes.get(indexedColumn);
					monitor.setMessage("Clear Index Table " + getName() + "." +
						schema.getFieldNames()[indexTable.getColumnIndex()]);
					indexTable.indexTable.deleteAll();
				}
			}
			finally {
				nodeMgr.releaseNodes();
			}

			// Determine actual record count, max-key value and rebuild indexes
			monitor.setMessage("Rebuild Table " + getName());
			int actualCount = 0;
			LongField maxKey = null;
			try {
				RecordIterator recIter = iterator();
				while (recIter.hasNext()) {
					DBRecord rec = recIter.next();
					++actualCount;
					Field keyField = rec.getKeyField();
					if ((keyField instanceof LongField) &&
						(maxKey == null || maxKey.compareTo(rec.getKeyField()) > 0)) {
						maxKey = (LongField) keyField;
					}
					insertedRecord(rec);
				}
			}
			finally {
				nodeMgr.releaseNodes();
			}

			if (maxKey != null && maxKey.getLongValue() > tableRecord.getMaxKey()) {
				tableRecord.setMaxKey(maxKey.getLongValue());
			}
			tableRecord.setRecordCount(actualCount);

			if (!isConsistent(monitor)) {
				throw new IOException(
					"Consistency check failed after rebuilding table " + getName());
			}
		}
	}

	/**
	 * Check the consistency of this table and its associated index tables.
	 * @param monitor task monitor
	 * @return true if consistency check passed, else false
	 * @throws IOException thrown if IO error occurs 
	 * @throws CancelledException is task was cancelled
	 */
	public boolean isConsistent(TaskMonitor monitor) throws IOException, CancelledException {
		return isConsistent(null, monitor);
	}

	boolean isConsistent(String indexName, TaskMonitor monitor)
			throws IOException, CancelledException {
		synchronized (db) {

			if (rootBufferId < 0) {
				return true;
			}

			monitor.setMessage("Check Table " + getName());

			boolean consistent;
			try {
				BTreeNode rootNode = getBTreeNode(rootBufferId);
				consistent = rootNode.isConsistent(getName(), monitor);
			}
			catch (IOException t) {
				Msg.debug(this, "Consistency Error (" + getName() +
					"): failed to fetch root buffer: " + t.getMessage());
				return false;
			}
			finally {
				nodeMgr.releaseNodes();
			}

			// Check consistency of index tables
			for (int indexedColumn : indexedColumns) {
				IndexTable indexTable = secondaryIndexes.get(indexedColumn);
				monitor.setMessage("Check Table " + getName() + "." +
					schema.getFieldNames()[indexTable.getColumnIndex()]);
				consistent &= indexTable.isConsistent(monitor);
			}

			HashMap<Integer, Integer> missingIndexRecMap = new HashMap<>();
			int actualCount = 0;
			RecordIterator recIter = iterator();
			while (recIter.hasNext()) {
				DBRecord rec = recIter.next();
				++actualCount;

				// Check for bad index tables (missing or invalid entries)
				for (int indexedColumn : indexedColumns) {
					IndexTable indexTable = secondaryIndexes.get(indexedColumn);
					boolean found = false;
					Field[] keys =
						indexTable.findPrimaryKeys(rec.getField(indexTable.getColumnIndex()));
					for (Field key : keys) {
						if (key.equals(rec.getKeyField())) {
							found = true;
							break;
						}
					}
					if (!found) {
						consistent = false;
						Integer missing = missingIndexRecMap.get(indexTable.getColumnIndex());
						if (missing == null) {
							missingIndexRecMap.put(indexTable.getColumnIndex(), 1);
						}
						else {
							missingIndexRecMap.put(indexTable.getColumnIndex(), missing + 1);
						}
						logIndexConsistencyError(
							schema.getFieldNames()[indexTable.getColumnIndex()],
							"Index table does not reference record key: " +
								rec.getKeyField().getValueAsString());
					}
				}

			}
			if (actualCount != getRecordCount()) {
				consistent = false;
				logIndexConsistencyError(indexName,
					"Table record count inconsistent: iterator-count=" + actualCount +
						" stored-count=" + getRecordCount());
			}
			for (int indexCol : missingIndexRecMap.keySet()) {
				int missing = missingIndexRecMap.get(indexCol);
				logIndexConsistencyError(schema.getFieldNames()[indexCol],
					"Index is missing " + missing + " record references");
			}

			// Check for bad index tables (missing or invalid entries)
			for (int indexedColumn : indexedColumns) {
				IndexTable indexTable = secondaryIndexes.get(indexedColumn);

				monitor.setMessage("Check Index " + getName() + "." +
					schema.getFieldNames()[indexTable.getColumnIndex()]);

				HashSet<Field> keySet = new HashSet<>();
				int extra = 0;
				DBFieldIterator keyIterator = indexTable.keyIterator();
				while (keyIterator.hasNext()) {
					Field key = keyIterator.next();
					if (getRecord(key) == null) {
						++extra;
					}
					if (!keySet.add(key)) {
						logIndexConsistencyError(
							schema.getFieldNames()[indexTable.getColumnIndex()],
							"Index table references duplicate key: " + key.getValueAsString());
					}
				}
				if (extra != 0) {
					consistent = false;
					logIndexConsistencyError(schema.getFieldNames()[indexTable.getColumnIndex()],
						"Index table references " + extra + " nonexistent record keys");
				}
			}

			return consistent;
		}
	}

	void logIndexConsistencyError(String indexName, String msg) {
		Msg.debug(this, "Index Consistency Error (" + getName() +
			(indexName != null ? ("." + indexName) : "") + "): " + msg);
	}

	/**
	 * Delete all records within this table.
	 * @throws IOException if IO error occurs
	 */
	public void deleteAll() throws IOException {
		synchronized (db) {
			db.checkTransaction();
			if (rootBufferId < 0) {
				return;
			}
			try {
				BTreeNode rootNode = getBTreeNode(rootBufferId);
				try {
					// Delete all records
					rootNode.delete();

					// Delete all index entries
					for (int indexedColumn : indexedColumns) {
						IndexTable indexTable = secondaryIndexes.get(indexedColumn);
						indexTable.deleteAll();
					}
				}
				finally {
					tableRecord.setRootBufferId(rootBufferId = -1);
					tableRecord.setRecordCount(recordCount = 0);
					tableRecord.setMaxKey(maximumKey = Long.MIN_VALUE);
				}
			}
			finally {
				nodeMgr.releaseNodes();
			}

		}
	}

	/**
	 * Get the list of columns which are indexed
	 * @return list of indexed columns
	 */
	public int[] getIndexedColumns() {
		return indexedColumns;
	}

	/**
	 * Remove the index associated with the specified column.
	 * @param columnIndex column corresponding to the column index which 
	 * should be deleted.
	 * @throws IOException thrown if IO error occurs
	 */
	void removeIndex(int columnIndex) throws IOException {
		IndexTable indexTable = secondaryIndexes.get(columnIndex);
		if (indexTable != null) {
			indexTable.deleteAll();
			db.getMasterTable().deleteTableRecord(indexTable.getTableNum());
			secondaryIndexes.remove(columnIndex);
			indexedColumns = secondaryIndexes.getKeys();
		}
	}

	/**
	 * Get this tables schema.
	 * @return table schema
	 */
	public Schema getSchema() {
		return schema;
	}

	/**
	 * Get table name
	 * @return table name
	 */
	public String getName() {
		return tableRecord.getName();
	}

	/**
	 * Change the name of this table
	 * @param name new table name
	 * @return true if rename successful
	 * @throws DuplicateNameException if new table name already exists
	 */
	public boolean setName(String name) throws DuplicateNameException {
		return db.setTableName(getName(), name);
	}

	/**
	 * Get record count
	 * @return record count
	 */
	public int getRecordCount() {
		return tableRecord.getRecordCount();
	}

	/**
	 * Get the maximum record key which has ever been assigned within this table.
	 * This method is only valid for those tables which employ a long key and may
	 * not reflect records which have been removed (i.e., returned key may not 
	 * correspond to an existing record).
	 * @return maximum record key.
	 */
	public long getMaxKey() {
		return tableRecord.getMaxKey();
	}

	/**
	 * Get the next available key.
	 * This method is only valid for those tables which employ a long key.
	 * @return next available key.
	 */
	public long getKey() {
		long key = getMaxKey();
		if (key == Long.MIN_VALUE) {
			return 0;
		}
		return key + 1;
	}

//	/**
//	 * Sets the current root node for this table.
//	 * If the root changes the master table must be updated.
//	 * @param rootNode
//	 */
//	private void setRootNode(LongKeyNode rootNode) {
//		int id = rootNode.getBufferId();
//		if (rootBufferId != id) {
//			tableRecord.setRootBufferId(id);
//			rootBufferId = id;
//		}
//	}
//	
//	/**
//	 * Sets the current root node for this table.
//	 * If the root changes the master table must be updated.
//	 * @param rootNode
//	 */
//	private void setRootNode(VarKeyNode rootNode) {
//		int id = rootNode.getBufferId();
//		if (rootBufferId != id) {
//			tableRecord.setRootBufferId(id);
//			rootBufferId = id;
//		}
//	}

	/**
	 * Determine if this table contains a record with the specified key.
	 * @param key record key.
	 * @return true if record exists with key, else false.
	 * @throws IOException thrown if IO error occurs
	 */
	public boolean hasRecord(long key) throws IOException {
		synchronized (db) {
			if (rootBufferId < 0) {
				return false;
			}
			boolean result = false;
			try {
				LongKeyRecordNode leaf = nodeMgr.getLongKeyNode(rootBufferId).getLeafNode(key);
				result = leaf.getKeyIndex(key) >= 0;
			}
			finally {
				nodeMgr.releaseNodes();
			}
			return result;
		}
	}

	/**
	 * Determine if this table contains a record with the specified key.
	 * @param key record key.
	 * @return true if record exists with key, else false.
	 * @throws IOException throw if an IO Error occurs
	 */
	public boolean hasRecord(Field key) throws IOException {
		synchronized (db) {
			if (schema.useLongKeyNodes()) {
				return hasRecord(key.getLongValue());
			}
			if (rootBufferId < 0) {
				return false;
			}
			boolean result = false;
			try {
				FieldKeyRecordNode leaf = getFieldKeyNode(rootBufferId).getLeafNode(key);
				result = leaf.getKeyIndex(key) >= 0;
			}
			finally {
				nodeMgr.releaseNodes();
			}
			return result;
		}
	}

	/**
	 * Get the record identified by the specified key value.
	 * @param key unique record key.
	 * @return Record the record identified by key, or null if record was not
	 * found.
	 * @throws IOException throw if an IO Error occurs
	 */
	public DBRecord getRecord(long key) throws IOException {
		synchronized (db) {
			if (rootBufferId < 0) {
				return null;
			}
			try {
				LongKeyRecordNode leaf = nodeMgr.getLongKeyNode(rootBufferId).getLeafNode(key);
				return leaf.getRecord(key, schema);
			}
			finally {
				nodeMgr.releaseNodes();
			}
		}
	}

	/**
	 * Get the record identified by the specified key value.
	 * @param key unique record key.
	 * @return Record the record identified by key, or null if record was not
	 * found.
	 * @throws IOException throw if an IO Error occurs
	 */
	public DBRecord getRecord(Field key) throws IOException {
		synchronized (db) {
			if (rootBufferId < 0) {
				return null;
			}
			if (key instanceof LongField) {
				return getRecord(key.getLongValue());
			}
			FieldKeyRecordNode leaf;
			try {
				if (key instanceof FixedField) {
					leaf = nodeMgr.getFixedKeyNode(rootBufferId).getLeafNode(key);
					return leaf.getRecord(key, schema);
				}
				leaf = getFieldKeyNode(rootBufferId).getLeafNode(key);
				return leaf.getRecord(key, schema);
			}
			finally {
				nodeMgr.releaseNodes();
			}
		}
	}

	/**
	 * Get the record with the maximum key value which is less than  
	 * the specified key.
	 * @param key unique key which may or may not exist within the table.
	 * @return the first record which has a key value less than the 
	 * specified key, or null if no record was found.
	 * @throws IOException throw if an IO Error occurs
	 */
	public DBRecord getRecordBefore(long key) throws IOException {
		synchronized (db) {
			if (rootBufferId < 0) {
				return null;
			}
			try {
				LongKeyRecordNode leaf = nodeMgr.getLongKeyNode(rootBufferId).getLeafNode(key);
				return leaf.getRecordBefore(key, schema);
			}
			finally {
				nodeMgr.releaseNodes();
			}
		}
	}

	/**
	 * Get the record with the maximum key value which is less than  
	 * the specified key.
	 * @param key unique key which may or may not exist within the table.
	 * @return the first record which has a key value less than the 
	 * specified key, or null if no record was found.
	 * @throws IOException throw if an IO Error occurs
	 */
	public DBRecord getRecordBefore(Field key) throws IOException {
		synchronized (db) {
			if (rootBufferId < 0) {
				return null;
			}
			if (key instanceof LongField) {
				return getRecordBefore(key.getLongValue());
			}
			try {
				FieldKeyRecordNode leaf = getFieldKeyNode(rootBufferId).getLeafNode(key);
				return leaf.getRecordBefore(key, schema);
			}
			finally {
				nodeMgr.releaseNodes();
			}
		}
	}

	/**
	 * Get the record with the minimum key value which is greater than 
	 * the specified key.
	 * @param key unique key which may or may not exist within the table.
	 * @return the first record which has a key value greater than the 
	 * specified key, or null if no record was found.
	 * @throws IOException throw if an IO Error occurs
	 */
	public DBRecord getRecordAfter(long key) throws IOException {
		synchronized (db) {
			if (rootBufferId < 0) {
				return null;
			}
			try {
				LongKeyRecordNode leaf = nodeMgr.getLongKeyNode(rootBufferId).getLeafNode(key);
				return leaf.getRecordAfter(key, schema);
			}
			finally {
				nodeMgr.releaseNodes();
			}
		}
	}

	/**
	 * Get the record with the minimum key value which is greater than 
	 * the specified key.
	 * @param key unique key which may or may not exist within the table.
	 * @return the first record which has a key value greater than the 
	 * specified key, or null if no record was found.
	 * @throws IOException throw if an IO Error occurs
	 */
	public DBRecord getRecordAfter(Field key) throws IOException {
		synchronized (db) {
			if (rootBufferId < 0) {
				return null;
			}
			if (key instanceof LongField) {
				return getRecordAfter(key.getLongValue());
			}
			try {
				FieldKeyRecordNode leaf = getFieldKeyNode(rootBufferId).getLeafNode(key);
				return leaf.getRecordAfter(key, schema);
			}
			finally {
				nodeMgr.releaseNodes();
			}
		}
	}

	/**
	 * Get the record with the maximum key value which is less than or equal 
	 * to the specified key.
	 * @param key unique key which may or may not exist within the table.
	 * @return the first record which has a key value less than or equal to the 
	 * specified key, or null if no record was found.
	 * @throws IOException throw if an IO Error occurs
	 */
	public DBRecord getRecordAtOrBefore(long key) throws IOException {
		synchronized (db) {
			if (rootBufferId < 0) {
				return null;
			}
			try {
				LongKeyRecordNode leaf = nodeMgr.getLongKeyNode(rootBufferId).getLeafNode(key);
				return leaf.getRecordAtOrBefore(key, schema);
			}
			finally {
				nodeMgr.releaseNodes();
			}
		}
	}

	/**
	 * Get the record with the maximum key value which is less than or equal 
	 * to the specified key.
	 * @param key unique key which may or may not exist within the table.
	 * @return the first record which has a key value less than or equal to the 
	 * specified key, or null if no record was found.
	 * @throws IOException throw if an IO Error occurs
	 */
	public DBRecord getRecordAtOrBefore(Field key) throws IOException {
		synchronized (db) {
			if (rootBufferId < 0) {
				return null;
			}
			if (key instanceof LongField) {
				return getRecordAtOrBefore(key.getLongValue());
			}
			try {
				FieldKeyRecordNode leaf = getFieldKeyNode(rootBufferId).getLeafNode(key);
				return leaf.getRecordAtOrBefore(key, schema);
			}
			finally {
				nodeMgr.releaseNodes();
			}
		}
	}

	/**
	 * Get the record with the minimum key value which is greater than or equal 
	 * to the specified key.
	 * @param key unique key which may or may not exist within the table.
	 * @return the first record which has a key value greater than or equal to the 
	 * specified key, or null if no record was found.
	 * @throws IOException throw if an IO Error occurs
	 */
	public DBRecord getRecordAtOrAfter(long key) throws IOException {
		synchronized (db) {
			if (rootBufferId < 0) {
				return null;
			}
			try {
				LongKeyRecordNode leaf = nodeMgr.getLongKeyNode(rootBufferId).getLeafNode(key);
				return leaf.getRecordAtOrAfter(key, schema);
			}
			finally {
				nodeMgr.releaseNodes();
			}
		}
	}

	/**
	 * Get the record with the minimum key value which is greater than or equal 
	 * to the specified key.
	 * @param key unique key which may or may not exist within the table.
	 * @return the first record which has a key value greater than or equal to the 
	 * specified key, or null if no record was found.
	 * @throws IOException throw if an IO Error occurs
	 */
	public DBRecord getRecordAtOrAfter(Field key) throws IOException {
		synchronized (db) {
			if (rootBufferId < 0) {
				return null;
			}
			if (key instanceof LongField) {
				return getRecordAtOrAfter(key.getLongValue());
			}
			try {
				FieldKeyRecordNode leaf = getFieldKeyNode(rootBufferId).getLeafNode(key);
				return leaf.getRecordAtOrAfter(key, schema);
			}
			finally {
				nodeMgr.releaseNodes();
			}
		}
	}

	/**
	 * Put the specified record into the stored BTree.
	 * @param record the record to be stored.
	 * @throws IOException throw if an IO Error occurs
	 */
	public void putRecord(DBRecord record) throws IOException {
		synchronized (db) {
			db.checkTransaction();
			if (schema.useLongKeyNodes()) {
				putLongKeyRecord(record);
			}
			else {
				putFieldKeyRecord(record);
			}

		}
	}

	/**
	 * Store a record which uses a long key
	 * @param record recore to be inserted or updated
	 * @throws IOException throw if an IO Error occurs
	 */
	private void putLongKeyRecord(DBRecord record) throws IOException {

//		boolean inserted = false;
		try {

// ?? Do we need to validate record against schema

			// Establish root node
			++modCount;
			LongKeyNode rootNode = null;
			if (rootBufferId < 0) {
				rootNode = LongKeyRecordNode.createRecordNode(nodeMgr, schema);
			}
			else {
				rootNode = nodeMgr.getLongKeyNode(rootBufferId);
			}

			// Put record and update root buffer ID
			long recKey = record.getKey();
			LongKeyRecordNode leaf = rootNode.getLeafNode(recKey);
			rootNode = leaf.putRecord(record, isIndexed ? this : null);
			int id = rootNode.getBufferId();
			if (rootBufferId != id) {
				rootBufferId = id;
				tableRecord.setRootBufferId(rootBufferId);
			}

			// Update maximum key
			if (maximumKey < recKey) {
				maximumKey = recKey;
				tableRecord.setMaxKey(maximumKey);
			}
		}
		finally {
			// Release node buffers and update record count
			int delta = nodeMgr.releaseNodes();
			if (delta != 0) {
//				inserted = true;
				recordCount += delta;
				tableRecord.setRecordCount(recordCount);
			}
		}
	}

	/**
	 * Store a record which uses a Field key
	 * @param record record to be inserted or updated
	 * @throws IOException throw if an IO Error occurs
	 */
	private void putFieldKeyRecord(DBRecord record) throws IOException {

//		boolean inserted = false;
		try {

// ?? Do we need to validate record against schema

			// Establish root node
			++modCount;
			FieldKeyNode rootNode = null;
			if (rootBufferId < 0) {
				rootNode = schema.useFixedKeyNodes() ? FixedKeyRecordNode.createRecordNode(nodeMgr)
						: new VarKeyRecordNode(nodeMgr, schema.getKeyFieldType());
			}
			else {
				rootNode = getFieldKeyNode(rootBufferId);
			}

			// Put record and update root buffer ID
			Field recKey = record.getKeyField();
			FieldKeyRecordNode leaf = rootNode.getLeafNode(recKey);
			rootNode = leaf.putRecord(record, isIndexed ? this : null);
			int id = rootNode.getBufferId();
			if (rootBufferId != id) {
				rootBufferId = id;
				tableRecord.setRootBufferId(rootBufferId);
			}

			// NOTE: Maximum key is not tracked

		}
		finally {
			// Release node buffers and update record count
			int delta = nodeMgr.releaseNodes();
			if (delta != 0) {
//				inserted = true;
				recordCount += delta;
				tableRecord.setRecordCount(recordCount);
			}
		}
	}

	/**
	 * Delete a record identified by the specified key value.
	 * @param key unique record key.
	 * @return true if record was deleted successfully.
	 * @throws IOException throw if an IO Error occurs
	 */
	public boolean deleteRecord(long key) throws IOException {
		synchronized (db) {
			db.checkTransaction();
			boolean result = false;

			if (rootBufferId < 0) {
				return false;
			}
			if (!schema.useLongKeyNodes()) {
				throw new IllegalArgumentException("Field key required");
			}
			try {
				++modCount;
				LongKeyNode rootNode = nodeMgr.getLongKeyNode(rootBufferId);
				LongKeyRecordNode leaf = rootNode.getLeafNode(key);
				rootNode = leaf.deleteRecord(key, isIndexed ? this : null);

				if (rootNode != null) {
					int id = rootNode.getBufferId();
					if (rootBufferId != id) {
						rootBufferId = id;
						tableRecord.setRootBufferId(rootBufferId);
					}
				}
				else {
					rootBufferId = -1;
					tableRecord.setRootBufferId(rootBufferId);
				}

			}
			finally {
				// Release node buffers and update record count
				int delta = nodeMgr.releaseNodes();
				if (delta != 0) {
					result = true;
					recordCount += delta;
					tableRecord.setRecordCount(recordCount);
				}
			}
			return result;
		}
	}

	/**
	 * Delete a record identified by the specified key value.
	 * @param key unique record key.
	 * @return true if record was deleted successfully.
	 * @throws IOException throw if an IO Error occurs
	 */
	public boolean deleteRecord(Field key) throws IOException {
		synchronized (db) {
			db.checkTransaction();
			boolean result = false;

			if (rootBufferId < 0) {
				return false;
			}
			if (key instanceof LongField) {
				return deleteRecord(key.getLongValue());
			}
			try {
				++modCount;
				FieldKeyNode rootNode = getFieldKeyNode(rootBufferId);
				FieldKeyRecordNode leaf = rootNode.getLeafNode(key);
				rootNode = leaf.deleteRecord(key, isIndexed ? this : null);

				if (rootNode != null) {
					int id = rootNode.getBufferId();
					if (rootBufferId != id) {
						rootBufferId = id;
						tableRecord.setRootBufferId(rootBufferId);
					}
				}
				else {
					rootBufferId = -1;
					tableRecord.setRootBufferId(rootBufferId);
				}

			}
			finally {
				// Release node buffers and update record count
				int delta = nodeMgr.releaseNodes();
				if (delta != 0) {
					result = true;
					recordCount += delta;
					tableRecord.setRecordCount(recordCount);
				}
			}
			return result;
		}
	}

	/**
	 * Delete all records whose keys fall within the specified range, inclusive.
	 * @param startKey minimum key value
	 * @param endKey maximum key value
	 * @return true if one or more records were deleted.
	 * @throws IOException thrown if an IO error occurs
	 */
	public boolean deleteRecords(long startKey, long endKey) throws IOException {
		synchronized (db) {
			db.checkTransaction();
			if (startKey > endKey) {
				throw new IllegalArgumentException();
			}
			if (!schema.useLongKeyNodes()) {
				throw new IllegalArgumentException("Long key required");
			}

			boolean result = false;
			if (rootBufferId < 0) {
				return result;
			}

			try {
				++modCount;
				LongKeyNode rootNode = nodeMgr.getLongKeyNode(rootBufferId);
				LongKeyRecordNode leaf = rootNode.getLeafNode(startKey);

				try {
					// Handle partial first leaf where leftmost key is not deleted
					int index = leaf.getKeyIndex(startKey);
					long lastKey = 0;
					if (index < 0) {
						index = -index - 1;
					}
					if (index > 0) {
						int lastIndex = leaf.getKeyIndex(endKey);
						if (lastIndex < 0) {
							lastIndex = -lastIndex - 2;
						}
						// delete individual records within first leaf
						while (index <= lastIndex--) {
							if (isIndexed) {
								deletedRecord(leaf.getRecord(schema, index));
							}
							leaf.remove(index);
						}
						result = true;
						if (index < leaf.keyCount) {
							return result;
						}
						LongKeyRecordNode nextLeaf = leaf.getNextLeaf();
						if (nextLeaf == null) {
							return result;
						}
						lastKey = nextLeaf.getKey(nextLeaf.keyCount - 1);
						leaf = rootNode.getLeafNode(lastKey);
						index = 0;
					}
					else {
						lastKey = leaf.getKey(leaf.keyCount - 1);
					}

					// Handle additional whole leaves
					while (lastKey <= endKey) {
						if (isIndexed) {
							for (int n = 0; n < leaf.keyCount; n++) {
								deletedRecord(leaf.getRecord(schema, n));
							}
						}
						LongKeyRecordNode nextLeaf = leaf.getNextLeaf();
						rootNode = leaf.removeLeaf();
						result = true;
						if (nextLeaf == null) {
							return result;
						}
						lastKey = nextLeaf.getKey(nextLeaf.keyCount - 1);
						leaf = rootNode.getLeafNode(lastKey);
					}

					// Handle final leaf
					// delete individual records within first leaf
					int lastIndex = leaf.getKeyIndex(endKey);
					if (lastIndex < 0) {
						lastIndex = -lastIndex - 2;
					}
					long key = leaf.getKey(0);
					while (index <= lastIndex--) {
						if (isIndexed) {
							deletedRecord(leaf.getRecord(schema, index));
						}
						leaf.remove(index);
						result = true;
					}
					if (index == 0 && leaf.parent != null) {
						leaf.parent.keyChanged(key, leaf.getKey(0));
					}
				}
				finally {
					// Update root node
					if (rootNode != null) {
						int id = rootNode.getBufferId();
						if (rootBufferId != id) {
							rootBufferId = id;
							tableRecord.setRootBufferId(rootBufferId);
						}
					}
					else {
						rootBufferId = -1;
						tableRecord.setRootBufferId(rootBufferId);
					}
				}

			}
			finally {
				// Release node buffers and update record count
				int delta = nodeMgr.releaseNodes();
				if (delta != 0) {
					result = true;
					recordCount += delta;
					tableRecord.setRecordCount(recordCount);
				}
			}

			return result;
		}
	}

	/**
	 * Delete all records whose keys fall within the specified range, inclusive.
	 * @param startKey minimum key value
	 * @param endKey maximum key value
	 * @return true if one or more records were deleted.
	 * @throws IOException thrown if an IO error occurs
	 */
	public boolean deleteRecords(Field startKey, Field endKey) throws IOException {
		synchronized (db) {
			db.checkTransaction();
			if (startKey.compareTo(endKey) > 0) {
				throw new IllegalArgumentException();
			}
			if (schema.useLongKeyNodes()) {
				throw new IllegalArgumentException("Field key required");
			}

			boolean result = false;
			if (rootBufferId < 0) {
				return result;
			}

			try {
				++modCount;
				FieldKeyNode rootNode = getFieldKeyNode(rootBufferId);
				FieldKeyRecordNode leaf = rootNode.getLeafNode(startKey);

				try {
					// Handle partial first leaf where leftmost key is not deleted
					int index = leaf.getKeyIndex(startKey);
					Field lastKey = null;
					if (index < 0) {
						index = -index - 1;
					}
					if (index > 0) {
						int lastIndex = leaf.getKeyIndex(endKey);
						if (lastIndex < 0) {
							lastIndex = -lastIndex - 2;
						}
						// delete individual records within first leaf
						while (index <= lastIndex--) {
							if (isIndexed) {
								deletedRecord(leaf.getRecord(schema, index));
							}
							leaf.remove(index);
						}
						result = true;
						if (index < leaf.getKeyCount()) {
							return result;
						}
						RecordNode nextLeaf = leaf.getNextLeaf();
						if (nextLeaf == null) {
							return result;
						}
						lastKey = nextLeaf.getKeyField(nextLeaf.getKeyCount() - 1);
						leaf = rootNode.getLeafNode(lastKey);
						index = 0;
					}
					else {
						lastKey = leaf.getKeyField(leaf.getKeyCount() - 1);
					}

					// Handle additional whole leaves
					while (lastKey.compareTo(endKey) <= 0) {
						if (isIndexed) {
							int count = leaf.getKeyCount();
							for (int n = 0; n < count; n++) {
								deletedRecord(leaf.getRecord(schema, n));
							}
						}
						RecordNode nextLeaf = leaf.getNextLeaf();
						rootNode = leaf.removeLeaf();
						result = true;
						if (nextLeaf == null) {
							return result;
						}
						lastKey = nextLeaf.getKeyField(nextLeaf.getKeyCount() - 1);
						leaf = rootNode.getLeafNode(lastKey);
					}

					// Handle final leaf
					// delete individual records within first leaf
					int lastIndex = leaf.getKeyIndex(endKey);
					if (lastIndex < 0) {
						lastIndex = -lastIndex - 2;
					}
					Field key = leaf.getKeyField(0);
					while (index <= lastIndex--) {
						if (isIndexed) {
							deletedRecord(leaf.getRecord(schema, index));
						}
						leaf.remove(index);
						result = true;
					}
					if (index == 0 && leaf.getParent() != null) {
						leaf.getParent().keyChanged(key, leaf.getKeyField(0), leaf);
					}
				}
				finally {
					// Update root node
					if (rootNode != null) {
						int id = rootNode.getBufferId();
						if (rootBufferId != id) {
							rootBufferId = id;
							tableRecord.setRootBufferId(rootBufferId);
						}
					}
					else {
						rootBufferId = -1;
						tableRecord.setRootBufferId(rootBufferId);
					}
				}

			}
			finally {
				// Release node buffers and update record count
				int delta = nodeMgr.releaseNodes();
				if (delta != 0) {
					result = true;
					recordCount += delta;
					tableRecord.setRecordCount(recordCount);
				}
			}

			return result;
		}
	}

	/**
	 * Find the primary keys corresponding to those records which contain the
	 * specified field value in the specified record column.  The table must
	 * have been created with long keys and a secondary index on the specified 
	 * column index.
	 * @param field the field value
	 * @param columnIndex the record schema column which should be searched.
	 * @return list of primary keys
	 * @throws IOException if a secondary index does not exist for the specified
	 * column, or the wrong field type was specified, or an I/O error occurs.
	 */
	public Field[] findRecords(Field field, int columnIndex) throws IOException {
		synchronized (db) {
			IndexTable indexTable = secondaryIndexes.get(columnIndex);
			if (indexTable == null) {
				throw new IOException("Index required (" + getName() + "," + columnIndex + ")");
			}
			return indexTable.findPrimaryKeys(field);
		}
	}

	/**
	 * Get the number of records which contain the
	 * specified field value in the specified record column.  The table must
	 * have been created with a secondary index on the specified column index.
	 * @param field the field value
	 * @param columnIndex the record schema column which should be searched.
	 * @return number of records which match the specified field value.
	 * @throws IOException if a secondary index does not exist for the specified
	 * column, or the wrong field type was specified, or an I/O error occurs.
	 */
	public int getMatchingRecordCount(Field field, int columnIndex) throws IOException {
		synchronized (db) {
			IndexTable indexTable = secondaryIndexes.get(columnIndex);
			if (indexTable == null) {
				throw new IOException("Index required (" + getName() + "," + columnIndex + ")");
			}
			return indexTable.getKeyCount(field);
		}
	}

	/**
	 * Determine if a record exists with the specified value within the specified
	 * column.  The table must have been created with a secondary index on the 
	 * specified column index.
	 * @param field the field value
	 * @param columnIndex the record schema column which should be searched.
	 * @return true if one or more records exis with the specified value.
	 * @throws IOException thrown if IO error occurs
	 */
	public boolean hasRecord(Field field, int columnIndex) throws IOException {
		synchronized (db) {
			IndexTable indexTable = secondaryIndexes.get(columnIndex);
			if (indexTable == null) {
				throw new IOException("Index required (" + getName() + "," + columnIndex + ")");
			}
			return indexTable.hasRecord(field);
		}
	}

	/**
	 * Iterate over all the unique index field values.  Index values are
	 * returned in an ascending sorted order with the initial iterator position
	 * set to the minimum index value.
	 * @param columnIndex identifies an indexed column.
	 * @return index field iterator.
	 * @throws IOException thrown if IO error occurs
	 */
	public DBFieldIterator indexFieldIterator(int columnIndex) throws IOException {
		synchronized (db) {
			IndexTable indexTable = secondaryIndexes.get(columnIndex);
			if (indexTable == null) {
				throw new IOException("Index required (" + getName() + "," + columnIndex + ")");
			}
			return indexTable.indexIterator();
		}
	}

	/**
	 * Iterate over all the unique index field values within the specified range identified
	 * by minField and maxField.  Index values are returned in an ascending sorted order.
	 * @param minField minimum index column value, if null absolute minimum is used
	 * @param maxField maximum index column value, if null absolute maximum is used
	 * @param before if true initial position is before minField, else position
	 * is after maxField
	 * @param columnIndex identifies an indexed column.
	 * @return index field iterator.
	 * @throws IOException thrown if IO error occurs
	 */
	public DBFieldIterator indexFieldIterator(Field minField, Field maxField, boolean before,
			int columnIndex) throws IOException {
		synchronized (db) {
			IndexTable indexTable = secondaryIndexes.get(columnIndex);
			if (indexTable == null) {
				throw new IOException("Index required (" + getName() + "," + columnIndex + ")");
			}
			return indexTable.indexIterator(minField, maxField, before);
		}
	}

	/**
	 * Iterate over all the unique index field values within the specified range identified
	 * by minField and maxField.  Index values are returned in an ascending sorted order with the 
	 * initial iterator position corresponding to the startField.
	 * @param minField minimum index column value, if null absolute minimum is used
	 * @param maxField maximum index column value, if null absolute maximum is used
	 * @param startField index column value corresponding to initial position of iterator
	 * @param before if true initial position is before startField value, else position
	 * is after startField value
	 * @param columnIndex identifies an indexed column.
	 * @return index field iterator.
	 * @throws IOException if a secondary index does not exist for the specified
	 * column or an I/O error occurs.
	 */
	public DBFieldIterator indexFieldIterator(Field minField, Field maxField, Field startField,
			boolean before, int columnIndex) throws IOException {
		synchronized (db) {
			IndexTable indexTable = secondaryIndexes.get(columnIndex);
			if (indexTable == null) {
				throw new IOException("Index required (" + getName() + "," + columnIndex + ")");
			}
			return indexTable.indexIterator(minField, maxField, startField, before);
		}
	}

	/**
	 * Iterate over the records using a secondary index.  Sorting occurs on the
	 * specified schema column.  This table must have been constructed with a secondary
	 * index on the specified column.
	 * @param columnIndex schema column to sort on.
	 * @return RecordIterator record iterator.
	 * @throws IOException if a secondary index does not exist for the specified
	 * column or an I/O error occurs.
	 */
	public RecordIterator indexIterator(int columnIndex) throws IOException {
		synchronized (db) {
			IndexTable indexTable = secondaryIndexes.get(columnIndex);
			if (indexTable == null) {
				throw new IOException("Index required (" + getName() + "," + columnIndex + ")");
			}
			return new KeyToRecordIterator(this, indexTable.keyIterator());
		}
	}

	/**
	 * Iterate over a range of records using a secondary index.  Sorting occurs on the
	 * specified schema column. The iterator is initially positioned before the startValue.
	 * This table must have been constructed with a secondary index on the specified column.
	 * @param columnIndex schema column to sort on.
	 * @param startValue the starting and minimum value of the secondary index field.
	 * @param endValue the ending and maximum value of the secondary index field.
	 * @param atStart if true, position the iterator before the start value. 
	 * Otherwise, position the iterator after the end value.
	 * 
	 * @return record iterator.
	 * @throws IOException if a secondary index does not exist for the specified
	 * column, or the wrong field type was specified, or an I/O error occurs.
	 */
	public RecordIterator indexIterator(int columnIndex, Field startValue, Field endValue,
			boolean atStart) throws IOException {
		synchronized (db) {
			IndexTable indexTable = secondaryIndexes.get(columnIndex);
			if (indexTable == null) {
				throw new IOException("Index required (" + getName() + "," + columnIndex + ")");
			}
			return new KeyToRecordIterator(this,
				indexTable.keyIterator(startValue, endValue, atStart));
		}
	}

	/**
	 * Iterate over the records using a secondary index.  Sorting occurs on the
	 * specified schema column.  The iterator's initial position immediately follows 
	 * the specified startValue. If this value does not exist, the initial position corresponds
	 * to where it would exist.
	 * This table must have been constructed with a secondary index on the specified column.
	 * @param columnIndex schema column to sort on.
	 * @param startValue the starting value of the secondary index field.
	 * @return RecordIterator record iterator.
	 * @throws IOException if a secondary index does not exist for the specified
	 * column, or the wrong field type was specified, or an I/O error occurs.
	 */
	public RecordIterator indexIteratorAfter(int columnIndex, Field startValue) throws IOException {
		synchronized (db) {
			IndexTable indexTable = secondaryIndexes.get(columnIndex);
			if (indexTable == null) {
				throw new IOException("Index required (" + getName() + "," + columnIndex + ")");
			}
			return new KeyToRecordIterator(this, indexTable.keyIteratorAfter(startValue));
		}
	}

	/**
	 * Iterate over the records using a secondary index.  Sorting occurs on the
	 * specified schema column.  The iterator's initial position immediately precedes 
	 * the specified startValue. If this value does not exist, the initial position corresponds
	 * to where it would exist.
	 * This table must have been constructed with a secondary index on the specified column.
	 * @param columnIndex schema column to sort on.
	 * @param startValue the starting value of the secondary index field.
	 * @return RecordIterator record iterator.
	 * @throws IOException if a secondary index does not exist for the specified
	 * column, or the wrong field type was specified, or an I/O error occurs.
	 */
	public RecordIterator indexIteratorBefore(int columnIndex, Field startValue)
			throws IOException {
		synchronized (db) {
			IndexTable indexTable = secondaryIndexes.get(columnIndex);
			if (indexTable == null) {
				throw new IOException("Index required (" + getName() + "," + columnIndex + ")");
			}
			return new KeyToRecordIterator(this, indexTable.keyIteratorBefore(startValue));
		}
	}

	/**
	 * Iterate over the records using a secondary index.  Sorting occurs on the
	 * specified schema column.  The iterator's initial position immediately follows 
	 * the specified startValue and primaryKey. If no such entry exists, the initial position 
	 * corresponds to where it would exist.
	 * <p>
	 * This table must have been constructed with a secondary index on the specified column.
	 * 
	 * @param columnIndex schema column to sort on.
	 * @param startValue the starting value of the secondary index field.
	 * @param primaryKey the primary key associated with the startField.
	 * @return RecordIterator record iterator.
	 * @throws IOException if a secondary index does not exist for the specified
	 * column, or the wrong field type was specified, or an I/O error occurs.
	 */
	public RecordIterator indexIteratorAfter(int columnIndex, Field startValue, Field primaryKey)
			throws IOException {
		synchronized (db) {
			IndexTable indexTable = secondaryIndexes.get(columnIndex);
			if (indexTable == null) {
				throw new IOException("Index required (" + getName() + "," + columnIndex + ")");
			}
			return new KeyToRecordIterator(this,
				indexTable.keyIteratorAfter(startValue, primaryKey));
		}
	}

	/**
	 * Iterate over the records using a secondary index.  Sorting occurs on the
	 * specified schema column.  The iterator's initial position immediately precedes 
	 * the specified startValue and primaryKey. If no such entry exists, the initial position 
	 * corresponds to where it would exist.
	 * <p>
	 * This table must have been constructed with a secondary index on the specified column.
	 * 
	 * @param columnIndex schema column to sort on.
	 * @param startValue the starting value of the secondary index field.
	 * @param primaryKey the primary key associated with the startField.
	 * @return RecordIterator record iterator.
	 * @throws IOException if a secondary index does not exist for the specified
	 * column, or the wrong field type was specified, or an I/O error occurs.
	 */
	public RecordIterator indexIteratorBefore(int columnIndex, Field startValue, Field primaryKey)
			throws IOException {
		synchronized (db) {
			IndexTable indexTable = secondaryIndexes.get(columnIndex);
			if (indexTable == null) {
				throw new IOException("Index required (" + getName() + "," + columnIndex + ")");
			}
			return new KeyToRecordIterator(this,
				indexTable.keyIteratorBefore(startValue, primaryKey));
		}
	}

	/**
	 * Iterate over all primary keys sorted based upon the associated index key.
	 * @param columnIndex schema column to sort on.
	 * @return primary key iterator
	 * @throws IOException thrown if IO error occurs
	 */
	public DBFieldIterator indexKeyIterator(int columnIndex) throws IOException {
		synchronized (db) {
			IndexTable indexTable = secondaryIndexes.get(columnIndex);
			if (indexTable == null) {
				throw new IOException("Index required (" + getName() + "," + columnIndex + ")");
			}
			return indexTable.keyIterator();
		}
	}

	/**
	 * Iterate over all primary keys sorted based upon the associated index key.
	 * The iterator is initially positioned before the first index buffer whose index key 
	 * is greater than or equal to the specified startField value.
	 * @param columnIndex schema column to sort on
	 * @param startField index column value which determines initial position of iterator
	 * @return primary key iterator
	 * @throws IOException thrown if IO error occurs
	 */
	public DBFieldIterator indexKeyIteratorBefore(int columnIndex, Field startField)
			throws IOException {
		synchronized (db) {
			IndexTable indexTable = secondaryIndexes.get(columnIndex);
			if (indexTable == null) {
				throw new IOException("Index required (" + getName() + "," + columnIndex + ")");
			}
			return indexTable.keyIteratorBefore(startField);
		}
	}

	/**
	 * Iterate over all primary keys sorted based upon the associated index key.
	 * The iterator is initially positioned after the index buffer whose index key 
	 * is equal to the specified startField value or immediately before the first 
	 * index buffer whose index key is greater than the specified startField value.
	 * @param columnIndex schema column to sort on
	 * @param startField index column value which determines initial position of iterator
	 * @return primary key iterator
	 * @throws IOException thrown if IO error occurs
	 */
	public DBFieldIterator indexKeyIteratorAfter(int columnIndex, Field startField)
			throws IOException {
		synchronized (db) {
			IndexTable indexTable = secondaryIndexes.get(columnIndex);
			if (indexTable == null) {
				throw new IOException("Index required (" + getName() + "," + columnIndex + ")");
			}
			return indexTable.keyIteratorAfter(startField);
		}
	}

	/**
	 * Iterate over all primary keys sorted based upon the associated index key.
	 * The iterator is initially positioned before the primaryKey within the index buffer 
	 * whose index key is equal to the specified startField value or immediately before the first 
	 * index buffer whose index key is greater than the specified startField value.
	 * @param columnIndex schema column to sort on
	 * @param startField index column value which determines initial position of iterator
	 * @param primaryKey initial position within index buffer if index key matches startField value.
	 * @return primary key iterator
	 * @throws IOException thrown if IO error occurs
	 */
	public DBFieldIterator indexKeyIteratorBefore(int columnIndex, Field startField,
			Field primaryKey) throws IOException {
		synchronized (db) {
			IndexTable indexTable = secondaryIndexes.get(columnIndex);
			if (indexTable == null) {
				throw new IOException("Index required (" + getName() + "," + columnIndex + ")");
			}
			return indexTable.keyIteratorBefore(startField, primaryKey);
		}
	}

	/**
	 * Iterate over all primary keys sorted based upon the associated index key.
	 * The iterator is initially positioned after the primaryKey within the index buffer 
	 * whose index key is equal to the specified startField value or immediately before the first 
	 * index buffer whose index key is greater than the specified startField value.
	 * @param columnIndex schema column to sort on
	 * @param startField index column value which determines initial position of iterator
	 * @param primaryKey initial position within index buffer if index key matches startField value.
	 * @return primary key iterator
	 * @throws IOException thrown if IO error occurs
	 */
	public DBFieldIterator indexKeyIteratorAfter(int columnIndex, Field startField,
			Field primaryKey) throws IOException {
		synchronized (db) {
			IndexTable indexTable = secondaryIndexes.get(columnIndex);
			if (indexTable == null) {
				throw new IOException("Index required (" + getName() + "," + columnIndex + ")");
			}
			return indexTable.keyIteratorAfter(startField, primaryKey);
		}
	}

	/**
	 * Iterate over all primary keys sorted based upon the associated index key.
	 * The iterator is limited to range of index keys of minField through maxField, inclusive.
	 * If atMin is true, the iterator is initially positioned before the first index 
	 * buffer whose index key is greater than or equal to the specified minField value. 
	 * If atMin is false, the iterator is initially positioned after the first index 
	 * buffer whose index key is less than or equal to the specified maxField value. 
	 * @param columnIndex schema column to sort on
	 * @param minField minimum index column value
	 * @param maxField maximum index column value
	 * @param atMin if true, position iterator before minField value, 
	 * Otherwise, position iterator after maxField value.
	 * @return primary key iterator
	 * @throws IOException thrown if IO error occurs
	 */
	public DBFieldIterator indexKeyIterator(int columnIndex, Field minField, Field maxField,
			boolean atMin) throws IOException {
		synchronized (db) {
			IndexTable indexTable = secondaryIndexes.get(columnIndex);
			if (indexTable == null) {
				throw new IOException("Index required (" + getName() + "," + columnIndex + ")");
			}
			return indexTable.keyIterator(minField, maxField, atMin);
		}
	}

	/**
	 * Iterate over all primary keys sorted based upon the associated index key.
	 * The iterator is limited to range of index keys of minField through maxField, inclusive.
	 * The iterator is initially positioned before or after the specified startField index value. 
	 * @param columnIndex schema column to sort on
	 * @param minField minimum index column value
	 * @param maxField maximum index column value
	 * @param startField starting indexed value position
	 * @param before if true positioned before startField value, else positioned after maxField
	 * @return primary key iterator
	 * @throws IOException thrown if IO error occurs
	 */
	public DBFieldIterator indexKeyIterator(int columnIndex, Field minField, Field maxField,
			Field startField, boolean before) throws IOException {
		synchronized (db) {
			IndexTable indexTable = secondaryIndexes.get(columnIndex);
			if (indexTable == null) {
				throw new IOException("Index required (" + getName() + "," + columnIndex + ")");
			}
			return indexTable.keyIterator(minField, maxField, startField, before);
		}
	}

	/**
	 * Iterate over the records in ascending sorted order.  Sorting occurs on the primary key value.
	 * @return record iterator
	 * @throws IOException if an I/O error occurs.
	 */
	public RecordIterator iterator() throws IOException {
		synchronized (db) {
			if (schema.useLongKeyNodes()) {
				return new LongKeyRecordIterator();
			}
			return new FieldKeyRecordIterator(null, null, null);
		}
	}

	/**
	 * Iterate over the records in ascending sorted order.  Sorting occurs on the primary key value
	 * starting at the specified startKey.
	 * @param startKey the first primary key.
	 * @return record iterator
	 * @throws IOException if an I/O error occurs.
	 */
	public RecordIterator iterator(long startKey) throws IOException {
		synchronized (db) {
			if (!schema.useLongKeyNodes()) {
				throw new IllegalArgumentException("Field key required");
			}
			return new LongKeyRecordIterator(Long.MIN_VALUE, Long.MAX_VALUE, startKey);
		}
	}

	/**
	 * Iterate over the records in ascending sorted order.  Sorting occurs on the primary key value
	 * starting at the specified startKey.
	 * @param minKey the minimum primary key.
	 * @param maxKey the maximum primary key.
	 * @param startKey the initial iterator position.
	 * @return record iterator
	 * @throws IOException if an I/O error occurs.
	 * @throws IllegalArgumentException if long keys are not in use or startKey 
	 * is less than minKey or greater than maxKey.
	 */
	public RecordIterator iterator(long minKey, long maxKey, long startKey) throws IOException {
		synchronized (db) {
			if (!schema.useLongKeyNodes()) {
				throw new IllegalArgumentException("Field key required");
			}
			return new LongKeyRecordIterator(minKey, maxKey, startKey);
		}
	}

	/**
	 * Iterate over the records in ascending sorted order.  Sorting occurs on the primary key value
	 * starting at the specified startKey.
	 * @param startKey the first primary key.
	 * @return record iterator
	 * @throws IOException if an I/O error occurs.
	 */
	public RecordIterator iterator(Field startKey) throws IOException {
		synchronized (db) {
			if (schema.useLongKeyNodes()) {
				return new LongKeyRecordIterator(Long.MIN_VALUE, Long.MAX_VALUE,
					startKey.getLongValue());
			}
			return new FieldKeyRecordIterator(null, null, startKey);
		}
	}

	/**
	 * Iterate over the records in ascending sorted order.  Sorting occurs on the primary key value
	 * starting at the specified startKey.
	 * @param minKey the minimum primary key, may be null.
	 * @param maxKey the maximum primary key, may be null.
	 * @param startKey the initial iterator position, if null minKey is also start.
	 * @return record iterator
	 * @throws IOException if an I/O error occurs.
	 */
	public RecordIterator iterator(Field minKey, Field maxKey, Field startKey) throws IOException {
		synchronized (db) {
			if (schema.useLongKeyNodes()) {
				long min = minKey != null ? minKey.getLongValue() : Long.MIN_VALUE;
				long max = maxKey != null ? maxKey.getLongValue() : Long.MAX_VALUE;
				long start = startKey != null ? startKey.getLongValue() : min;
				return new LongKeyRecordIterator(min, max, start);
			}
			return new FieldKeyRecordIterator(minKey, maxKey, startKey);
		}
	}

	/**
	 * Iterate over all long primary keys in ascending sorted order.
	 * @return long key iterator
	 * @throws IOException if an I/O error occurs.
	 */
	public DBLongIterator longKeyIterator() throws IOException {
		synchronized (db) {
			if (!schema.useLongKeyNodes()) {
				throw new AssertException();
			}
			return new LongKeyIterator();
		}
	}

	/**
	 * Iterate over the long primary keys in ascending sorted order
	 * starting at the specified startKey.
	 * @param startKey the first primary key.
	 * @return long key iterator
	 * @throws IOException if an I/O error occurs.
	 */
	public DBLongIterator longKeyIterator(long startKey) throws IOException {
		synchronized (db) {
			if (!schema.useLongKeyNodes()) {
				throw new AssertException();
			}
			return new LongKeyIterator(Long.MIN_VALUE, Long.MAX_VALUE, startKey);
		}
	}

	/**
	 * Iterate over the long primary keys in ascending sorted order
	 * starting at the specified startKey.
	 * @param minKey the minimum primary key.
	 * @param maxKey the maximum primary key.
	 * @param startKey the initial iterator position.
	 * @return long key iterator
	 * @throws IOException if an I/O error occurs.
	 */
	public DBLongIterator longKeyIterator(long minKey, long maxKey, long startKey)
			throws IOException {
		synchronized (db) {
			if (!schema.useLongKeyNodes()) {
				throw new AssertException();
			}
			return new LongKeyIterator(minKey, maxKey, startKey);
		}
	}

	/**
	 * Iterate over all primary keys in ascending sorted order.
	 * @return Field type key iterator
	 * @throws IOException if an I/O error occurs.
	 */
	public DBFieldIterator fieldKeyIterator() throws IOException {
		synchronized (db) {
			if (schema.useLongKeyNodes()) {
				throw new AssertException();
			}
			return new FieldKeyIterator(null, null, null);
		}
	}

	/**
	 * Iterate over the primary keys in ascending sorted order
	 * starting at the specified startKey.
	 * @param startKey the first primary key.  If null the minimum key value will be assumed.
	 * @return Field type key iterator
	 * @throws IOException if an I/O error occurs.
	 */
	public DBFieldIterator fieldKeyIterator(Field startKey) throws IOException {
		synchronized (db) {
			if (schema.useLongKeyNodes()) {
				throw new AssertException();
			}
			return new FieldKeyIterator(null, null, startKey);
		}
	}

	/**
	 * Iterate over the records in ascending sorted order
	 * starting at the specified startKey.
	 * @param minKey minimum key value.  Null corresponds to minimum key value.
	 * @param maxKey maximum key value.  Null corresponds to maximum key value.
	 * @param startKey the initial iterator position.  If null minKey will be assumed,
	 * if still null the minimum key value will be assumed.
	 * @return Field type key iterator
	 * @throws IOException if an I/O error occurs.
	 */
	public DBFieldIterator fieldKeyIterator(Field minKey, Field maxKey, Field startKey)
			throws IOException {
		synchronized (db) {
			if (schema.useLongKeyNodes()) {
				throw new AssertException();
			}
			return new FieldKeyIterator(minKey, maxKey, startKey);
		}
	}

	/**
	 * Iterate over the records in ascending sorted order
	 * starting at the specified startKey.
	 * @param minKey minimum key value.  Null corresponds to minimum key value.
	 * @param maxKey maximum key value.  Null corresponds to maximum key value.
	 * @param before if true initial position is before minKey, else position
	 * is after maxKey.
	 * @return Field type key iterator
	 * @throws IOException if an I/O error occurs.
	 */
	public DBFieldIterator fieldKeyIterator(Field minKey, Field maxKey, boolean before)
			throws IOException {
		synchronized (db) {
			if (schema.useLongKeyNodes()) {
				throw new AssertException();
			}
			return new FieldKeyIterator(minKey, maxKey, before);
		}
	}

	/**
	 * A RecordIterator class for use with table data contained within LeafNode's.
	 */
	private class LongKeyRecordIterator implements RecordIterator {

		private int bufferId = -1; // current record buffer ID
		private int recordIndex; // current record index
		private boolean isNext; // recover position is next record
		private boolean isPrev; // recover position is previous record

		private DBRecord record; // current record
		private long curKey; // copy of record key (record may get changed by consumer)
		private DBRecord lastRecord;

		private boolean hasPrev; // current record is previous
		private boolean hasNext; // current record is next

		private long minKey;
		private long maxKey;

		private int expectedModCount;

		/**
		 * Construct a record iterator over all records. 
		 * @throws IOException thrown if IO error occurs
		 */
		LongKeyRecordIterator() throws IOException {
			this(Long.MIN_VALUE, Long.MAX_VALUE, Long.MIN_VALUE);
			hasPrev = false;
		}

		/**
		 * Construct a record iterator.
		 * @param minKey minimum allowed primary key.
		 * @param maxKey maximum allowed primary key.
		 * @param startKey the first primary key value.
		 * @throws IOException thrown if IO error occurs
		 */
		LongKeyRecordIterator(long minKey, long maxKey, long startKey) throws IOException {

			expectedModCount = modCount;

			this.minKey = minKey;
			this.maxKey = maxKey;

			if (rootBufferId < 0) {
				return;
			}

			if (minKey > maxKey) {
				return;
			}

			try {
				LongKeyNode rootNode = nodeMgr.getLongKeyNode(rootBufferId);
				LongKeyRecordNode leaf = rootNode.getLeafNode(startKey);
				recordIndex = leaf.getKeyIndex(startKey);

				// Start key was found
				if (recordIndex >= 0) {
					hasPrev = true;
					hasNext = true;
				}

				// Start key was not found
				else {
					recordIndex = -(recordIndex + 1);
					if (recordIndex == leaf.keyCount) {
						--recordIndex;
						hasPrev = leaf.getKey(recordIndex) >= minKey;
						if (!hasPrev) {
							leaf = leaf.getNextLeaf();
							if (leaf == null) {
								return;
							}
							recordIndex = 0;
							hasNext = leaf.getKey(recordIndex) <= maxKey;
						}
					}
					else {
						hasNext = leaf.getKey(recordIndex) <= maxKey;
						if (!hasNext) {
							// position to previous record
							if (recordIndex == 0) {
								leaf = leaf.getPreviousLeaf();
								if (leaf == null) {
									return;
								}
								recordIndex = leaf.keyCount - 1;
							}
							else {
								--recordIndex;
							}
							hasPrev = leaf.getKey(recordIndex) >= minKey;
						}
					}

				}

				if (hasPrev || hasNext) {
					bufferId = leaf.getBufferId();
					record = leaf.getRecord(schema, recordIndex);
					curKey = record.getKey();
				}
			}
			finally {
				nodeMgr.releaseNodes();
			}
		}

		/**
		 * Get the current record leaf.  If the current record can not be found, attempt to 
		 * recover the record position.
		 * @param recoverPrev if true and the current record no longer exists,
		 * the current position will be set to the previous record and isPrev set to true; 
		 * else if false and the current record no longer exists, the current position
		 * will be set to the next record and isNext set to true.
		 * @return LongKeyRecordNode the leaf node containing the current record position
		 * identified by bufferId and recordIndex.  If null, the current record was not found
		 * or the position could not be set to a next/previous record position based upon the
		 * recoverPrev value specified.
		 * @throws IOException thrown if IO error occurs
		 */
		private LongKeyRecordNode getRecordLeaf(boolean recoverPrev) throws IOException {

			if (rootBufferId < 0 || record == null) {
				return null;
			}

			LongKeyRecordNode leaf = null;
			isNext = false;
			isPrev = false;

			if (expectedModCount == modCount) {
				leaf = (LongKeyRecordNode) nodeMgr.getLongKeyNode(bufferId);
				if (recordIndex >= leaf.keyCount || leaf.getKey(recordIndex) != curKey) {
					leaf = null; // something changed - key search required
				}
			}

			if (leaf == null) {

				// Something changed - try to relocate record using key
				LongKeyNode rootNode = nodeMgr.getLongKeyNode(rootBufferId);
				leaf = rootNode.getLeafNode(curKey);
				int index = leaf.getKeyIndex(curKey);
				if (index < 0) {
					// Record was deleted - position on next key
					index = -index - 1;
					if (recoverPrev) {
						--index;
						if (index < 0) {
							leaf = leaf.getPreviousLeaf();
							index = leaf != null ? (leaf.keyCount - 1) : 0;
						}
						isPrev = true;
					}
					else {
						if (index == leaf.keyCount) {
							leaf = leaf.getNextLeaf();
							index = 0;
						}
						isNext = true;
					}
				}
				if (leaf != null) {
					bufferId = leaf.getBufferId();
					recordIndex = index;
				}
				expectedModCount = modCount;
			}
			return leaf;
		}

		@Override
		public boolean hasNext() throws IOException {
			synchronized (db) {

				if (!hasNext && nodeMgr != null) {

					try {
						// Check for modification to storage of previous record
						LongKeyRecordNode leaf = getRecordLeaf(false);
						if (leaf == null) {
							return false;
						}

						// Position to next record
						int nextIndex = recordIndex;
						if (!isNext) {
							++nextIndex;
						}
						int nextBufferId = bufferId;
						if (nextIndex == leaf.keyCount) {
							leaf = leaf.getNextLeaf();
							if (leaf == null) {
								return false;
							}
							nextBufferId = leaf.getBufferId();
							nextIndex = 0;
						}

						// Load next record
						DBRecord nextRecord = leaf.getRecord(schema, nextIndex);
						hasNext = nextRecord.getKey() <= maxKey;
						if (hasNext) {
							bufferId = nextBufferId;
							recordIndex = nextIndex;
							record = nextRecord;
							curKey = record.getKey();
							hasPrev = false;
						}
					}
					finally {
						nodeMgr.releaseNodes();
					}
				}
				return hasNext;
			}
		}

		@Override
		public boolean hasPrevious() throws IOException {
			synchronized (db) {

				if (!hasPrev && nodeMgr != null) {

					try {
						// Check for modification to storage of next record
						LongKeyRecordNode leaf = getRecordLeaf(true);
						if (leaf == null) {
							return false;
						}

						// Position to previous record
						int prevIndex = recordIndex;
						if (!isPrev) {
							--prevIndex;
						}
						int prevBufferId = bufferId;
						if (prevIndex < 0) {
							leaf = leaf.getPreviousLeaf();
							if (leaf == null) {
								return false;
							}
							prevBufferId = leaf.getBufferId();
							prevIndex = leaf.keyCount - 1;
						}

						// Load previous record
						DBRecord prevRecord = leaf.getRecord(schema, prevIndex);
						hasPrev = prevRecord.getKey() >= minKey;
						if (hasPrev) {
							bufferId = prevBufferId;
							recordIndex = prevIndex;
							record = prevRecord;
							curKey = record.getKey();
							hasNext = false;
						}
					}
					finally {
						nodeMgr.releaseNodes();
					}
				}
				return hasPrev;
			}
		}

		@Override
		public DBRecord next() throws IOException {
			if (hasNext || hasNext()) {
				hasNext = false;
				hasPrev = true;
				lastRecord = record;
				return record;
			}
			return null;
		}

		@Override
		public DBRecord previous() throws IOException {
			if (hasPrev || hasPrevious()) {
				hasNext = true;
				hasPrev = false;
				lastRecord = record;
				return record;
			}
			return null;
		}

		@Override
		public boolean delete() throws IOException {
			if (lastRecord == null) {
				return false;
			}
			deleteRecord(lastRecord.getKey());
			lastRecord = null;
			return true;
		}

	}

	/**
	 * A RecordIterator class for use with table data contained within LeafNode's.
	 */
	private class FieldKeyRecordIterator implements RecordIterator {

		private int bufferId = -1; // current record buffer ID
		private int recordIndex; // current record index
		private boolean isNext; // recover position is next record
		private boolean isPrev; // recover position is previous record

		private DBRecord record; // current record
//		private Field curKey;			// copy of record key (record may get changed by consumer)
		private DBRecord lastRecord;

		private boolean hasPrev; // current record is previous
		private boolean hasNext; // current record is next

		private Field minKey;
		private Field maxKey;

		private int expectedModCount;

		/**
		 * Construct a record iterator.
		 * @param minKey minimum allowed primary key.
		 * @param maxKey maximum allowed primary key.
		 * @param startKey the first primary key value. If null, minKey will be used.
		 * @throws IOException thrown if IO error occurs
		 */
		FieldKeyRecordIterator(Field minKey, Field maxKey, Field startKey) throws IOException {

			expectedModCount = modCount;

			this.minKey = minKey;
			this.maxKey = maxKey;

			if (rootBufferId < 0) {
				return;
			}

			if (minKey != null && maxKey != null && minKey.compareTo(maxKey) > 0) {
				return;
			}

			if (startKey != null) {
//				if (minKey != null && startKey.compareTo(minKey) < 0)
//					return;
//				if (maxKey != null && startKey.compareTo(maxKey) > 0)
//					return;
			}
			else {
				startKey = minKey;
			}

			try {
				FieldKeyNode rootNode = getFieldKeyNode(rootBufferId);

				// If startKey not specified, start with leftmost record
				if (startKey == null) {
					FieldKeyRecordNode leaf = rootNode.getLeftmostLeafNode();
					bufferId = leaf.getBufferId();
					recordIndex = 0;
					record = leaf.getRecord(schema, 0);
//					curKey = record.getKeyField();
					hasNext = true;
				}

				// else, start with specified startKey
				else {

					FieldKeyRecordNode leaf = rootNode.getLeafNode(startKey);
					recordIndex = leaf.getKeyIndex(startKey);

					// Start key was found
					if (recordIndex >= 0) {
						hasPrev = true;
						hasNext = true;
					}

					// Start key was not found
					else {
						recordIndex = -(recordIndex + 1);
						if (recordIndex == leaf.getKeyCount()) {
							--recordIndex;
							hasPrev = minKey == null ? true
									: (leaf.getKeyField(recordIndex).compareTo(minKey) >= 0);
							if (!hasPrev) {
								leaf = leaf.getNextLeaf();
								if (leaf == null) {
									return;
								}
								recordIndex = 0;
								hasNext = maxKey == null ? true
										: (leaf.getKeyField(recordIndex).compareTo(maxKey) <= 0);
							}
						}
						else {
							hasNext = maxKey == null ? true
									: (leaf.getKeyField(recordIndex).compareTo(maxKey) <= 0);
							if (!hasNext) {
								// position to previous record
								if (recordIndex == 0) {
									leaf = leaf.getPreviousLeaf();
									if (leaf == null) {
										return;
									}
									recordIndex = leaf.getKeyCount() - 1;
								}
								else {
									--recordIndex;
								}
								hasPrev = minKey == null ? true
										: (leaf.getKeyField(recordIndex).compareTo(minKey) >= 0);
							}
						}
					}

					if (hasPrev || hasNext) {
						bufferId = leaf.getBufferId();
						record = leaf.getRecord(schema, recordIndex);
//						curKey = record.getKeyField();
					}

				}

			}
			finally {
				nodeMgr.releaseNodes();
			}
		}

		/**
		 * Get the current record leaf.  If the current record can not be found, attempt to 
		 * recover the record position.
		 * @param recoverPrev if true and the current record no longer exists,
		 * the current position will be set to the previous record and isPrev set to true; 
		 * else if false and the current record no longer exists, the current position
		 * will be set to the next record and isNext set to true.
		 * @return FieldKeyRecordNode the leaf node containing the current record position
		 * identified by bufferId and recordIndex.  If null, the current record was not found
		 * or the position could not be set to a next/previous record position based upon the
		 * recoverPrev value specified.
		 * @throws IOException thrown if IO error occurs
		 */
		private FieldKeyRecordNode getRecordLeaf(boolean recoverPrev) throws IOException {

			if (rootBufferId < 0 || record == null) {
				return null;
			}

			Field key = record.getKeyField();
			FieldKeyRecordNode leaf = null;
			isNext = false;
			isPrev = false;

			if (expectedModCount == modCount) {
				leaf = (FieldKeyRecordNode) getFieldKeyNode(bufferId);
				if (recordIndex >= leaf.getKeyCount() ||
					!leaf.getKeyField(recordIndex).equals(key)) {
					leaf = null; // something changed - key search required
				}
			}

			if (leaf == null) {

				// Something changed - try to relocate record using key
				FieldKeyNode rootNode = getFieldKeyNode(rootBufferId);
				leaf = rootNode.getLeafNode(key);
				int index = leaf.getKeyIndex(key);
				if (index < 0) {
					// Record was deleted - position on next key
					index = -index - 1;
					if (recoverPrev) {
						--index;
						if (index < 0) {
							leaf = leaf.getPreviousLeaf();
							index = leaf != null ? (leaf.getKeyCount() - 1) : 0;
						}
						isPrev = true;
					}
					else {
						if (index == leaf.getKeyCount()) {
							leaf = leaf.getNextLeaf();
							index = 0;
						}
						isNext = true;
					}
				}
				if (leaf != null) {
					bufferId = leaf.getBufferId();
					recordIndex = index;
				}
				expectedModCount = modCount;
			}
			return leaf;
		}

		@Override
		public boolean hasNext() throws IOException {
			synchronized (db) {

				if (!hasNext && nodeMgr != null) {

					try {
						// Check for modification to storage of previous record
						FieldKeyRecordNode leaf = getRecordLeaf(false);
						if (leaf == null) {
							return false;
						}

						// Position to next record
						int nextIndex = recordIndex;
						if (!isNext) {
							++nextIndex;
						}
						int nextBufferId = bufferId;
						if (nextIndex == leaf.getKeyCount()) {
							leaf = leaf.getNextLeaf();
							if (leaf == null) {
								return false;
							}
							nextBufferId = leaf.getBufferId();
							nextIndex = 0;
						}

						// Load next record
						DBRecord nextRecord = leaf.getRecord(schema, nextIndex);
						hasNext = maxKey == null ? true
								: (nextRecord.getKeyField().compareTo(maxKey) <= 0);
						if (hasNext) {
							bufferId = nextBufferId;
							recordIndex = nextIndex;
							record = nextRecord;
//							curKey = record.getKeyField();
							hasPrev = false;
						}
					}
					finally {
						nodeMgr.releaseNodes();
					}
				}
				return hasNext;
			}
		}

		@Override
		public boolean hasPrevious() throws IOException {
			synchronized (db) {

				if (!hasPrev && nodeMgr != null) {

					try {
						// Check for modification to storage of next record
						FieldKeyRecordNode leaf = getRecordLeaf(true);
						if (leaf == null) {
							return false;
						}

						// Position to previous record
						int prevIndex = recordIndex;
						if (!isPrev) {
							--prevIndex;
						}
						int prevBufferId = bufferId;
						if (prevIndex < 0) {
							leaf = leaf.getPreviousLeaf();
							if (leaf == null) {
								return false;
							}
							prevBufferId = leaf.getBufferId();
							prevIndex = leaf.getKeyCount() - 1;
						}

						// Load previous record
						DBRecord prevRecord = leaf.getRecord(schema, prevIndex);
						hasPrev = minKey == null ? true
								: (prevRecord.getKeyField().compareTo(minKey) >= 0);
						if (hasPrev) {
							bufferId = prevBufferId;
							recordIndex = prevIndex;
							record = prevRecord;
//							curKey = record.getKeyField();
							hasNext = false;
						}
					}
					finally {
						nodeMgr.releaseNodes();
					}
				}
				return hasPrev;
			}
		}

		@Override
		public DBRecord next() throws IOException {
			if (hasNext || hasNext()) {
				hasNext = false;
				hasPrev = true;
				lastRecord = record;
				return record;
			}
			return null;
		}

		@Override
		public DBRecord previous() throws IOException {
			if (hasPrev || hasPrevious()) {
				hasNext = true;
				hasPrev = false;
				lastRecord = record;
				return record;
			}
			return null;
		}

		@Override
		public boolean delete() throws IOException {
			if (lastRecord == null) {
				return false;
			}
			deleteRecord(lastRecord.getKeyField());
			lastRecord = null;
			return true;
		}

	}

	/**
	 * A long key iterator class.  The initial iterator is optimized for
	 * short iterations.  If it determined that the iterator is to be used 
	 * for a large number of iterations, the underlying iterator is switched
	 * to one optimized for longer iterations.
	 */
	private class LongKeyIterator implements DBLongIterator {

		private static final int SHORT_ITER_THRESHOLD = 10;

		private DBLongIterator keyIter;
		private int iterCnt = 0;

		/**
		 * Construct a record iterator over all records. 
		 * @throws IOException thrown if IO error occurs
		 */
		LongKeyIterator() throws IOException {
			keyIter = new LongKeyIterator2();
		}

		/**
		 * Construct a record iterator.
		 * @param minKey minimum allowed primary key.
		 * @param maxKey maximum allowed primary key.
		 * @param startKey the first primary key value.
		 * @throws IOException thrown if IO error occurs
		 */
		LongKeyIterator(long minKey, long maxKey, long startKey) throws IOException {
			keyIter = new LongKeyIterator1(minKey, maxKey, startKey);
		}

		@Override
		public boolean hasNext() throws IOException {
			synchronized (db) {
				if (iterCnt < SHORT_ITER_THRESHOLD) {
					if (++iterCnt > SHORT_ITER_THRESHOLD) {
						// Long iterations should use LongKeyIterator1
						keyIter = new LongKeyIterator1((LongKeyIterator2) keyIter);
					}
				}
				return keyIter.hasNext();
			}
		}

		@Override
		public boolean hasPrevious() throws IOException {
			synchronized (db) {
				if (iterCnt < SHORT_ITER_THRESHOLD) {
					if (++iterCnt > SHORT_ITER_THRESHOLD) {
						// Long iterations should use LongKeyIterator1
						keyIter = new LongKeyIterator1((LongKeyIterator2) keyIter);
					}
				}
				return keyIter.hasPrevious();
			}
		}

		@Override
		public long next() throws IOException {
			return keyIter.next();
		}

		@Override
		public long previous() throws IOException {
			return keyIter.previous();
		}

		@Override
		public boolean delete() throws IOException {
			return keyIter.delete();
		}
	}

	/**
	 * A long key iterator class - optimized for long iterations since
	 * all keys are read for each record node.
	 */
	private class LongKeyIterator1 implements DBLongIterator {

		private int bufferId;
		private int keyIndex;
		private long[] keys;
		private long key;
		private long lastKey;
		private boolean hasLastKey;

		private int expectedModCount;

		private boolean hasPrev;
		private boolean hasNext;

		private long minKey;
		private long maxKey;

		LongKeyIterator1(LongKeyIterator2 keyIter) throws IOException {

			this.bufferId = keyIter.bufferId;
			this.keyIndex = keyIter.keyIndex;
			this.key = keyIter.key;
			this.lastKey = keyIter.lastKey;
			this.hasLastKey = keyIter.hasLastKey;
			this.expectedModCount = keyIter.expectedModCount;
			this.hasPrev = keyIter.hasPrev;
			this.hasNext = keyIter.hasNext;
			this.minKey = keyIter.minKey;
			this.maxKey = keyIter.maxKey;

			if (bufferId >= 0) {

				if (modCount != expectedModCount) {
					reset();
				}
				else {
					LongKeyRecordNode leaf = (LongKeyRecordNode) nodeMgr.getLongKeyNode(bufferId);
					getKeys(leaf);
				}

			}

		}

		/**
		 * Construct a record iterator.
		 * @param minKey minimum allowed primary key.
		 * @param maxKey maximum allowed primary key.
		 * @param startKey the first primary key value.
		 * @throws IOException thrown if IO error occurs
		 */
		LongKeyIterator1(long minKey, long maxKey, long startKey) throws IOException {

//			if (startKey < minKey || startKey > maxKey || minKey > maxKey)
//				throw new IllegalArgumentException();

			this.minKey = minKey;
			this.maxKey = maxKey;
			this.key = startKey;

			initialize(startKey);
		}

		/**
		 * Initialize (or re-initialize) iterator state.
		 * An empty or null keys array will force a complete initialization.
		 * Otherwise, following the deletethe keys array and keyIndex should reflect the state
		 * following a delete.
		 * @param targetKey the initial key.  For construction this is the startKey, 
		 * following a delete this is the deleted key.
		 * @throws IOException thrown if IO error occurs
		 */
		private void initialize(long targetKey) throws IOException {

			expectedModCount = modCount;
			hasPrev = false;
			hasNext = false;

			if (rootBufferId < 0) {
				bufferId = -1;
				keys = new long[0];
				return;
			}

			try {
				LongKeyRecordNode leaf = null;
				if (keys == null || keys.length == 0) {
					LongKeyNode rootNode = nodeMgr.getLongKeyNode(rootBufferId);
					leaf = rootNode.getLeafNode(targetKey);

					// Empty leaf node - special case
					int leafRecCount = leaf.keyCount;
					if (leafRecCount == 0) {
						return;
					}

					keyIndex = leaf.getKeyIndex(targetKey);
					getKeys(leaf);
				}

				// Start key was found
				if (keyIndex >= 0) {
					key = targetKey;
					hasPrev = true;
					hasNext = true;
				}

				// Start key was not found
				else {
					keyIndex = -(keyIndex + 1);
					if (keyIndex == keys.length) {
						--keyIndex;
						hasPrev = keys[keyIndex] >= minKey;
						if (!hasPrev) {
							if (leaf == null) {
								keys = null;
								initialize(targetKey);
								return;
							}
							leaf = leaf.getNextLeaf();
							if (leaf == null) {
								keys = new long[0];
								bufferId = -1;
								return;
							}
							keyIndex = 0;
							getKeys(leaf);
							hasNext = keys[keyIndex] <= maxKey;
						}
					}
					else {
						hasNext = keys[keyIndex] <= maxKey;
						if (!hasNext) {
							// position to previous record
							if (keyIndex == 0) {
								if (leaf == null) {
									keys = null;
									initialize(targetKey);
									return;
								}
								leaf = leaf.getPreviousLeaf();
								if (leaf == null) {
									keys = new long[0];
									bufferId = -1;
									return;
								}
								keyIndex = leaf.keyCount - 1;
								getKeys(leaf);
							}
							else {
								--keyIndex;
							}
							hasPrev = keys[keyIndex] >= minKey;
						}
					}
					if (hasNext || hasPrev) {
						key = keys[keyIndex];
					}
				}
			}
			finally {
				nodeMgr.releaseNodes();
			}

		}

		private void reset() throws IOException {
			boolean hadNext = hasNext;
			boolean hadPrev = hasPrev;
			keys = null;
			initialize(key);

			if (hasNext && hasPrev) {
				hasNext = hadNext;
				hasPrev = hadPrev;
			}
		}

		private void getKeys(LongKeyRecordNode node) {
			bufferId = node.getBufferId();
			if (keys == null || keys.length != node.keyCount) {
				keys = new long[node.keyCount];
			}
			for (int i = 0; i < node.keyCount; i++) {
				keys[i] = node.getKey(i);
			}
		}

		@Override
		public boolean hasNext() throws IOException {
			synchronized (db) {
				if (modCount != expectedModCount) {
					reset();
				}
				if (!hasNext) {

					// Check next key index
					int nextIndex = keyIndex + 1;

					// Process next leaf if needed
					if (nextIndex >= keys.length) {
						try {
							if (bufferId == -1) {
								return false;
							}
							LongKeyRecordNode leaf = ((LongKeyRecordNode) nodeMgr.getLongKeyNode(
								bufferId)).getNextLeaf();
							if (leaf == null || leaf.getKey(0) > maxKey) {
								return false;
							}
							getKeys(leaf);
							key = keys[0];
							keyIndex = 0;
							hasNext = true;
							hasPrev = false;
						}
						finally {
							nodeMgr.releaseNodes();
						}
					}

					// else, use keys cache
					else {
						hasNext = keys[nextIndex] <= maxKey;
						if (hasNext) {
							key = keys[nextIndex];
							keyIndex = nextIndex;
							hasPrev = false;
						}
					}

				}
				return hasNext;
			}
		}

		@Override
		public boolean hasPrevious() throws IOException {
			synchronized (db) {
				if (modCount != expectedModCount) {
					reset();
				}
				if (!hasPrev) {

					// Check previous key index
					int prevIndex = keyIndex - 1;

					// Process previous leaf if needed
					if (prevIndex < 0 || keys.length == 0) {
						try {
							if (bufferId == -1) {
								return false;
							}
							LongKeyRecordNode leaf = ((LongKeyRecordNode) nodeMgr.getLongKeyNode(
								bufferId)).getPreviousLeaf();
							if (leaf == null) {
								return false;
							}
							prevIndex = leaf.keyCount - 1;
							if (leaf.getKey(prevIndex) < minKey) {
								return false;
							}
							getKeys(leaf);
							key = keys[prevIndex];
							keyIndex = prevIndex;
							hasNext = false;
							hasPrev = true;
						}
						finally {
							nodeMgr.releaseNodes();
						}
					}

					// else, use keys cache
					else {
						hasPrev = keys[prevIndex] >= minKey;
						if (hasPrev) {
							key = keys[prevIndex];
							keyIndex = prevIndex;
							hasNext = false;
						}
					}
				}
				return hasPrev;
			}
		}

		@Override
		public long next() throws IOException {
			if (hasNext || hasNext()) {
				hasNext = false;
				hasPrev = true;
				lastKey = key;
				hasLastKey = true;
				return key;
			}
			throw new NoSuchElementException();
		}

		@Override
		public long previous() throws IOException {
			if (hasPrev || hasPrevious()) {
				hasNext = true;
				hasPrev = false;
				lastKey = key;
				hasLastKey = true;
				return key;
			}
			throw new NoSuchElementException();
		}

		@Override
		public boolean delete() throws IOException {
			if (hasLastKey) {
				synchronized (db) {
					long deleteKey = lastKey;
					hasLastKey = false;
					boolean success = deleteRecord(deleteKey);
					int newLen = keys.length - 1;
					if (deleteKey == key && keys.length > 1 /* && keyIndex < newLen */) {
						long[] newKeys = new long[newLen];
						System.arraycopy(keys, 0, newKeys, 0, keyIndex);
						System.arraycopy(keys, keyIndex + 1, newKeys, keyIndex, newLen - keyIndex);
						keys = newKeys;
						keyIndex = -(keyIndex + 1); // reflects non-existent key to initialize method
					}
					else {
						keys = null;
					}
					initialize(deleteKey);
					return success;
				}
			}
			return false;
		}

	}

	/**
	 * A long key iterator class - optimized for short iterations since
	 * the number of keys read from each record node is minimized.
	 */
	private class LongKeyIterator2 implements DBLongIterator {

		private int bufferId;
		private int keyIndex;
		private long key;
		private long lastKey;
		private boolean hasLastKey = false;

		private int expectedModCount;

		private boolean hasPrev;
		private boolean hasNext;

		private long minKey;
		private long maxKey;

		/**
		 * Construct a record iterator over all records. 
		 * @throws IOException thrown if IO error occurs
		 */
		LongKeyIterator2() throws IOException {
			this(Long.MIN_VALUE, Long.MAX_VALUE, Long.MIN_VALUE);
			hasPrev = false;
		}

		/**
		 * Construct a record iterator.
		 * @param minKey minimum allowed primary key.
		 * @param maxKey maximum allowed primary key.
		 * @param startKey the first primary key value.
		 * @throws IOException thrown if IO error occurs
		 */
		LongKeyIterator2(long minKey, long maxKey, long startKey) throws IOException {

//			if (startKey < minKey || startKey > maxKey || minKey > maxKey)
//				throw new IllegalArgumentException();

			this.minKey = minKey;
			this.maxKey = maxKey;
			this.key = startKey;

			initialize(startKey);
		}

		/**
		 * Initialize (or re-initialize) iterator state.
		 * An empty or null keys array will force a complete initialization.
		 * Otherwise, following the deletethe keys array and keyIndex should reflect the state
		 * following a delete.
		 * @param targetKey the initial key.  For construction this is the startKey, 
		 * following a delete this is the deleted key.
		 * @throws IOException thrown if IO error occurs
		 */
		private void initialize(long targetKey) throws IOException {

			expectedModCount = modCount;
			hasPrev = false;
			hasNext = false;
			bufferId = -1;

			if (rootBufferId < 0) {
				return;
			}

			try {
				LongKeyRecordNode leaf = null;
				LongKeyNode rootNode = nodeMgr.getLongKeyNode(rootBufferId);

				leaf = rootNode.getLeafNode(targetKey);
				bufferId = leaf.getBufferId();

				// Empty leaf node - special case
				if (leaf.keyCount == 0) {
					keyIndex = -1;
					return;
				}

				keyIndex = leaf.getKeyIndex(targetKey);

				// Start key was found
				if (keyIndex >= 0) {
					key = leaf.getKey(keyIndex);
					hasPrev = true;
					hasNext = true;
				}

				// Start key was not found
				else {
					keyIndex = -(keyIndex + 1);
					if (keyIndex == leaf.keyCount) {
						--keyIndex;
						key = leaf.getKey(keyIndex);
						hasPrev = key >= minKey;
					}
					else {
						key = leaf.getKey(keyIndex);
						hasNext = key <= maxKey;
					}
				}
			}
			finally {
				nodeMgr.releaseNodes();
			}

		}

		private void reset() throws IOException {
			boolean hadNext = hasNext;
			boolean hadPrev = hasPrev;
			initialize(key);
			if (hasNext && hasPrev) {
				hasNext = hadNext;
				hasPrev = hadPrev;
			}
		}

		@Override
		public boolean hasNext() throws IOException {
			synchronized (db) {
				if (modCount != expectedModCount) {
					reset();
				}
				if (!hasNext) {

					if (bufferId < 0 || keyIndex < 0) {
						return false;
					}

					// Check next key index
					int nextIndex = keyIndex + 1;

					try {
						// Process next leaf if needed
						LongKeyRecordNode leaf =
							(LongKeyRecordNode) nodeMgr.getLongKeyNode(bufferId);
						if (nextIndex >= leaf.keyCount) {
							leaf = leaf.getNextLeaf();
							if (leaf == null) {
								return false;
							}
							long nextKey = leaf.getKey(0);
							if (nextKey > maxKey) {
								return false;
							}
							bufferId = leaf.getBufferId();
							key = nextKey;
							keyIndex = 0;
							hasNext = true;
							hasPrev = false;
						}

						// else, use keys cache
						else {
							long nextKey = leaf.getKey(nextIndex);
							hasNext = (nextKey <= maxKey);
							if (hasNext) {
								key = nextKey;
								keyIndex = nextIndex;
								hasPrev = false;
							}
						}
					}
					finally {
						nodeMgr.releaseNodes();
					}

				}
				return hasNext;
			}
		}

		@Override
		public boolean hasPrevious() throws IOException {
			synchronized (db) {
				if (modCount != expectedModCount) {
					reset();
				}
				if (!hasPrev) {

					if (bufferId < 0 || keyIndex < 0) {
						return false;
					}

					// Check previous key index
					int prevIndex = keyIndex - 1;

					try {
						// Process previous leaf if needed
						LongKeyRecordNode leaf =
							(LongKeyRecordNode) nodeMgr.getLongKeyNode(bufferId);
						if (prevIndex < 0) {
							leaf = leaf.getPreviousLeaf();
							if (leaf == null) {
								return false;
							}
							prevIndex = leaf.keyCount - 1;
							long prevKey = leaf.getKey(prevIndex);
							if (prevKey < minKey) {
								return false;
							}
							bufferId = leaf.getBufferId();
							key = prevKey;
							keyIndex = prevIndex;
							hasNext = false;
							hasPrev = true;
						}

						// else, use keys cache
						else {
							long prevKey = leaf.getKey(prevIndex);
							hasPrev = prevKey >= minKey;
							if (hasPrev) {
								key = prevKey;
								keyIndex = prevIndex;
								hasNext = false;
							}
						}
					}
					finally {
						nodeMgr.releaseNodes();
					}
				}
				return hasPrev;
			}
		}

		@Override
		public long next() throws IOException {
			if (hasNext || hasNext()) {
				hasNext = false;
				hasPrev = true;
				lastKey = key;
				hasLastKey = true;
				return key;
			}
			throw new NoSuchElementException();
		}

		@Override
		public long previous() throws IOException {
			if (hasPrev || hasPrevious()) {
				hasNext = true;
				hasPrev = false;
				lastKey = key;
				hasLastKey = true;
				return key;
			}
			throw new NoSuchElementException();
		}

		@Override
		public boolean delete() throws IOException {
			if (hasLastKey) {
				hasLastKey = false;
				return deleteRecord(lastKey);
			}
			return false;
		}

	}

	/**
	 * A Field key iterator class.  The initial iterator is optimized for
	 * short iterations.  If it determined that the iterator is to be used 
	 * for a large number of iterations, the underlying iterator is switched
	 * to one optimized for longer iterations.
	 */
	private class FieldKeyIterator implements DBFieldIterator {

		private static final int SHORT_ITER_THRESHOLD = 10;

		private DBFieldIterator keyIter;
		private int iterCnt = 0;

		/**
		 * Construct a record iterator.
		 * @param minKey minimum key value.  Null corresponds to minimum key value.
		 * @param maxKey maximum key value.  Null corresponds to maximum key value.
		 * @param startKey the first primary key value.  If null minKey will be assumed,
		 * if still null the minimum indexed value will be assumed.
		 * @throws IOException thrown if IO error occurs
		 */
		FieldKeyIterator(Field minKey, Field maxKey, Field startKey) throws IOException {
			keyIter = new FieldKeyIterator2(minKey, maxKey, startKey);
		}

		/**
		 * Construct a record iterator.
		 * @param minKey minimum key value.  Null corresponds to minimum key value.
		 * @param maxKey maximum key value.  Null corresponds to maximum key value.
		 * @param before true if initial position is before range, else after range
		 * @throws IOException thrown if IO error occurs
		 */
		FieldKeyIterator(Field minKey, Field maxKey, boolean before) throws IOException {

			Field startKey = before ? minKey : maxKey;

			if (startKey == null && !before && rootBufferId != -1) {
				try {
					FieldKeyNode rightmostLeaf =
						getFieldKeyNode(rootBufferId).getRightmostLeafNode();
					startKey = rightmostLeaf.getKeyField(rightmostLeaf.getKeyCount() - 1);
				}
				finally {
					nodeMgr.releaseNodes();
				}
			}

			keyIter = new FieldKeyIterator2(minKey, maxKey, startKey);
		}

		@Override
		public boolean hasNext() throws IOException {
			synchronized (db) {
				if (iterCnt < SHORT_ITER_THRESHOLD) {
					if (++iterCnt > SHORT_ITER_THRESHOLD) {
						// Long iterations should use LongKeyIterator1
						keyIter = new FieldKeyIterator1((FieldKeyIterator2) keyIter);
					}
				}
				return keyIter.hasNext();
			}
		}

		@Override
		public boolean hasPrevious() throws IOException {
			synchronized (db) {
				if (iterCnt < SHORT_ITER_THRESHOLD) {
					if (++iterCnt > SHORT_ITER_THRESHOLD) {
						// Long iterations should use LongKeyIterator1
						keyIter = new FieldKeyIterator1((FieldKeyIterator2) keyIter);
					}
				}
				return keyIter.hasPrevious();
			}
		}

		@Override
		public Field next() throws IOException {
			return keyIter.next();
		}

		@Override
		public Field previous() throws IOException {
			return keyIter.previous();
		}

		@Override
		public boolean delete() throws IOException {
			return keyIter.delete();
		}
	}

	/**
	 * A Field key iterator class - optimized for long iterations since
	 * all keys are read for each record node.
	 */
	private class FieldKeyIterator1 implements DBFieldIterator {

		private int bufferId;
		private int keyIndex;
		private Field[] keys;
		private Field key;
		private Field lastKey;

		private int expectedModCount;

		private boolean hasPrev;
		private boolean hasNext;

		private Field minKey;
		private Field maxKey;

		FieldKeyIterator1(FieldKeyIterator2 keyIter) throws IOException {

			this.bufferId = keyIter.bufferId;
			this.keyIndex = keyIter.keyIndex;
			this.key = keyIter.key;
			this.lastKey = keyIter.lastKey;
			this.expectedModCount = keyIter.expectedModCount;
			this.hasPrev = keyIter.hasPrev;
			this.hasNext = keyIter.hasNext;
			this.minKey = keyIter.minKey;
			this.maxKey = keyIter.maxKey;

			if (bufferId >= 0) {

				if (modCount != expectedModCount) {
					reset();
				}
				else {
					FieldKeyRecordNode leaf = (FieldKeyRecordNode) getFieldKeyNode(bufferId);
					getKeys(leaf);
				}

			}
		}

		/**
		 * Initialize (or re-initialize) iterator state.
		 * An empty or null keys array will force a complete initialization.
		 * Otherwise, following the delete the keys array and keyIndex should reflect the state
		 * following a delete.
		 * @param targetKey the initial key.  For construction this is the startKey, 
		 * following a delete this is the deleted key.
		 * @throws IOException thrown if IO error occurs
		 */
		private void initialize(Field targetKey) throws IOException {

			expectedModCount = modCount;
			hasNext = false;
			hasPrev = false;

			if (rootBufferId < 0) {
				keys = Field.EMPTY_ARRAY;
				bufferId = -1;
				return;
			}

			try {

				FieldKeyRecordNode leaf = null;
				if (keys == null || keys.length == 0) {

					FieldKeyNode rootNode = getFieldKeyNode(rootBufferId);

					if (targetKey == null) {
						targetKey = minKey;
					}

					// If startKey not specified, start with leftmost record
					if (targetKey == null) {
						leaf = rootNode.getLeftmostLeafNode();
						getKeys(leaf);
						key = keys[0];
						keyIndex = 0;
						hasNext = true;
						return;
					}
					leaf = rootNode.getLeafNode(targetKey);
					getKeys(leaf);

					// Empty leaf node - special case
					if (keys.length == 0) {
						return;
					}

					keyIndex = leaf.getKeyIndex(targetKey);
				}

				// Start key was found
				if (keyIndex >= 0) {
					hasPrev = true;
					hasNext = true;
				}

				// Start key was not found
				else {
					keyIndex = -(keyIndex + 1);
					if (keyIndex == keys.length) {
						--keyIndex;
						hasPrev = minKey == null ? true : (keys[keyIndex].compareTo(minKey) >= 0);
						if (!hasPrev) {
							if (leaf == null) {
								keys = null;
								initialize(targetKey);
								return;
							}
							leaf = leaf.getNextLeaf();
							if (leaf == null) {
								keys = Field.EMPTY_ARRAY;
								bufferId = -1;
								return;
							}
							keyIndex = 0;
							getKeys(leaf);
							hasNext =
								maxKey == null ? true : (keys[keyIndex].compareTo(maxKey) <= 0);
						}
					}
					else {
						hasNext = maxKey == null ? true : (keys[keyIndex].compareTo(maxKey) <= 0);
						if (!hasNext) {
							// position to previous record
							if (keyIndex == 0) {
								if (leaf == null) {
									keys = null;
									initialize(targetKey);
									return;
								}
								leaf = leaf.getPreviousLeaf();
								if (leaf == null) {
									keys = Field.EMPTY_ARRAY;
									bufferId = -1;
									return;
								}
								keyIndex = leaf.getKeyCount() - 1;
								getKeys(leaf);
							}
							else {
								--keyIndex;
							}
							hasPrev =
								minKey == null ? true : (keys[keyIndex].compareTo(minKey) >= 0);
						}
					}
					if (hasNext || hasPrev) {
						key = keys[keyIndex];
					}
				}

			}
			finally {
				nodeMgr.releaseNodes();
			}
		}

		private void reset() throws IOException {
			boolean hadNext = hasNext;
			boolean hadPrev = hasPrev;
			keys = null;
			initialize(key);
			if (hasNext && hasPrev) {
				hasNext = hadNext;
				hasPrev = hadPrev;
			}
		}

		private void getKeys(FieldKeyRecordNode node) throws IOException {
			bufferId = node.getBufferId();
			int keyCount = node.getKeyCount();
			if (keys == null || keys.length != keyCount) {
				keys = new Field[keyCount];
			}
			for (int i = 0; i < keyCount; i++) {
				keys[i] = node.getKeyField(i);
			}
		}

		@Override
		public boolean hasNext() throws IOException {
			synchronized (db) {
				if (modCount != expectedModCount) {
					reset();
				}
				if (!hasNext) {

					if (bufferId < 0) {
						return false;
					}

					// Check next key index
					int nextIndex = keyIndex + 1;

					// Process next leaf if needed
					if (nextIndex >= keys.length) {
						try {
							FieldKeyRecordNode leaf =
								((FieldKeyRecordNode) getFieldKeyNode(bufferId)).getNextLeaf();
							if (leaf == null ||
								(maxKey != null && leaf.getKeyField(0).compareTo(maxKey) > 0)) {
								return false;
							}
							getKeys(leaf);
							key = keys[0];
							keyIndex = 0;
							hasNext = true;
							hasPrev = false;
						}
						finally {
							nodeMgr.releaseNodes();
						}
					}

					// else, use keys cache
					else {
						hasNext = maxKey == null || keys[nextIndex].compareTo(maxKey) <= 0;
						if (hasNext) {
							key = keys[nextIndex];
							keyIndex = nextIndex;
							hasPrev = false;
						}
					}

				}
				return hasNext;
			}
		}

		@Override
		public boolean hasPrevious() throws IOException {
			synchronized (db) {
				if (modCount != expectedModCount) {
					reset();
				}
				if (!hasPrev) {

					if (bufferId < 0) {
						return false;
					}

					// Check previous key index
					int prevIndex = keyIndex - 1;

					// Process previous leaf if needed
					if (prevIndex < 0) {
						try {
							FieldKeyRecordNode leaf =
								((FieldKeyRecordNode) getFieldKeyNode(bufferId)).getPreviousLeaf();
							if (leaf == null) {
								return false;
							}
							prevIndex = leaf.getKeyCount() - 1;
							if (minKey != null &&
								leaf.getKeyField(prevIndex).compareTo(minKey) < 0) {
								return false;
							}
							getKeys(leaf);
							key = keys[prevIndex];
							keyIndex = prevIndex;
							hasNext = false;
							hasPrev = true;
						}
						finally {
							nodeMgr.releaseNodes();
						}
					}

					// else, use keys cache
					else {
						hasPrev = minKey == null || keys[prevIndex].compareTo(minKey) >= 0;
						if (hasPrev) {
							key = keys[prevIndex];
							keyIndex = prevIndex;
							hasNext = false;
						}
					}
				}
				return hasPrev;
			}
		}

		@Override
		public Field next() throws IOException {
			if (hasNext || hasNext()) {
				hasNext = false;
				hasPrev = true;
				lastKey = key;
				return key;
			}
			return null;
		}

		@Override
		public Field previous() throws IOException {
			if (hasPrev || hasPrevious()) {
				hasNext = true;
				hasPrev = false;
				lastKey = key;
				return key;
			}
			return null;
		}

		@Override
		public boolean delete() throws IOException {
			if (lastKey != null) {
				synchronized (db) {
					Field deleteKey = lastKey;
					lastKey = null;
					boolean success = deleteRecord(deleteKey);
					int newLen = keys.length - 1;
					if (deleteKey.equals(key) && keys.length > 1 && keyIndex < newLen) {
						Field[] newKeys = new Field[newLen];
						System.arraycopy(keys, 0, newKeys, 0, keyIndex);
						System.arraycopy(keys, keyIndex + 1, newKeys, keyIndex, newLen - keyIndex);
						keys = newKeys;
						keyIndex = -(keyIndex + 1); // reflects non-existent key to initialize method
					}
					else {
						keys = null;
					}
					initialize(deleteKey);
					return success;
				}
			}
			return false;
		}

	}

	/**
	 * A Field key iterator class - optimized for short iterations since
	 * the number of keys read from each record node is minimized.
	 */
	private class FieldKeyIterator2 implements DBFieldIterator {

		private int bufferId;
		private int keyIndex;
		private Field lastKey;
		private Field key;

		private int expectedModCount;

		private boolean hasPrev;
		private boolean hasNext;

		private Field minKey;
		private Field maxKey;

		/**
		 * Construct a record iterator.
		 * @param minKey minimum key value.  Null corresponds to minimum key value.
		 * @param maxKey maximum key value.  Null corresponds to maximum key value.
		 * @param startKey the first primary key value.  If null minKey will be assumed,
		 * if still null the minimum indexed value will be assumed.
		 * @throws IOException
		 */
		FieldKeyIterator2(Field minKey, Field maxKey, Field startKey) throws IOException {

			this.minKey = minKey;
			this.maxKey = maxKey;
			this.key = startKey;

			initialize(startKey);
		}

		/**
		 * Initialize (or re-initialize) iterator state.
		 * An empty or null keys array will force a complete initialization.
		 * Otherwise, following the delete the keys array and keyIndex should reflect the state
		 * following a delete.
		 * @param targetKey the initial key.  For construction this is the startKey, 
		 * following a delete this is the deleted key.
		 * @throws IOException thrown if IO error occurs
		 */
		private void initialize(Field targetKey) throws IOException {

			expectedModCount = modCount;
			hasNext = false;
			hasPrev = false;
			bufferId = -1;

			if (rootBufferId < 0) {
				return;
			}

			try {

				FieldKeyRecordNode leaf;
				FieldKeyNode rootNode = getFieldKeyNode(rootBufferId);

				if (targetKey == null) {
					targetKey = minKey;
				}

				// If startKey not specified, start with leftmost record
				if (targetKey == null) {
					leaf = rootNode.getLeftmostLeafNode();
					bufferId = leaf.getBufferId();
					key = leaf.getKeyField(0);
					keyIndex = 0;
					hasNext = true;
					return;
				}
				leaf = rootNode.getLeafNode(targetKey);
				bufferId = leaf.getBufferId();

				// Empty leaf node - special case
				if (leaf.getKeyCount() == 0) {
					keyIndex = -1;
					return;
				}

				keyIndex = leaf.getKeyIndex(targetKey);

				// Start key was found
				if (keyIndex >= 0) {
					key = leaf.getKeyField(keyIndex);
					hasPrev = true;
					hasNext = true;
				}

				// Start key was not found
				else {
					keyIndex = -(keyIndex + 1);
					if (keyIndex == leaf.getKeyCount()) {
						--keyIndex;
						key = leaf.getKeyField(keyIndex);
						hasPrev = minKey == null ? true : (key.compareTo(minKey) >= 0);
					}
					else {
						key = leaf.getKeyField(keyIndex);
						hasNext = maxKey == null ? true : (key.compareTo(maxKey) <= 0);
					}

				}

			}
			finally {
				nodeMgr.releaseNodes();
			}
		}

		private void reset() throws IOException {
			boolean hadNext = hasNext;
			boolean hadPrev = hasPrev;
			initialize(key);
			if (hasNext && hasPrev) {
				hasNext = hadNext;
				hasPrev = hadPrev;
			}
		}

		@Override
		public boolean hasNext() throws IOException {
			synchronized (db) {
				if (modCount != expectedModCount) {
					reset();
				}
				if (!hasNext) {

					if (bufferId < 0 || keyIndex < 0) {
						return false;
					}

					// Check next key index
					int nextIndex = keyIndex + 1;

					try {
						// Process next leaf if needed
						FieldKeyRecordNode leaf = (FieldKeyRecordNode) getFieldKeyNode(bufferId);
						if (nextIndex >= leaf.getKeyCount()) {
							leaf = leaf.getNextLeaf();
							if (leaf == null) {
								return false;
							}
							Field nextKey = leaf.getKeyField(0);
							if (maxKey != null && nextKey.compareTo(maxKey) > 0) {
								return false;
							}
							bufferId = leaf.getBufferId();
							key = nextKey;
							keyIndex = 0;
							hasNext = true;
							hasPrev = false;
						}

						// else, use keys cache
						else {
							Field nextKey = leaf.getKeyField(nextIndex);
							hasNext = maxKey == null ? true : (nextKey.compareTo(maxKey) <= 0);
							if (hasNext) {
								key = nextKey;
								keyIndex = nextIndex;
								hasPrev = false;
							}
						}
					}
					finally {
						nodeMgr.releaseNodes();
					}
				}
				return hasNext;
			}
		}

		@Override
		public boolean hasPrevious() throws IOException {
			synchronized (db) {
				if (modCount != expectedModCount) {
					reset();
				}
				if (!hasPrev) {

					if (bufferId < 0 || keyIndex < 0) {
						return false;
					}

					// Check previous key index
					int prevIndex = keyIndex - 1;

					try {
						// Process previous leaf if needed
						FieldKeyRecordNode leaf = (FieldKeyRecordNode) getFieldKeyNode(bufferId);
						if (prevIndex < 0) {
							leaf = leaf.getPreviousLeaf();
							if (leaf == null) {
								return false;
							}
							prevIndex = leaf.getKeyCount() - 1;
							Field prevKey = leaf.getKeyField(prevIndex);
							if (minKey != null && prevKey.compareTo(minKey) < 0) {
								return false;
							}
							bufferId = leaf.getBufferId();
							key = prevKey;
							keyIndex = prevIndex;
							hasNext = false;
							hasPrev = true;
						}

						// else, use keys cache
						else {
							Field prevKey = leaf.getKeyField(prevIndex);
							hasPrev = minKey == null ? true : (prevKey.compareTo(minKey) >= 0);
							if (hasPrev) {
								key = prevKey;
								keyIndex = prevIndex;
								hasNext = false;
							}
						}
					}
					finally {
						nodeMgr.releaseNodes();
					}
				}
				return hasPrev;
			}
		}

		@Override
		public Field next() throws IOException {
			if (hasNext || hasNext()) {
				hasNext = false;
				hasPrev = true;
				lastKey = key;
				return key;
			}
			return null;
		}

		@Override
		public Field previous() throws IOException {
			if (hasPrev || hasPrevious()) {
				hasNext = true;
				hasPrev = false;
				lastKey = key;
				return key;
			}
			return null;
		}

		@Override
		public boolean delete() throws IOException {
			if (lastKey != null) {
				Field deleteKey = lastKey;
				lastKey = null;
				return deleteRecord(deleteKey);
			}
			return false;
		}

	}

	/**
	 * @return true if table is valid and has not been invalidated
	 */
	public boolean isInvalid() {
		return nodeMgr == null;
	}

	@Override
	public String toString() {
		return getName() + "(" + getRecordCount() + ")";
	}
}
