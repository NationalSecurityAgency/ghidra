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
package ghidra.program.database;

import java.io.IOException;
import java.util.*;

import db.*;
import ghidra.framework.data.DomainObjectDBChangeSet;
import ghidra.program.database.map.NormalizedAddressSet;
import ghidra.program.model.listing.DataTypeArchiveChangeSet;

/**
 * Holds changes made to a data type archive.
 *
 */
class DataTypeArchiveDBChangeSet implements DataTypeArchiveChangeSet, DomainObjectDBChangeSet {

	private static final Schema STORED_ID_SCHEMA =
		new Schema(0, "Key", new Class[] { LongField.class }, new String[] { "value" });

	private static final String DATATYPE_ADDITIONS = "DataType Additions";
	private static final String DATATYPE_CHANGES = "DataType Changes";
	private static final String CATEGORY_ADDITIONS = "Category Additions";
	private static final String CATEGORY_CHANGES = "Category Changes";
	private static final String SOURCE_ARCHIVE_ADDITIONS = "Source Archive Additions";
	private static final String SOURCE_ARCHIVE_CHANGES = "Source Archive Changes";

	private HashSet<Long> changedDataTypeIds;
	private HashSet<Long> changedCategoryIds;
	private HashSet<Long> changedSourceArchiveIds;
	private HashSet<Long> addedDataTypeIds;
	private HashSet<Long> addedCategoryIds;
	private HashSet<Long> addedSourceArchiveIds;

	private HashSet<Long> tmpChangedDataTypeIds;
	private HashSet<Long> tmpChangedCategoryIds;
	private HashSet<Long> tmpChangedSourceArchiveIds;
	private HashSet<Long> tmpAddedDataTypeIds;
	private HashSet<Long> tmpAddedCategoryIds;
	private HashSet<Long> tmpAddedSourceArchiveIds;

	private LinkedList<MyChangeDiff> undoList = new LinkedList<MyChangeDiff>();
	private LinkedList<MyChangeDiff> redoList = new LinkedList<MyChangeDiff>();

	private boolean inTransaction;
	private int numUndos = 4;

	/**
	 * Construct a new DataTypeArchiveChangeSet.
	 * @param addrMap the address map.
	 * @param numUndos the number of undo change sets to track.
	 */
	public DataTypeArchiveDBChangeSet(int numUndos) {
		this.numUndos = numUndos;
		changedDataTypeIds = new HashSet<Long>();
		changedCategoryIds = new HashSet<Long>();
		changedSourceArchiveIds = new HashSet<Long>();
		addedDataTypeIds = new HashSet<Long>();
		addedCategoryIds = new HashSet<Long>();
		addedSourceArchiveIds = new HashSet<Long>();
	}

	/**
	 * @see ghidra.program.model.listing.DataTypeChangeSet#dataTypeChanged(long)
	 */
	@Override
	public synchronized void dataTypeChanged(long id) {
		if (!inTransaction) {
			throw new IllegalStateException("Not in a transaction");
		}
		Long lid = new Long(id);
		if (!addedDataTypeIds.contains(lid) && !tmpAddedDataTypeIds.contains(lid)) {
			tmpChangedDataTypeIds.add(lid);
		}
	}

	/**
	 * @see ghidra.program.model.listing.DataTypeChangeSet#dataTypeAdded(long)
	 */
	@Override
	public synchronized void dataTypeAdded(long id) {
		if (!inTransaction) {
			throw new IllegalStateException("Not in a transaction");
		}
		tmpAddedDataTypeIds.add(new Long(id));
	}

	/**
	 * @see ghidra.program.model.listing.DataTypeChangeSet#getDataTypeChanges()
	 */
	@Override
	public synchronized long[] getDataTypeChanges() {
		return getLongs(changedDataTypeIds);
	}

	/**
	 * @see ghidra.program.model.listing.DataTypeChangeSet#getDataTypeAdditions()
	 */
	@Override
	public synchronized long[] getDataTypeAdditions() {
		return getLongs(addedDataTypeIds);
	}

	/**
	 * @see ghidra.program.model.listing.DataTypeChangeSet#categoryChanged(long)
	 */
	@Override
	public synchronized void categoryChanged(long id) {
		if (!inTransaction) {
			throw new IllegalStateException("Not in a transaction");
		}
		Long lid = new Long(id);
		if (!addedCategoryIds.contains(lid) && !tmpAddedCategoryIds.contains(lid)) {
			tmpChangedCategoryIds.add(lid);
		}
	}

	/**
	 * @see ghidra.program.model.listing.DataTypeChangeSet#categoryAdded(long)
	 */
	@Override
	public synchronized void categoryAdded(long id) {
		if (!inTransaction) {
			throw new IllegalStateException("Not in a transaction");
		}
		tmpAddedCategoryIds.add(new Long(id));
	}

	/**
	 * @see ghidra.program.model.listing.DataTypeChangeSet#getCategoryChanges()
	 */
	@Override
	public synchronized long[] getCategoryChanges() {
		return getLongs(changedCategoryIds);
	}

	/**
	 * @see ghidra.program.model.listing.DataTypeChangeSet#getCategoryAdditions()
	 */
	@Override
	public synchronized long[] getCategoryAdditions() {
		return getLongs(addedCategoryIds);
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.listing.DataTypeChangeSet#archiveAdded(long)
	 */
	@Override
	public void sourceArchiveAdded(long id) {
		if (!inTransaction) {
			throw new IllegalStateException("Not in a transaction");
		}
		tmpAddedSourceArchiveIds.add(new Long(id));
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.listing.DataTypeChangeSet#archiveChanged(long)
	 */
	@Override
	public void sourceArchiveChanged(long id) {
		if (!inTransaction) {
			throw new IllegalStateException("Not in a transaction");
		}
		Long lid = new Long(id);
		if (!addedSourceArchiveIds.contains(lid) && !tmpAddedSourceArchiveIds.contains(lid)) {
			tmpChangedSourceArchiveIds.add(lid);
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.listing.DataTypeChangeSet#getArchiveAdditions()
	 */
	@Override
	public long[] getSourceArchiveAdditions() {
		return getLongs(addedSourceArchiveIds);
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.listing.DataTypeChangeSet#getArchiveChanges()
	 */
	@Override
	public long[] getSourceArchiveChanges() {
		return getLongs(changedSourceArchiveIds);
	}

	@Override
	public synchronized void clearUndo(boolean isCheckedOut) {
		if (inTransaction) {
			throw new IllegalStateException("Cannot clear in a transaction");
		}
		if (!isCheckedOut) {
			changedCategoryIds.clear();
			changedDataTypeIds.clear();
			changedSourceArchiveIds.clear();
			addedCategoryIds.clear();
			addedDataTypeIds.clear();
			addedSourceArchiveIds.clear();
		}
		clearUndo();
	}

	/**
	 * @see ghidra.framework.data.DomainObjectDBChangeSet#startTransaction()
	 */
	@Override
	public synchronized void startTransaction() {
		redoList.clear();
		inTransaction = true;

		tmpChangedDataTypeIds = new HashSet<Long>();
		tmpChangedCategoryIds = new HashSet<Long>();
		tmpChangedSourceArchiveIds = new HashSet<Long>();
		tmpAddedDataTypeIds = new HashSet<Long>();
		tmpAddedCategoryIds = new HashSet<Long>();
		tmpAddedSourceArchiveIds = new HashSet<Long>();
	}

	/**
	 * @see ghidra.framework.data.DomainObjectDBChangeSet#endTransaction(boolean)
	 */
	@Override
	public synchronized void endTransaction(boolean commit) {
		if (!inTransaction) {
			return;
		}
		inTransaction = false;
		if (commit) {
			tmpChangedDataTypeIds.removeAll(changedDataTypeIds);
			tmpChangedCategoryIds.removeAll(changedCategoryIds);
			tmpChangedSourceArchiveIds.removeAll(changedSourceArchiveIds);

			changedDataTypeIds.addAll(tmpChangedDataTypeIds);
			changedCategoryIds.addAll(tmpChangedCategoryIds);
			changedSourceArchiveIds.addAll(tmpChangedSourceArchiveIds);
			addedDataTypeIds.addAll(tmpAddedDataTypeIds);
			addedCategoryIds.addAll(tmpAddedCategoryIds);
			addedSourceArchiveIds.addAll(tmpAddedSourceArchiveIds);

			undoList.addLast(new MyChangeDiff(tmpChangedDataTypeIds, tmpChangedCategoryIds,
				tmpChangedSourceArchiveIds, tmpAddedDataTypeIds, tmpAddedCategoryIds,
				tmpAddedSourceArchiveIds));

			if (undoList.size() > numUndos) {
				undoList.removeFirst();
			}
		}

		tmpChangedDataTypeIds = null;
		tmpChangedCategoryIds = null;
		tmpChangedSourceArchiveIds = null;
		tmpAddedDataTypeIds = null;
		tmpAddedCategoryIds = null;
		tmpAddedSourceArchiveIds = null;

	}

	/**
	 * @see ghidra.framework.data.DomainObjectDBChangeSet#undo()
	 */
	@Override
	public synchronized void undo() {
		MyChangeDiff diff = undoList.removeLast();
		changedDataTypeIds.removeAll(diff.changedDts);
		changedCategoryIds.removeAll(diff.changedCats);
		changedSourceArchiveIds.removeAll(diff.changedArchives);
		addedDataTypeIds.removeAll(diff.addedDts);
		addedCategoryIds.removeAll(diff.addedCats);
		addedSourceArchiveIds.removeAll(diff.addedArchives);
		redoList.addLast(diff);
	}

	/**
	 * @see ghidra.framework.data.DomainObjectDBChangeSet#redo()
	 */
	@Override
	public synchronized void redo() {
		MyChangeDiff diff = redoList.removeLast();
		changedDataTypeIds.addAll(diff.changedDts);
		changedCategoryIds.addAll(diff.changedCats);
		changedSourceArchiveIds.addAll(diff.changedArchives);
		addedDataTypeIds.addAll(diff.addedDts);
		addedCategoryIds.addAll(diff.addedCats);
		addedSourceArchiveIds.addAll(diff.addedArchives);
		undoList.addLast(diff);
	}

	/**
	 * @see ghidra.framework.model.ChangeSet#clearUndo()
	 */
	@Override
	public synchronized void clearUndo() {
		undoList.clear();
		redoList.clear();
	}

	/**
	 * @see ghidra.framework.data.DomainObjectDBChangeSet#setMaxUndos(int)
	 */
	@Override
	public synchronized void setMaxUndos(int numUndos) {
		this.numUndos = numUndos;
	}

	/**
	 * @see ghidra.framework.model.ChangeSet#read(ghidra.framework.store.db.DBHandle)
	 */
	@Override
	public synchronized void read(DBHandle dbh) throws IOException {

		startTransaction();
		boolean success = false;
		try {

			readIdRecords(dbh, DATATYPE_ADDITIONS, tmpAddedDataTypeIds);
			readIdRecords(dbh, DATATYPE_CHANGES, tmpChangedDataTypeIds);
			readIdRecords(dbh, CATEGORY_ADDITIONS, tmpAddedCategoryIds);
			readIdRecords(dbh, CATEGORY_CHANGES, tmpChangedCategoryIds);
			readIdRecords(dbh, SOURCE_ARCHIVE_ADDITIONS, tmpAddedSourceArchiveIds);
			readIdRecords(dbh, SOURCE_ARCHIVE_CHANGES, tmpChangedSourceArchiveIds);

			success = true;
		}
		finally {
			endTransaction(success);
			clearUndo();
		}
	}

	private void readIdRecords(DBHandle dbh, String tableName, Set<Long> ids) throws IOException {
		Table table = dbh.getTable(tableName);
		if (table != null) {
			RecordIterator it = table.iterator();
			while (it.hasNext()) {
				Record rec = it.next();
				ids.add(rec.getLongValue(0));
			}
		}
	}

	/**
	 * @see ghidra.framework.model.ChangeSet#write(ghidra.framework.store.db.DBHandle)
	 */
	@Override
	public synchronized void write(DBHandle dbh, boolean isRecoverySave) throws IOException {

		long txId = dbh.startTransaction();
		boolean success = false;
		try {

			writeIdRecords(dbh, DATATYPE_ADDITIONS, addedDataTypeIds);
			writeIdRecords(dbh, DATATYPE_CHANGES, changedDataTypeIds);
			writeIdRecords(dbh, CATEGORY_ADDITIONS, addedCategoryIds);
			writeIdRecords(dbh, CATEGORY_CHANGES, changedCategoryIds);
			writeIdRecords(dbh, SOURCE_ARCHIVE_ADDITIONS, addedSourceArchiveIds);
			writeIdRecords(dbh, SOURCE_ARCHIVE_CHANGES, changedSourceArchiveIds);

			success = true;
		}
		finally {
			dbh.endTransaction(txId, success);
		}
	}

	private void writeIdRecords(DBHandle dbh, String tableName, Set<Long> ids) throws IOException {
		if (ids.size() > 0) {
			Table table = dbh.createTable(tableName, STORED_ID_SCHEMA);
			Record rec = STORED_ID_SCHEMA.createRecord(0);
			int key = 1;
			for (long id : ids) {
				rec.setKey(key++);
				rec.setLongValue(0, id);
				table.putRecord(rec);
			}
		}
	}

	private long[] getLongs(HashSet<Long> set) {
		long[] result = new long[set.size()];
		Iterator<Long> it = set.iterator();
		int i = 0;
		while (it.hasNext()) {
			result[i++] = it.next().longValue();
		}
		return result;
	}

	@Override
	public boolean hasChanges() {
		if (changedDataTypeIds.isEmpty() && changedCategoryIds.isEmpty() &&
			changedSourceArchiveIds.isEmpty() && addedDataTypeIds.isEmpty() &&
			addedCategoryIds.isEmpty() && addedSourceArchiveIds.isEmpty()) {
			return false;
		}
		return true;
	}

}

class MyChangeDiff {
	NormalizedAddressSet set;
	NormalizedAddressSet regSet;
	HashSet<Long> changedDts;
	HashSet<Long> changedCats;
	HashSet<Long> changedPts;
	HashSet<Long> changedSyms;
	HashSet<Long> changedArchives;
	HashSet<Long> addedDts;
	HashSet<Long> addedCats;
	HashSet<Long> addedPts;
	HashSet<Long> addedSyms;
	HashSet<Long> addedArchives;

	MyChangeDiff(HashSet<Long> changedDts, HashSet<Long> changedCats, HashSet<Long> changedArchives,
			HashSet<Long> addedDts, HashSet<Long> addedCats, HashSet<Long> addedArchives) {
		this.changedDts = changedDts;
		this.changedCats = changedCats;
		this.changedArchives = changedArchives;
		this.addedDts = addedDts;
		this.addedCats = addedCats;
		this.addedArchives = addedArchives;
	}
}
