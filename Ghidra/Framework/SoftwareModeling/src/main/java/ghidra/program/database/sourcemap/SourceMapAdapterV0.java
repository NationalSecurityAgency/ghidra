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
package ghidra.program.database.sourcemap;

import java.io.IOException;

import db.*;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.map.AddressIndexPrimaryKeyIterator;
import ghidra.program.database.map.AddressMapDB;
import ghidra.program.database.util.DatabaseTableUtils;
import ghidra.program.database.util.EmptyRecordIterator;
import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Initial version of {@link SourceMapAdapter}
 */
class SourceMapAdapterV0 extends SourceMapAdapter implements DBListener {

	final static int SCHEMA_VERSION = 0;
	static final int V0_FILE_LINE_COL = 0;  // indexed
	static final int V0_BASE_ADDR_COL = 1;  // indexed
	static final int V0_LENGTH_COL = 2;

	//  key | ((32-bit source file id << 32) | 32-bit line number) | base addr | length
	private final static Schema V0_SCHEMA = new Schema(SCHEMA_VERSION, "ID",
		new Field[] { LongField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE },
		new String[] { "fileAndLine", "baseAddress", "length" }, null);

	private static final int[] INDEXED_COLUMNS = new int[] { V0_FILE_LINE_COL, V0_BASE_ADDR_COL };

	private Table table; // lazy creation, null if empty
	private final DBHandle dbHandle;
	private AddressMapDB addrMap;

	/**
	 * Creates an adapter for version 0 of the source map adapter
	 * @param dbh database handle
	 * @param addrMap address map
	 * @param openMode open mode
	 * @throws VersionException if version incompatible
	 */
	SourceMapAdapterV0(DBHandle dbh, AddressMapDB addrMap, OpenMode openMode)
			throws VersionException {
		this.dbHandle = dbh;
		this.addrMap = addrMap;

		// As in FunctionTagAdapterV0, we need to add this as a database listener.
		// Since the table is created lazily, undoing a transaction which (for example) caused
		// the table to be created can leave the table in a bad state. 
		// The implementation of dbRestored(DBHandle) solves this issue.  
		this.dbHandle.addListener(this);

		if (!openMode.equals(OpenMode.CREATE)) {
			table = dbHandle.getTable(TABLE_NAME);
			if (table == null) {
				return; // perform lazy table creation
			}
			int version = table.getSchema().getVersion();
			if (version != SCHEMA_VERSION) {
				throw new VersionException(VersionException.NEWER_VERSION, false);
			}
		}
	}

	@Override
	public void dbRestored(DBHandle dbh) {
		table = dbh.getTable(TABLE_NAME);
	}

	@Override
	public void dbClosed(DBHandle dbh) {
		// nothing to do
	}

	@Override
	public void tableDeleted(DBHandle dbh, Table t) {
		// nothing to do
	}

	@Override
	public void tableAdded(DBHandle dbh, Table t) {
		// nothing to do
	}

	@Override
	boolean removeRecord(long key) throws IOException {
		if (table != null) {
			return table.deleteRecord(key);
		}
		return false;
	}

	@Override
	RecordIterator getSourceMapRecordIterator(Address addr, boolean before) throws IOException {
		if (table == null || addr == null) {
			return EmptyRecordIterator.INSTANCE;
		}
		AddressIndexPrimaryKeyIterator keyIter =
			new AddressIndexPrimaryKeyIterator(table, V0_BASE_ADDR_COL, addrMap, addr, before);
		return new KeyToRecordIterator(table, keyIter);
	}

	@Override
	RecordIterator getRecordsForSourceFile(long fileId, int minLine, int maxLine)
			throws IOException {
		if (table == null) {
			return EmptyRecordIterator.INSTANCE;
		}
		fileId = fileId << 32;
		LongField minField = new LongField(fileId | minLine);
		LongField maxField = new LongField(fileId | maxLine);
		return table.indexIterator(V0_FILE_LINE_COL, minField, maxField, true);
	}

	@Override
	DBRecord addMapEntry(long fileId, int lineNum, Address baseAddr, long length)
			throws IOException {
		DBRecord rec = V0_SCHEMA.createRecord(getTable().getKey());
		rec.setLongValue(V0_FILE_LINE_COL, (fileId << 32) | lineNum);
		rec.setLongValue(V0_BASE_ADDR_COL, addrMap.getKey(baseAddr, true));
		rec.setLongValue(V0_LENGTH_COL, length);
		table.putRecord(rec);
		return rec;
	}

	@Override
	void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException, IOException {
		if (table == null) {
			return;
		}
		DatabaseTableUtils.updateIndexedAddressField(table, V0_BASE_ADDR_COL, addrMap, fromAddr,
			toAddr, length, null, monitor);
	}

	private Table getTable() throws IOException {
		if (table == null) {
			table = dbHandle.createTable(TABLE_NAME, V0_SCHEMA, INDEXED_COLUMNS);
		}
		return table;
	}

}
