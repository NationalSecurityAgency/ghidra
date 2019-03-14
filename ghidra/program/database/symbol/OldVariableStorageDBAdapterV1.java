/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.database.symbol;

import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

import db.*;

public class OldVariableStorageDBAdapterV1 extends OldVariableStorageDBAdapter {

	private static final int TABLE_VERSION = 1;
	private Table variableStorageTable;

	OldVariableStorageDBAdapterV1(DBHandle handle, boolean create) throws VersionException,
			IOException {

		if (create) {
			variableStorageTable =
				handle.createTable(VARIABLE_STORAGE_TABLE_NAME, VARIABLE_STORAGE_SCHEMA,
					new int[] { NAMESPACE_ID_COL });
		}
		else {
			variableStorageTable = handle.getTable(VARIABLE_STORAGE_TABLE_NAME);
			if (variableStorageTable == null) {
				throw new VersionException(VersionException.OLDER_VERSION, true);
			}
			int version = variableStorageTable.getSchema().getVersion();
			if (version < TABLE_VERSION) {
				throw new VersionException(VersionException.OLDER_VERSION, true);
			}
			if (version > TABLE_VERSION) {
				throw new VersionException(VersionException.NEWER_VERSION, false);
			}
		}
	}

	/**
	 * @see ghidra.program.database.symbol.VariableStorageDBAdapter#getNextStorageID()
	 */
	@Override
	long getNextStorageID() {
		long nextKey = variableStorageTable.getMaxKey() + 1;
		if (nextKey <= 0) {
			nextKey = 1;
		}
		return nextKey;
	}

	/**
	 * @see ghidra.program.database.symbol.VariableStorageDBAdapter#deleteRecord(long)
	 */
	@Override
	void deleteRecord(long key) throws IOException {
		variableStorageTable.deleteRecord(key);
	}

	/**
	 * @see ghidra.program.database.symbol.VariableStorageDBAdapter#getRecord(long)
	 */
	@Override
	Record getRecord(long key) throws IOException {
		return variableStorageTable.getRecord(key);
	}

	/**
	 * @see ghidra.program.database.symbol.VariableStorageDBAdapter#getRecordsForNamespace(long)
	 */
	@Override
	Record[] getRecordsForNamespace(long namespaceID) throws IOException {
		long[] keys =
			variableStorageTable.findRecords(new LongField(namespaceID), NAMESPACE_ID_COL);
		Record[] records = new Record[keys.length];
		for (int i = 0; i < keys.length; i++) {
			records[i] = variableStorageTable.getRecord(keys[i]);
		}
		return records;
	}

	/**
	 * @see ghidra.program.database.symbol.VariableStorageDBAdapter#updateRecord(db.Record)
	 */
	@Override
	void updateRecord(Record record) throws IOException {
		variableStorageTable.putRecord(record);
	}

	/**
	 * @throws IOException 
	 * @see ghidra.program.database.symbol.VariableStorageDBAdapter#getRecords()
	 */
	@Override
	RecordIterator getRecords() throws IOException {
		return variableStorageTable.iterator();
	}

	/**
	 * @see ghidra.program.database.symbol.VariableStorageDBAdapter#getRecordCount()
	 */
	@Override
	int getRecordCount() {
		return variableStorageTable.getRecordCount();
	}

	public static OldVariableStorageDBAdapter upgrade(DBHandle dbHandle,
			OldVariableStorageDBAdapter oldAdapter, TaskMonitor monitor) throws IOException,
			CancelledException {
		DBHandle tmpHandle = dbHandle.getScratchPad();
		try {

			monitor.setMessage("Upgrading Variable Storage Table...");
			monitor.setMaximum((oldAdapter.getRecordCount()) * 2);
			int count = 0;

			OldVariableStorageDBAdapterV1 tmpAdapter =
				new OldVariableStorageDBAdapterV1(tmpHandle, true);
			RecordIterator iter = oldAdapter.getRecords();
			while (iter.hasNext()) {
				monitor.checkCanceled();
				Record rec = iter.next();
				Record newRec = VARIABLE_STORAGE_SCHEMA.createRecord(rec.getKey());
				newRec.setLongValue(STORAGE_ADDR_COL, rec.getLongValue(STORAGE_ADDR_COL));
				newRec.setLongValue(NAMESPACE_ID_COL, rec.getLongValue(NAMESPACE_ID_COL));
				newRec.setIntValue(SYMBOL_COUNT_COL, rec.getIntValue(SYMBOL_COUNT_COL));
				tmpAdapter.updateRecord(newRec);
				monitor.setProgress(++count);
			}

			dbHandle.deleteTable(VARIABLE_STORAGE_TABLE_NAME);
			OldVariableStorageDBAdapterV1 newAdapter =
				new OldVariableStorageDBAdapterV1(dbHandle, true);

			iter = tmpAdapter.getRecords();
			while (iter.hasNext()) {
				monitor.checkCanceled();
				newAdapter.updateRecord(iter.next());
				monitor.setProgress(++count);
			}
			return newAdapter;
		}
		catch (VersionException e) {
			throw new AssertException();
		}
		finally {
			tmpHandle.deleteTable(VARIABLE_STORAGE_TABLE_NAME);
		}
	}

}
