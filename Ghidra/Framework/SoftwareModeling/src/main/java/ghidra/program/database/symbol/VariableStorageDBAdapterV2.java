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
package ghidra.program.database.symbol;

import java.io.IOException;

import db.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class VariableStorageDBAdapterV2 extends VariableStorageDBAdapter {

	private static final int TABLE_VERSION = 2;
	private Table variableStorageTable;

	VariableStorageDBAdapterV2(DBHandle handle, boolean create)
			throws VersionException, IOException {

		if (create) {
			variableStorageTable = handle.createTable(VARIABLE_STORAGE_TABLE_NAME,
				VARIABLE_STORAGE_SCHEMA, new int[] { HASH_COL });
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

	@Override
	long getNextStorageID() {
		long nextKey = variableStorageTable.getMaxKey() + 1;
		if (nextKey <= 0) {
			nextKey = 1;
		}
		return nextKey;
	}

	@Override
	long findRecordKey(long hash) throws IOException {
		Field[] recs = variableStorageTable.findRecords(new LongField(hash), HASH_COL);
		return recs.length == 0 ? -1 : recs[0].getLongValue();
	}

	@Override
	void deleteRecord(long key) throws IOException {
		variableStorageTable.deleteRecord(key);
	}

	@Override
	DBRecord getRecord(long key) throws IOException {
		return variableStorageTable.getRecord(key);
	}

	@Override
	void updateRecord(DBRecord record) throws IOException {
		variableStorageTable.putRecord(record);
	}

	@Override
	RecordIterator getRecords() throws IOException {
		return variableStorageTable.iterator();
	}

	@Override
	int getRecordCount() {
		return variableStorageTable.getRecordCount();
	}

	public static VariableStorageDBAdapter upgrade(DBHandle dbHandle,
			VariableStorageDBAdapter oldAdapter, TaskMonitor monitor) throws IOException {
		// Simple upgrade from no-table case
		try {
			return new VariableStorageDBAdapterV2(dbHandle, true);
		}
		catch (VersionException e) {
			throw new AssertException(e); // Unexpected on create
		}
	}

}
