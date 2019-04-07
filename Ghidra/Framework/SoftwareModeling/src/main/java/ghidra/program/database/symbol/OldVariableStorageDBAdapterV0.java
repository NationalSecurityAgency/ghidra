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

import ghidra.util.exception.VersionException;

import java.io.IOException;

import db.*;

public class OldVariableStorageDBAdapterV0 extends OldVariableStorageDBAdapter {

	private static final int TABLE_VERSION = 0;
	private Table variableStorageTable;

	OldVariableStorageDBAdapterV0(DBHandle handle) throws VersionException {
		variableStorageTable = handle.getTable(VARIABLE_STORAGE_TABLE_NAME);
		if (variableStorageTable == null ||
			variableStorageTable.getSchema().getVersion() != TABLE_VERSION) {
			throw new VersionException();
		}
	}

	/**
	 * @see ghidra.program.database.symbol.VariableStorageDBAdapter#getNextStorageID()
	 */
	@Override
	long getNextStorageID() {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.symbol.VariableStorageDBAdapter#deleteRecord(long)
	 */
	@Override
	void deleteRecord(long key) throws IOException {
		throw new UnsupportedOperationException();
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
		throw new UnsupportedOperationException();
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

}
