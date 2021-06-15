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

/**
 * <code>OldVariableStorageDBAdapterV0V1</code> provide legacy variable storage 
 * table support where each variable storage record was namespace-specific and
 * provided storage address only.  In a later revision this was deemed inadequate 
 * since size information and support for storage binding was needed.
 */
class OldVariableStorageDBAdapterV0V1 {

	static final String VARIABLE_STORAGE_TABLE_NAME = "VariableStorage";

	static final Schema VARIABLE_STORAGE_SCHEMA = new Schema(1, "Key",
		new Field[] { LongField.INSTANCE, LongField.INSTANCE, IntField.INSTANCE },
		new String[] { "Address", "NamespaceID", "SymCount" });

	static final int STORAGE_ADDR_COL = 0;
	static final int NAMESPACE_ID_COL = 1;
	static final int SYMBOL_COUNT_COL = 2;

	private Table variableStorageTable;

	/**
	 * Construction legacy variable storage adapter.  The old variable storage 
	 * table must exist (see {@link #VARIABLE_STORAGE_TABLE_NAME}).
	 * @param handle database handle
	 * @throws IOException if VariableStorage table is missing or invalid schema version detected
	 */
	OldVariableStorageDBAdapterV0V1(DBHandle handle) throws IOException {

		variableStorageTable = handle.getTable(VARIABLE_STORAGE_TABLE_NAME);
		if (variableStorageTable == null) {
			throw new IOException("No such table: " + VARIABLE_STORAGE_TABLE_NAME);
		}
		int version = variableStorageTable.getSchema().getVersion();
		if (version != 0 && version != 1) {
			throw new IOException("No such table schema version: " + version);
		}
	}

	DBRecord getRecord(long key) throws IOException {
		return variableStorageTable.getRecord(key);
	}

	DBRecord[] getRecordsForNamespace(long namespaceID) throws IOException {
		Field[] keys =
			variableStorageTable.findRecords(new LongField(namespaceID), NAMESPACE_ID_COL);
		DBRecord[] records = new DBRecord[keys.length];
		for (int i = 0; i < keys.length; i++) {
			records[i] = variableStorageTable.getRecord(keys[i]);
		}
		return records;
	}

}
