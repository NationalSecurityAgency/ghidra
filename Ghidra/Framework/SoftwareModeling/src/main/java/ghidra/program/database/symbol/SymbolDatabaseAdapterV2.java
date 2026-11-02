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
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.VersionException;

/**
 * SymbolDatabaseAdapter for version 2
 */
class SymbolDatabaseAdapterV2 extends PreV6SymbolDatabaseAdapter implements RecordTranslator {

/* Do not remove the following commented out schema! It shows the version 2 symbol table schema. */
//	static final Schema SYMBOL_SCHEMA = new Schema(2, "Key",
//		new Field[] { StringField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE,
//			ByteField.INSTANCE, LongField.INSTANCE, IntField.INSTANCE, StringField.INSTANCE,
//			ByteField.INSTANCE },
//		new String[] { "Name", "Address", "Parent", "Symbol Type", "SymbolData1", "SymbolData2",
//			"SymbolData3", "Flags" });

	private static final int VERSION = 2;

	private static final int V2_SYMBOL_NAME_COL = 0;
	private static final int V2_SYMBOL_ADDR_COL = 1;
	private static final int V2_SYMBOL_PARENT_ID_COL = 2;
	private static final int V2_SYMBOL_TYPE_COL = 3;
	private static final int V2_SYMBOL_DATA1_COL = 4; // Long data (variable dataTypeId)
	private static final int V2_SYMBOL_DATA2_COL = 5; // Int data (primary flag, variable-offset)
	private static final int V2_SYMBOL_DATA3_COL = 6; // String data (external address)
	private static final int V2_SYMBOL_FLAGS_COL = 7;

	private Table symbolTable;

	SymbolDatabaseAdapterV2(DBHandle handle, AddressMap addrMap) throws VersionException {

		symbolTable = handle.getTable(SYMBOL_TABLE_NAME);
		if (symbolTable == null) {
			throw new VersionException("Missing Table: " + SYMBOL_TABLE_NAME);
		}
		if (symbolTable.getSchema().getVersion() != VERSION) {
			int version = symbolTable.getSchema().getVersion();
			if (version < VERSION) {
				throw new VersionException(true);
			}
			throw new VersionException(VersionException.NEWER_VERSION, false);
		}
	}

	@Override
	RecordIterator getSymbols() throws IOException {
		RecordIterator it = symbolTable.iterator();
		return new TranslatedRecordIterator(it, this);

	}

	/**
	 * Returns a record matching the current database schema from the version 2 record.
	 * @param record the record matching the version 2 schema.
	 * @return a current symbol record.
	 */
	@Override
	public DBRecord translateRecord(DBRecord record) {
		if (record == null) {
			return null;
		}
		DBRecord rec = SymbolDatabaseAdapter.SYMBOL_SCHEMA.createRecord(record.getKey());

		String symbolName = record.getString(V2_SYMBOL_NAME_COL);
		rec.setString(SymbolDatabaseAdapter.SYMBOL_NAME_COL, symbolName);

		long symbolAddrKey = record.getLongValue(V2_SYMBOL_ADDR_COL);
		rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_ADDR_COL, symbolAddrKey);

		long namespaceId = record.getLongValue(V2_SYMBOL_PARENT_ID_COL);
		rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_PARENT_ID_COL, namespaceId);

		byte symbolTypeId = record.getByteValue(V2_SYMBOL_TYPE_COL);
		rec.setByteValue(SymbolDatabaseAdapter.SYMBOL_TYPE_COL, symbolTypeId);

		rec.setByteValue(SymbolDatabaseAdapter.SYMBOL_FLAGS_COL,
			record.getByteValue(V2_SYMBOL_FLAGS_COL));

		//
		// Convert sparse columns
		//

		SymbolDatabaseAdapterV3.convertSymbolStringData(symbolTypeId, rec,
			record.getString(V2_SYMBOL_DATA3_COL));

		Field hash = computeLocatorHash(symbolName, namespaceId, symbolAddrKey);
		rec.setField(SymbolDatabaseAdapter.SYMBOL_HASH_COL, hash);

		long dataTypeId = record.getLongValue(V2_SYMBOL_DATA1_COL);
		if (dataTypeId != -1) {
			rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_DATATYPE_COL, dataTypeId);
		}

		SymbolType type = SymbolType.getSymbolType(symbolTypeId);
		int data2 = record.getIntValue(V2_SYMBOL_DATA2_COL);
		// The data2 field was used in two ways for label symbols, it stored a 1 for primary and 0
		// for non-primary.  If the type was a parameter or variable, it stored the ordinal or
		// first use offset respectively
		if (SymbolType.LABEL.equals(type)) {
			if (data2 == 1) { // if it was primary, put the address in the indexed primary col
				rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_PRIMARY_COL, symbolAddrKey);
			}
		}
		else if (SymbolType.PARAMETER.equals(type) || SymbolType.LOCAL_VAR.equals(type)) {
			rec.setIntValue(SymbolDatabaseAdapter.SYMBOL_VAROFFSET_COL, data2);
		}

		// also need to store primary for functions
		if (SymbolType.FUNCTION.equals(type)) {
			rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_PRIMARY_COL, symbolAddrKey);
		}

		return rec;
	}

	@Override
	protected int getVersion() {
		return VERSION;
	}

	@Override
	int getSymbolCount() {
		return symbolTable.getRecordCount();
	}
}
