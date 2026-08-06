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
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.VersionException;

/**
 * SymbolDatabaseAdapter for version 1
 */
class SymbolDatabaseAdapterV1 extends PreV6SymbolDatabaseAdapter implements RecordTranslator {

/* Do not remove the following commented out schema! It shows the version 1 symbol table schema. */
//	static final Schema SYMBOL_SCHEMA = new Schema(1, "Key", 
//			new Class[] {StringField.class,
//				LongField.class, LongField.class, ByteField.class,
//				LongField.class, IntField.class, StringField.class},
//			new String[] {"Name", "Address", "Parent", "Symbol Type",
//						  "SymbolData1", "SymbolData2", "Comment"});

	private static final int VERSION = 1;

	private static final int V1_SYMBOL_NAME_COL = 0;
	private static final int V1_SYMBOL_ADDR_COL = 1;
	private static final int V1_SYMBOL_PARENT_COL = 2;
	private static final int V1_SYMBOL_TYPE_COL = 3;
	private static final int V1_SYMBOL_DATA1_COL = 4; // Long data (variable dataTypeId) 
	private static final int V1_SYMBOL_DATA2_COL = 5; // Int data (primary flag, variable-offset)
	private static final int V1_SYMBOL_COMMENT_COL = 6;

	private Table symbolTable;
	private AddressMap addrMap;

	SymbolDatabaseAdapterV1(DBHandle handle, AddressMap addrMap) throws VersionException {

		this.addrMap = addrMap;
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
	public DBRecord translateRecord(DBRecord record) {
		if (record == null) {
			return null;
		}
		DBRecord rec = SymbolDatabaseAdapter.SYMBOL_SCHEMA.createRecord(record.getKey());
		String symbolName = record.getString(V1_SYMBOL_NAME_COL);
		rec.setString(SymbolDatabaseAdapter.SYMBOL_NAME_COL, symbolName);

		long symbolAddrKey = record.getLongValue(V1_SYMBOL_ADDR_COL);
		rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_ADDR_COL, symbolAddrKey);

		long namespaceId = record.getLongValue(V1_SYMBOL_PARENT_COL);
		rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_PARENT_ID_COL, namespaceId);

		byte symbolTypeId = record.getByteValue(V1_SYMBOL_TYPE_COL);
		rec.setByteValue(SymbolDatabaseAdapter.SYMBOL_TYPE_COL, symbolTypeId);

		SourceType source = SourceType.USER_DEFINED;
		if (symbolTypeId == SymbolType.FUNCTION.getID()) {
			Address symbolAddress = addrMap.decodeAddress(symbolAddrKey);
			String defaultName = SymbolUtilities.getDefaultFunctionName(symbolAddress);
			if (symbolName.equals(defaultName)) {
				source = SourceType.DEFAULT;
			}
		}
		rec.setByteValue(SymbolDatabaseAdapter.SYMBOL_FLAGS_COL, (byte) source.ordinal());

		//
		// Convert sparse columns
		//

		SymbolDatabaseAdapterV3.convertSymbolStringData(symbolTypeId, rec,
			record.getString(V1_SYMBOL_COMMENT_COL));

		long dataTypeId = record.getLongValue(V1_SYMBOL_DATA1_COL);
		if (dataTypeId != -1) {
			rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_DATATYPE_COL, dataTypeId);
		}

		SymbolType type = SymbolType.getSymbolType(symbolTypeId);
		int data2 = record.getIntValue(V1_SYMBOL_DATA2_COL);
		// The data1 field was used in two ways for label symbols, it stored a 1 for primary and 0
		// for non-primary.  If the type was a parameter or variable, it stored the ordinal or
		// first use offset respectively. 
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

		Field hash = computeLocatorHash(symbolName, namespaceId, symbolAddrKey);
		rec.setField(SymbolDatabaseAdapter.SYMBOL_HASH_COL, hash);

		return rec;
	}

	@Override
	RecordIterator getSymbols() throws IOException {
		RecordIterator it = symbolTable.iterator();
		return new TranslatedRecordIterator(it, this);
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
