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

import org.apache.commons.lang3.StringUtils;

import db.*;
import ghidra.program.database.map.AddressMap;
import ghidra.util.exception.VersionException;

/**
 * SymbolDatabaseAdapter for version 3
 * 
 * This version provides for fast symbol lookup by namespace and name and introduced the use of 
 * sparse table columns for storing optional symbol data (hash, primary, datatype-ID, variable-offset).
 * It was created in June 2021 with ProgramDB version 24. 
 * It was first in affect within Ghidra starting at version 10.1
 */
class SymbolDatabaseAdapterV3 extends PreV6SymbolDatabaseAdapter implements RecordTranslator {

	static final int VERSION = 3;

	// NOTE: the primary field duplicates the symbol's address when the symbol is primary. This
	// allows us to index this field and quickly find the primary symbols. The field is sparse
	// so that non-primary symbols don't consume any space for this field.

/* Do not remove the following commented out schema! It shows the version 3 symbol table schema. */
//	static final Schema V3_SYMBOL_SCHEMA = new Schema(SYMBOL_VERSION, "Key",
//		new Field[] { StringField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE,
//			ByteField.INSTANCE, StringField.INSTANCE, ByteField.INSTANCE, LongField.INSTANCE,
//			LongField.INSTANCE, LongField.INSTANCE, IntField.INSTANCE },
//		new String[] { "Name", "Address", "Namespace", "Symbol Type", "String Data", "Flags",
//			"Locator Hash", "Primary", "Datatype", "Variable Offset" },
//		new int[] { SYMBOL_HASH_COL, SYMBOL_PRIMARY_COL, SYMBOL_DATATYPE_COL,
//			SYMBOL_VAROFFSET_COL });

	private static final int V3_SYMBOL_NAME_COL = 0;
	private static final int V3_SYMBOL_ADDR_COL = 1;
	private static final int V3_SYMBOL_PARENT_ID_COL = 2;
	private static final int V3_SYMBOL_TYPE_COL = 3;
	private static final int V3_SYMBOL_STRING_DATA_COL = 4; // removed with V4; External [address][,importName]
	private static final int V3_SYMBOL_FLAGS_COL = 5;

	// sparse fields - the following fields are not always applicable so they are optional and 
	// don't consume space in the database if they aren't used.
	private static final int V3_SYMBOL_HASH_COL = 6;
	private static final int V3_SYMBOL_PRIMARY_COL = 7;
	private static final int V3_SYMBOL_DATATYPE_COL = 8; // External and variable symbol use
	private static final int V3_SYMBOL_VAROFFSET_COL = 9;

	private Table symbolTable;

	SymbolDatabaseAdapterV3(DBHandle handle, AddressMap addrMap) throws VersionException {

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
	 * Returns a record matching the current database schema from the version 3 record.
	 * @param record the record matching the version 3 schema.
	 * @return a current symbol record.
	 */
	@Override
	public DBRecord translateRecord(DBRecord record) {
		if (record == null) {
			return null;
		}
		DBRecord rec = SymbolDatabaseAdapter.SYMBOL_SCHEMA.createRecord(record.getKey());

		String symbolName = record.getString(V3_SYMBOL_NAME_COL);
		rec.setString(SymbolDatabaseAdapter.SYMBOL_NAME_COL, symbolName);

		long symbolAddrKey = record.getLongValue(V3_SYMBOL_ADDR_COL);
		rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_ADDR_COL, symbolAddrKey);

		long namespaceId = record.getLongValue(V3_SYMBOL_PARENT_ID_COL);
		rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_PARENT_ID_COL, namespaceId);

		byte symbolTypeId = record.getByteValue(V3_SYMBOL_TYPE_COL);
		rec.setByteValue(SymbolDatabaseAdapter.SYMBOL_TYPE_COL, symbolTypeId);

		rec.setByteValue(SymbolDatabaseAdapter.SYMBOL_FLAGS_COL,
			record.getByteValue(V3_SYMBOL_FLAGS_COL));

		//
		// Convert sparse columns
		//

		convertSymbolStringData(symbolTypeId, rec, record.getString(V3_SYMBOL_STRING_DATA_COL));

		Field hash = record.getFieldValue(V3_SYMBOL_HASH_COL);
		if (hash != null) {
			rec.setField(SymbolDatabaseAdapter.SYMBOL_HASH_COL, hash);
		}

		Field primaryAddr = record.getFieldValue(V3_SYMBOL_PRIMARY_COL);
		if (primaryAddr != null) {
			rec.setField(SymbolDatabaseAdapter.SYMBOL_PRIMARY_COL, primaryAddr);
		}

		Field dataTypeId = record.getFieldValue(V3_SYMBOL_DATATYPE_COL);
		if (dataTypeId != null) {
			rec.setField(SymbolDatabaseAdapter.SYMBOL_DATATYPE_COL, dataTypeId);
		}

		Field varOffset = record.getFieldValue(V3_SYMBOL_VAROFFSET_COL);
		if (varOffset != null) {
			rec.setField(SymbolDatabaseAdapter.SYMBOL_VAROFFSET_COL, varOffset);
		}

		return rec;
	}

	@Override
	protected int getVersion() {
		return VERSION;
	}

	static void convertSymbolStringData(byte symbolTypeId, DBRecord record, String str) {

		// Adhoc String field use/format
		//   External location (label or function):  "[<addressStr>][,<originalImportedName>]"
		//   Library: [externalLibraryPath]
		//   Variables: [comment]

		if (StringUtils.isBlank(str)) {
			return;
		}

		if (symbolTypeId == SYMBOL_TYPE_LABEL || symbolTypeId == SYMBOL_TYPE_FUNCTION) {
			int indexOf = str.indexOf(",");
			String originalImportedName = indexOf >= 0 ? str.substring(indexOf + 1) : null;
			String addressString = indexOf >= 0 ? str.substring(0, indexOf) : str;
			record.setString(SYMBOL_EXTERNAL_PROG_ADDR_COL, addressString);
			record.setString(SYMBOL_ORIGINAL_IMPORTED_NAME_COL, originalImportedName);
		}
		else if (symbolTypeId == SYMBOL_TYPE_LOCAL_VAR || symbolTypeId == SYMBOL_TYPE_PARAMETER) {
			record.setString(SYMBOL_COMMENT_COL, str);
		}
		else if (symbolTypeId == SYMBOL_TYPE_LIBRARY) {
			record.setString(SYMBOL_LIBPATH_COL, str);
		}
	}

	@Override
	int getSymbolCount() {
		return symbolTable.getRecordCount();
	}
}
