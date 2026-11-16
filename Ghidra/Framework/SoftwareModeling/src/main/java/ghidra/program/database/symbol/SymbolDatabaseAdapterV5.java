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
import ghidra.util.exception.VersionException;

/**
 * SymbolDatabaseAdapter for version 5
 * 
 * This version added additional sparse columns to store optional data specific to certain
 * symbol types.  The adhoc string data column was eliminated.
 */
class SymbolDatabaseAdapterV5 extends PreV6SymbolDatabaseAdapter implements RecordTranslator {

	static final int VERSION = 5;

	static final int V5_SYMBOL_NAME_COL = 0;
	static final int V5_SYMBOL_ADDR_COL = 1;
	static final int V5_SYMBOL_PARENT_ID_COL = 2;
	static final int V5_SYMBOL_TYPE_COL = 3;
	static final int V5_SYMBOL_FLAGS_COL = 4;

	// Sparse fields - the following fields are not always applicable so they are optional and 
	// don't consume space in the database if they aren't used.
	static final int V5_SYMBOL_HASH_COL = 5;
	static final int V5_SYMBOL_PRIMARY_COL = 6;
	static final int V5_SYMBOL_DATATYPE_COL = 7;
	static final int V5_SYMBOL_VAROFFSET_COL = 8;
	static final int V5_SYMBOL_ORIGINAL_IMPORTED_NAME_COL = 9;
	static final int V5_SYMBOL_EXTERNAL_PROG_ADDR_COL = 10;
	static final int V5_SYMBOL_COMMENT_COL = 11;
	static final int V5_SYMBOL_LIBPATH_COL = 12;
	static final int V5_SYMBOL_LIB_ORDINAL_COL = 13;

	// NOTE: the primary field duplicates the symbol's address when the symbol is primary. This
	// allows us to index this field and quickly find the primary symbols. The field is sparse
	// so that non-primary symbols don't consume any space for this field.

// Do not remove the following commented out schema! It shows the version 4 symbol table schema. */
//	static final Schema V5_SYMBOL_SCHEMA = new Schema(SYMBOL_VERSION, "Key",
//		new Field[] { StringField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE,
//			ByteField.INSTANCE, ByteField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE,
//			LongField.INSTANCE, IntField.INSTANCE, StringField.INSTANCE, StringField.INSTANCE,
//			StringField.INSTANCE, StringField.INSTANCE, IntField.INSTANCE },
//		new String[] { "Name", "Address", "Namespace", "Symbol Type", "Flags", "Locator Hash",
//			"Primary", "Datatype", "Variable Offset", "ExtOrigImportName", "ExtProgAddr", "Comment",
//			"LibPath", "LibOrdinal" },
//		new int[] { V5_SYMBOL_HASH_COL, V5_SYMBOL_PRIMARY_COL, V5_SYMBOL_DATATYPE_COL,
//			V5_SYMBOL_VAROFFSET_COL, V5_SYMBOL_ORIGINAL_IMPORTED_NAME_COL,
//			V5_SYMBOL_EXTERNAL_PROG_ADDR_COL, V5_SYMBOL_COMMENT_COL, V5_SYMBOL_LIBPATH_COL,
//			V5_SYMBOL_LIB_ORDINAL_COL });

	private Table symbolTable;

	SymbolDatabaseAdapterV5(DBHandle handle, AddressMap addrMap)
			throws VersionException {

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
		return new TranslatedRecordIterator(symbolTable.iterator(), this);
	}

	@Override
	protected int getVersion() {
		return VERSION;
	}

	@Override
	public DBRecord translateRecord(DBRecord record) {
		if (record == null) {
			return null;
		}
		DBRecord rec = SymbolDatabaseAdapter.SYMBOL_SCHEMA.createRecord(record.getKey());

		String symbolName = record.getString(V5_SYMBOL_NAME_COL);
		rec.setString(SymbolDatabaseAdapter.SYMBOL_NAME_COL, symbolName);

		long symbolAddrKey = record.getLongValue(V5_SYMBOL_ADDR_COL);
		rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_ADDR_COL, symbolAddrKey);

		long namespaceId = record.getLongValue(V5_SYMBOL_PARENT_ID_COL);
		rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_PARENT_ID_COL, namespaceId);

		byte symbolTypeId = record.getByteValue(V5_SYMBOL_TYPE_COL);
		rec.setByteValue(SymbolDatabaseAdapter.SYMBOL_TYPE_COL, symbolTypeId);

		rec.setByteValue(SymbolDatabaseAdapter.SYMBOL_FLAGS_COL,
			record.getByteValue(V5_SYMBOL_FLAGS_COL));

		//
		// Convert sparse columns

		Field hash = record.getFieldValue(V5_SYMBOL_HASH_COL);
		if (hash != null) {
			rec.setField(SymbolDatabaseAdapter.SYMBOL_HASH_COL, hash);
		}

		Field primaryAddr = record.getFieldValue(V5_SYMBOL_PRIMARY_COL);
		if (primaryAddr != null) {
			rec.setField(SymbolDatabaseAdapter.SYMBOL_PRIMARY_COL, primaryAddr);
		}

		Field dataTypeId = record.getFieldValue(V5_SYMBOL_DATATYPE_COL);
		if (dataTypeId != null) {
			rec.setField(SymbolDatabaseAdapter.SYMBOL_DATATYPE_COL, dataTypeId);
		}

		Field varOffset = record.getFieldValue(V5_SYMBOL_VAROFFSET_COL);
		if (varOffset != null) {
			rec.setField(SymbolDatabaseAdapter.SYMBOL_VAROFFSET_COL, varOffset);
		}

		Field origName = record.getFieldValue(V5_SYMBOL_ORIGINAL_IMPORTED_NAME_COL);
		if (origName != null) {
			rec.setField(SymbolDatabaseAdapter.SYMBOL_ORIGINAL_IMPORTED_NAME_COL, origName);
		}

		Field extProgramAddr = record.getFieldValue(V5_SYMBOL_EXTERNAL_PROG_ADDR_COL);
		if (extProgramAddr != null) {
			rec.setField(SymbolDatabaseAdapter.SYMBOL_EXTERNAL_PROG_ADDR_COL, extProgramAddr);
		}

		Field comment = record.getFieldValue(V5_SYMBOL_COMMENT_COL);
		if (comment != null) {
			rec.setField(SymbolDatabaseAdapter.SYMBOL_COMMENT_COL, comment);
		}

		Field libPath = record.getFieldValue(V5_SYMBOL_LIBPATH_COL);
		if (libPath != null) {
			rec.setField(SymbolDatabaseAdapter.SYMBOL_LIBPATH_COL, libPath);
		}
		Field libOrdinal = record.getFieldValue(V5_SYMBOL_LIB_ORDINAL_COL);
		if (libOrdinal != null) {
			rec.setField(SymbolDatabaseAdapter.SYMBOL_LIB_ORDINAL_COL, libOrdinal);
		}

		return rec;
	}

	@Override
	int getSymbolCount() {
		return symbolTable.getRecordCount();
	}
}
