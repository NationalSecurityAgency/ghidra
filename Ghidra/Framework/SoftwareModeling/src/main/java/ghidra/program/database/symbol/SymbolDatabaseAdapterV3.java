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
import java.util.Set;

import org.apache.commons.lang3.StringUtils;

import db.*;
import ghidra.program.database.map.*;
import ghidra.program.database.util.EmptyRecordIterator;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * SymbolDatabaseAdapter for version 3
 * 
 * This version provides for fast symbol lookup by namespace and name and introduced the use of 
 * sparse table columns for storing optional symbol data (hash, primary, datatype-ID, variable-offset).
 * It was created in June 2021 with ProgramDB version 24. 
 * It was first in affect within Ghidra starting at version 10.1
 */
class SymbolDatabaseAdapterV3 extends SymbolDatabaseAdapter {

	static final int SYMBOL_VERSION = 3;

	// Used to create a range when searching symbols by name/namespace but don't care about address
	private static final long MIN_ADDRESS_OFFSET = 0;
	private static final long MAX_ADDRESS_OFFSET = -1;

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
	private AddressMap addrMap;

	SymbolDatabaseAdapterV3(DBHandle handle, AddressMap addrMap) throws VersionException {

		this.addrMap = addrMap;
		symbolTable = handle.getTable(SYMBOL_TABLE_NAME);
		if (symbolTable == null) {
			throw new VersionException("Missing Table: " + SYMBOL_TABLE_NAME);
		}
		if (symbolTable.getSchema().getVersion() != SYMBOL_VERSION) {
			int version = symbolTable.getSchema().getVersion();
			if (version < SYMBOL_VERSION) {
				throw new VersionException(true);
			}
			throw new VersionException(VersionException.NEWER_VERSION, false);
		}
	}

	@Override
	DBRecord createSymbolRecord(String name, long namespaceID, Address address,
			SymbolType symbolType, boolean isPrimary, SourceType source) {
		throw new UnsupportedOperationException();
	}

	@Override
	void removeSymbol(long symbolID) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	boolean hasSymbol(Address addr) throws IOException {
		long key = addrMap.getKey(addr, false);
		if (key == AddressMap.INVALID_ADDRESS_KEY && !addr.equals(Address.NO_ADDRESS)) {
			return false;
		}
		return symbolTable.hasRecord(new LongField(key), SYMBOL_ADDR_COL);
	}

	@Override
	Field[] getSymbolIDs(Address addr) throws IOException {
		long key = addrMap.getKey(addr, false);
		if (key == AddressMap.INVALID_ADDRESS_KEY && !addr.equals(Address.NO_ADDRESS)) {
			return Field.EMPTY_ARRAY;
		}
		return symbolTable.findRecords(new LongField(key), SYMBOL_ADDR_COL);
	}

	@Override
	DBRecord getSymbolRecord(long symbolID) throws IOException {
		return convertV3Record(symbolTable.getRecord(symbolID));
	}

	@Override
	int getSymbolCount() {
		return symbolTable.getRecordCount();
	}

	@Override
	RecordIterator getSymbolsByAddress(boolean forward) throws IOException {
		KeyToRecordIterator it = new KeyToRecordIterator(symbolTable,
			new AddressIndexPrimaryKeyIterator(symbolTable, SYMBOL_ADDR_COL, addrMap, forward));
		return new V3ConvertedRecordIterator(it);
	}

	@Override
	RecordIterator getSymbolsByAddress(Address startAddr, boolean forward) throws IOException {
		KeyToRecordIterator it =
			new KeyToRecordIterator(symbolTable, new AddressIndexPrimaryKeyIterator(symbolTable,
				SYMBOL_ADDR_COL, addrMap, startAddr, forward));
		return new V3ConvertedRecordIterator(it);
	}

	@Override
	void updateSymbolRecord(DBRecord record) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	RecordIterator getSymbols() throws IOException {
		return new V3ConvertedRecordIterator(symbolTable.iterator());
	}

	@Override
	RecordIterator getSymbols(Address start, Address end, boolean forward) throws IOException {
		KeyToRecordIterator it =
			new KeyToRecordIterator(symbolTable, new AddressIndexPrimaryKeyIterator(symbolTable,
				SYMBOL_ADDR_COL, addrMap, start, end, forward));
		return new V3ConvertedRecordIterator(it);
	}

	@Override
	RecordIterator getSymbols(AddressSetView set, boolean forward) throws IOException {
		KeyToRecordIterator it =
			new KeyToRecordIterator(symbolTable, new AddressIndexPrimaryKeyIterator(symbolTable,
				SYMBOL_ADDR_COL, addrMap, set, forward));
		return new V3ConvertedRecordIterator(it);
	}

	@Override
	protected RecordIterator getPrimarySymbols(AddressSetView set, boolean forward)
			throws IOException {
		KeyToRecordIterator it =
			new KeyToRecordIterator(symbolTable, new AddressIndexPrimaryKeyIterator(symbolTable,
				SYMBOL_PRIMARY_COL, addrMap, set, forward));
		return new V3ConvertedRecordIterator(it);
	}

	@Override
	protected DBRecord getPrimarySymbol(Address address) throws IOException {
		AddressIndexPrimaryKeyIterator it = new AddressIndexPrimaryKeyIterator(symbolTable,
			SYMBOL_PRIMARY_COL, addrMap, address, address, true);
		if (it.hasNext()) {
			return convertV3Record(symbolTable.getRecord(it.next()));
		}
		return null;
	}

	@Override
	void moveAddress(Address oldAddr, Address newAddr) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	Set<Address> deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException, IOException {
		throw new UnsupportedOperationException();
	}

	private String getExternalStringData(DBRecord rec) {
		long addrKey = rec.getLongValue(V3_SYMBOL_ADDR_COL);
		Address addr = addrMap.decodeAddress(addrKey);
		if (addr == null || !addr.isExternalAddress()) {
			return null;
		}
		byte symbolTypeId = rec.getByteValue(V3_SYMBOL_TYPE_COL);
		if (symbolTypeId != SYMBOL_TYPE_FUNCTION && symbolTypeId != SYMBOL_TYPE_LABEL) {
			return null;
		}

		return rec.getString(V3_SYMBOL_STRING_DATA_COL);
	}

	@Override
	RecordIterator getExternalSymbolsByMemoryAddress(Address extProgAddr) throws IOException {
		if (extProgAddr == null) {
			return EmptyRecordIterator.INSTANCE;
		}
		String matchAddrStr = extProgAddr.toString();
		return new ConstrainedForwardRecordIterator(symbolTable.iterator(), rec -> {
			String str = getExternalStringData(rec);
			if (str != null) {
				int indexOf = str.indexOf(","); // [address][,importName]
				String addressString = indexOf >= 0 ? str.substring(0, indexOf) : str;
				if (matchAddrStr.equals(addressString)) {
					return convertV3Record(rec);
				}
			}
			return null;
		});
	}

	@Override
	RecordIterator getExternalSymbolsByOriginalImportName(String extLabel) throws IOException {
		if (StringUtils.isBlank(extLabel)) {
			return EmptyRecordIterator.INSTANCE;
		}
		return new ConstrainedForwardRecordIterator(symbolTable.iterator(), rec -> {
			String str = getExternalStringData(rec);
			if (str != null) {
				int indexOf = str.indexOf(","); // [address][,importName]
				String originalImportedName = indexOf >= 0 ? str.substring(indexOf + 1) : null;
				if (extLabel.equals(originalImportedName)) {
					return convertV3Record(rec);
				}
			}
			return null;
		});
	}

	@Override
	RecordIterator getSymbolsByNamespace(long id) throws IOException {
		LongField field = new LongField(id);
		RecordIterator it = symbolTable.indexIterator(SYMBOL_PARENT_ID_COL, field, field, true);
		return new V3ConvertedRecordIterator(it);
	}

	@Override
	RecordIterator getSymbolsByName(String name) throws IOException {
		StringField field = new StringField(name);
		RecordIterator it = symbolTable.indexIterator(SYMBOL_NAME_COL, field, field, true);
		return new V3ConvertedRecordIterator(it);
	}

	@Override
	RecordIterator scanSymbolsByName(String startName) throws IOException {
		StringField field = new StringField(startName);
		RecordIterator it = symbolTable.indexIterator(SYMBOL_NAME_COL, field, null, true);
		return new V3ConvertedRecordIterator(it);
	}

	@Override
	RecordIterator getSymbolsByNameAndNamespace(String name, long id) throws IOException {
		// create a range of hash fields for all symbols with this name and namespace id over all
		// possible addresses
		Field start = computeLocatorHash(name, id, MIN_ADDRESS_OFFSET);
		if (start == null) {
			return EmptyRecordIterator.INSTANCE;
		}

		Field end = computeLocatorHash(name, id, MAX_ADDRESS_OFFSET);

		RecordIterator it = symbolTable.indexIterator(SYMBOL_HASH_COL, start, end, true);
		it = new V3ConvertedRecordIterator(it);

		RecordIterator filtered = getNameAndNamespaceFilterIterator(name, id, it);
		return new V3ConvertedRecordIterator(filtered);
	}

	@Override
	DBRecord getSymbolRecord(Address address, String name, long namespaceId) throws IOException {
		long addressKey = addrMap.getKey(address, false);
		Field search = computeLocatorHash(name, namespaceId, addressKey);
		if (search == null) {
			return null;
		}
		RecordIterator it = symbolTable.indexIterator(SYMBOL_HASH_COL, search, search, true);
		it = new V3ConvertedRecordIterator(it);

		RecordIterator filtered =
			getNameNamespaceAddressFilterIterator(name, namespaceId, addressKey, it);
		if (filtered.hasNext()) {
			return filtered.next();
		}
		return null;
	}

	@Override
	Address getMaxSymbolAddress(AddressSpace space) throws IOException {
		if (space.isMemorySpace()) {
			AddressIndexKeyIterator addressKeyIterator = new AddressIndexKeyIterator(symbolTable,
				SYMBOL_ADDR_COL, addrMap, space.getMinAddress(), space.getMaxAddress(), false);
			if (addressKeyIterator.hasNext()) {
				return addrMap.decodeAddress(addressKeyIterator.next());
			}
		}
		else {
			LongField max = new LongField(addrMap.getKey(space.getMaxAddress(), false));
			DBFieldIterator iterator =
				symbolTable.indexFieldIterator(null, max, false, SYMBOL_ADDR_COL);
			if (iterator.hasPrevious()) {
				LongField val = (LongField) iterator.previous();
				Address addr = addrMap.decodeAddress(val.getLongValue());
				if (space.equals(addr.getAddressSpace())) {
					return addr;
				}
			}
		}
		return null;
	}

	@Override
	Table getTable() {
		return symbolTable;
	}

	/**
	 * Returns a record matching the current database schema from the version 2 record.
	 * @param record the record matching the version 2 schema.
	 * @return a current symbol record.
	 */
	private DBRecord convertV3Record(DBRecord record) {
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

	private class V3ConvertedRecordIterator extends ConvertedRecordIterator {

		V3ConvertedRecordIterator(RecordIterator originalIterator) {
			super(originalIterator, false);
		}

		@Override
		protected DBRecord convertRecord(DBRecord record) {
			return convertV3Record(record);
		}
	}

}
