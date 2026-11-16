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
import java.util.HashSet;
import java.util.Set;

import db.*;
import ghidra.program.database.map.*;
import ghidra.program.database.util.EmptyRecordIterator;
import ghidra.program.database.util.RecordFilter;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * SymbolDatabaseAdapter for version 6
 * 
 * This version adds a new column for storing a library symbol id. This id indicates the symbol
 * is external in in the library associated with that id.
 */
class SymbolDatabaseAdapterV6 extends SymbolDatabaseAdapter {
	static final int V6_SYMBOL_NAME_COL = 0;
	static final int V6_SYMBOL_ADDR_COL = 1;
	static final int V6_SYMBOL_PARENT_ID_COL = 2;
	static final int V6_SYMBOL_TYPE_COL = 3;
	static final int V6_SYMBOL_FLAGS_COL = 4;

	// Sparse fields - the following fields are not always applicable so they are optional and 
	// don't consume space in the database if they aren't used.
	static final int V6_SYMBOL_HASH_COL = 5;
	static final int V6_SYMBOL_PRIMARY_COL = 6;
	static final int V6_SYMBOL_DATATYPE_COL = 7;
	static final int V6_SYMBOL_VAROFFSET_COL = 8;
	static final int V6_SYMBOL_ORIGINAL_IMPORTED_NAME_COL = 9;
	static final int V6_SYMBOL_EXTERNAL_PROG_ADDR_COL = 10;
	static final int V6_SYMBOL_COMMENT_COL = 11;
	static final int V6_SYMBOL_LIBPATH_COL = 12;
	static final int V6_SYMBOL_LIB_ORDINAL_COL = 13;
	static final int V6_SYMBOL_LIBRARY_ID_COL = 14;

	static final int VERSION = 6;

	// Used to create a range when searching symbols by name/namespace but don't care about address
	private static final long MIN_ENCODED_ADDRESS = 0;
	private static final long MAX_ENCODED_ADDRESS = -1;

	// NOTE: the primary field duplicates the symbol's address when the symbol is primary. This
	// allows us to index this field and quickly find the primary symbols. The field is sparse
	// so that non-primary symbols don't consume any space for this field.

	static final Schema V6_SYMBOL_SCHEMA = new Schema(VERSION, "Key",
		new Field[] { StringField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE,
			ByteField.INSTANCE, ByteField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE,
			LongField.INSTANCE, IntField.INSTANCE, StringField.INSTANCE, StringField.INSTANCE,
			StringField.INSTANCE, StringField.INSTANCE, IntField.INSTANCE, LongField.INSTANCE },
		new String[] { "Name", "Address", "Namespace", "Symbol Type", "Flags", "Locator Hash",
			"Primary", "Datatype", "Variable Offset", "ExtOrigImportName", "ExtProgAddr", "Comment",
			"LibPath", "LibOrdinal", "LIBRARY_ID" },
		new int[] { V6_SYMBOL_HASH_COL, V6_SYMBOL_PRIMARY_COL, V6_SYMBOL_DATATYPE_COL,
			V6_SYMBOL_VAROFFSET_COL, V6_SYMBOL_ORIGINAL_IMPORTED_NAME_COL,
			V6_SYMBOL_EXTERNAL_PROG_ADDR_COL, V6_SYMBOL_COMMENT_COL,
			V6_SYMBOL_LIBPATH_COL, V6_SYMBOL_LIB_ORDINAL_COL, V6_SYMBOL_LIBRARY_ID_COL });

	private Table symbolTable;
	private AddressMap addrMap;

	SymbolDatabaseAdapterV6(DBHandle handle, AddressMap addrMap, boolean create)
			throws VersionException, IOException {

		this.addrMap = addrMap;
		if (create) {
			symbolTable = handle.createTable(SYMBOL_TABLE_NAME, SYMBOL_SCHEMA,
				new int[] { V6_SYMBOL_ADDR_COL, V6_SYMBOL_NAME_COL, V6_SYMBOL_PARENT_ID_COL,
					V6_SYMBOL_HASH_COL, V6_SYMBOL_PRIMARY_COL, V6_SYMBOL_ORIGINAL_IMPORTED_NAME_COL,
					V6_SYMBOL_EXTERNAL_PROG_ADDR_COL, V6_SYMBOL_LIBRARY_ID_COL });
		}
		else {
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
	}

	@Override
	DBRecord createSymbolRecord(String name, long namespaceID, Address address,
			SymbolType symbolType, boolean isPrimary, SourceType source) {

		long nextID = symbolTable.getKey();

		// Avoid key 0, as it is reserved for the global namespace
		if (nextID == 0) {
			nextID++;
		}

		long addressKey = addrMap.getKey(address, true);

		DBRecord rec = symbolTable.getSchema().createRecord(nextID);
		rec.setString(V6_SYMBOL_NAME_COL, name);
		rec.setLongValue(V6_SYMBOL_ADDR_COL, addressKey);
		rec.setLongValue(V6_SYMBOL_PARENT_ID_COL, namespaceID);
		rec.setByteValue(V6_SYMBOL_TYPE_COL, symbolType.getID());
		rec.setByteValue(V6_SYMBOL_FLAGS_COL, getSourceTypeFlagsBits(source)); // assume non-pinned

		// Sparse columns - these columns don't apply to all symbols.
		// they default to null unless specifically set. Null values don't consume space.

		rec.setField(V6_SYMBOL_HASH_COL, computeLocatorHash(name, namespaceID, addressKey));

		if (isPrimary) {
			rec.setLongValue(V6_SYMBOL_PRIMARY_COL, addressKey);
		}

		return rec;
	}

	@Override
	void removeSymbol(long symbolID) throws IOException {
		symbolTable.deleteRecord(symbolID);
	}

	@Override
	boolean hasSymbol(Address addr) throws IOException {
		long key = addrMap.getKey(addr, false);
		if (key == AddressMap.INVALID_ADDRESS_KEY && !addr.equals(Address.NO_ADDRESS)) {
			return false;
		}
		return symbolTable.hasRecord(new LongField(key), V6_SYMBOL_ADDR_COL);
	}

	@Override
	Field[] getSymbolIDs(Address addr) throws IOException {
		long key = addrMap.getKey(addr, false);
		if (key == AddressMap.INVALID_ADDRESS_KEY && !addr.equals(Address.NO_ADDRESS)) {
			return Field.EMPTY_ARRAY;
		}
		return symbolTable.findRecords(new LongField(key), V6_SYMBOL_ADDR_COL);
	}

	@Override
	DBRecord getSymbolRecord(long symbolID) throws IOException {
		return symbolTable.getRecord(symbolID);
	}

	@Override
	int getSymbolCount() {
		return symbolTable.getRecordCount();
	}

	@Override
	RecordIterator getSymbolsByAddress(boolean forward) throws IOException {
		return new KeyToRecordIterator(symbolTable,
			new AddressIndexPrimaryKeyIterator(symbolTable, V6_SYMBOL_ADDR_COL, addrMap, forward));
	}

	@Override
	RecordIterator getSymbolsByAddress(Address startAddr, boolean forward) throws IOException {
		return new KeyToRecordIterator(symbolTable, new AddressIndexPrimaryKeyIterator(symbolTable,
			V6_SYMBOL_ADDR_COL, addrMap, startAddr, forward));
	}

	@Override
	void updateSymbolRecord(DBRecord record) throws IOException {
		// make sure hash is updated to current name and name space
		String name = record.getString(V6_SYMBOL_NAME_COL);
		long namespaceId = record.getLongValue(V6_SYMBOL_PARENT_ID_COL);
		long addressKey = record.getLongValue(V6_SYMBOL_ADDR_COL);
		record.setField(V6_SYMBOL_HASH_COL, computeLocatorHash(name, namespaceId, addressKey));
		symbolTable.putRecord(record);
	}

	@Override
	RecordIterator getSymbols() throws IOException {
		return symbolTable.iterator();
	}

	@Override
	RecordIterator getSymbols(Address start, Address end, boolean forward) throws IOException {
		return new KeyToRecordIterator(symbolTable, new AddressIndexPrimaryKeyIterator(symbolTable,
			V6_SYMBOL_ADDR_COL, addrMap, start, end, forward));
	}

	@Override
	RecordIterator getSymbols(AddressSetView set, boolean forward) throws IOException {
		return new KeyToRecordIterator(symbolTable, new AddressIndexPrimaryKeyIterator(symbolTable,
			V6_SYMBOL_ADDR_COL, addrMap, set, forward));
	}

	@Override
	protected RecordIterator getPrimarySymbols(AddressSetView set, boolean forward)
			throws IOException {
		return new KeyToRecordIterator(symbolTable, new AddressIndexPrimaryKeyIterator(symbolTable,
			V6_SYMBOL_PRIMARY_COL, addrMap, set, forward));
	}

	@Override
	protected DBRecord getPrimarySymbol(Address address) throws IOException {
		AddressIndexPrimaryKeyIterator it = new AddressIndexPrimaryKeyIterator(symbolTable,
			V6_SYMBOL_PRIMARY_COL, addrMap, address, address, true);
		if (it.hasNext()) {
			return symbolTable.getRecord(it.next());
		}
		return null;
	}

	void deleteExternalEntries(Address start, Address end) throws IOException {
		AddressRecordDeleter.deleteRecords(symbolTable, V6_SYMBOL_ADDR_COL, addrMap, start, end,
			null);
	}

	@Override
	void moveAddress(Address oldAddr, Address newAddr) throws IOException {
		LongField oldKey = new LongField(addrMap.getKey(oldAddr, false));
		long newKey = addrMap.getKey(newAddr, true);
		Field[] keys = symbolTable.findRecords(oldKey, V6_SYMBOL_ADDR_COL);
		for (Field key : keys) {
			DBRecord rec = symbolTable.getRecord(key);
			rec.setLongValue(V6_SYMBOL_ADDR_COL, newKey);
			symbolTable.putRecord(rec);
		}
	}

	@Override
	Set<Address> deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException, IOException {

		AnchoredSymbolRecordFilter filter = new AnchoredSymbolRecordFilter();
		AddressRecordDeleter.deleteRecords(symbolTable, V6_SYMBOL_ADDR_COL, addrMap, startAddr,
			endAddr, filter);

		return filter.getAddressesForSkippedRecords();
	}

	@Override
	RecordIterator getSymbolsByNamespace(long id) throws IOException {
		LongField field = new LongField(id);
		return symbolTable.indexIterator(V6_SYMBOL_PARENT_ID_COL, field, field, true);
	}

	@Override
	RecordIterator getSymbolsByLibrary(long libraryID) throws IOException {
		LongField field = new LongField(libraryID);
		return symbolTable.indexIterator(V6_SYMBOL_LIBRARY_ID_COL, field, field, true);
	}

	@Override
	RecordIterator getSymbolsByName(String name) throws IOException {
		StringField field = new StringField(name);
		return symbolTable.indexIterator(V6_SYMBOL_NAME_COL, field, field, true);
	}

	@Override
	RecordIterator scanSymbolsByName(String startName) throws IOException {
		StringField field = new StringField(startName);
		return symbolTable.indexIterator(V6_SYMBOL_NAME_COL, field, null, true);
	}

	@Override
	RecordIterator getExternalSymbolsByOriginalImportName(String extLabel) throws IOException {
		StringField extLabelField = new StringField(extLabel);
		return symbolTable.indexIterator(V6_SYMBOL_ORIGINAL_IMPORTED_NAME_COL, extLabelField,
			extLabelField, true);
	}

	@Override
	RecordIterator getExternalSymbolsByMemoryAddress(Address extProgAddr) throws IOException {
		StringField addrField = new StringField(extProgAddr.toString());
		return symbolTable.indexIterator(V6_SYMBOL_EXTERNAL_PROG_ADDR_COL, addrField, addrField,
			true);
	}

	@Override
	RecordIterator getSymbolsByNameAndNamespace(String name, long id) throws IOException {
		// create a range of hash fields for all symbols with this name and namespace id over all
		// possible addresses
		Field start = computeLocatorHash(name, id, MIN_ENCODED_ADDRESS);
		if (start == null) {
			return EmptyRecordIterator.INSTANCE;
		}

		Field end = computeLocatorHash(name, id, MAX_ENCODED_ADDRESS);

		RecordIterator it = symbolTable.indexIterator(V6_SYMBOL_HASH_COL, start, end, true);
		return getNameAndNamespaceFilterIterator(name, id, it);
	}

	@Override
	DBRecord getSymbolRecord(Address address, String name, long namespaceId) throws IOException {
		long addressKey = addrMap.getKey(address, false);
		Field search = computeLocatorHash(name, namespaceId, addressKey);
		if (search == null) {
			return null;
		}
		RecordIterator it = symbolTable.indexIterator(V6_SYMBOL_HASH_COL, search, search, true);
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
				V6_SYMBOL_ADDR_COL, addrMap, space.getMinAddress(), space.getMaxAddress(), false);
			if (addressKeyIterator.hasNext()) {
				return addrMap.decodeAddress(addressKeyIterator.next());
			}
		}
		else {
			LongField max = new LongField(addrMap.getKey(space.getMaxAddress(), false));
			DBFieldIterator iterator =
				symbolTable.indexFieldIterator(null, max, false, V6_SYMBOL_ADDR_COL);
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

	@Override
	protected int getVersion() {
		return VERSION;
	}

	private class AnchoredSymbolRecordFilter implements RecordFilter {
		private Set<Address> set = new HashSet<Address>();

		@Override
		public boolean matches(DBRecord record) {
			// only move symbols whose anchor flag is not on
			Address addr = addrMap.decodeAddress(record.getLongValue(V6_SYMBOL_ADDR_COL));
			byte flags = record.getByteValue(V6_SYMBOL_FLAGS_COL);
			boolean pinned = (flags & SymbolDatabaseAdapter.SYMBOL_PINNED_FLAG) != 0;
			if (!pinned) {
				return true;
			}
			set.add(addr);
			return false;
		}

		Set<Address> getAddressesForSkippedRecords() {
			return set;
		}
	}

}
