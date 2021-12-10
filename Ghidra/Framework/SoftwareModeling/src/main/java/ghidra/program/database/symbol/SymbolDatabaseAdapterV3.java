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
 * SymbolDatabaseAdapter for version 3
 * 
 * This version provides for fast symbol lookup by namespace and name.
 * It was created in June 2021 with ProgramDB version 24. 
 * It will be included in Ghidra starting at version 10.1
 */
class SymbolDatabaseAdapterV3 extends SymbolDatabaseAdapter {

	static final int SYMBOL_VERSION = 3;

	// Used to create a range when searching symbols by name/namespace but don't care about address
	private static final long MIN_ADDRESS_OFFSET = 0;
	private static final long MAX_ADDRESS_OFFSET = -1;

	// NOTE: the primary field duplicates the symbol's address when the symbol is primary. This
	// allows us to index this field and quickly find the primary symbols. The field is sparse
	// so that non-primary symbols don't consume any space for this field.

	static final Schema V3_SYMBOL_SCHEMA = new Schema(SYMBOL_VERSION, "Key",
		new Field[] { StringField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE,
			ByteField.INSTANCE, StringField.INSTANCE, ByteField.INSTANCE,
			LongField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE, IntField.INSTANCE },
		new String[] { "Name", "Address", "Namespace", "Symbol Type", "String Data", "Flags",
			"Locator Hash", "Primary", "Datatype", "Variable Offset" },
		new int[] { SYMBOL_HASH_COL, SYMBOL_PRIMARY_COL, SYMBOL_DATATYPE_COL,
			SYMBOL_VAROFFSET_COL });

	private Table symbolTable;
	private AddressMap addrMap;

	SymbolDatabaseAdapterV3(DBHandle handle, AddressMap addrMap, boolean create)
			throws VersionException, IOException {

		this.addrMap = addrMap;
		if (create) {
			symbolTable = handle.createTable(SYMBOL_TABLE_NAME, SYMBOL_SCHEMA,
				new int[] { SYMBOL_ADDR_COL, SYMBOL_NAME_COL, SYMBOL_PARENT_COL, SYMBOL_HASH_COL,
					SYMBOL_PRIMARY_COL });
		}
		else {
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
	}

	@Override
	DBRecord createSymbol(String name, Address address, long namespaceID, SymbolType symbolType,
			String stringData, Long dataTypeId, Integer varOffset, SourceType source,
			boolean isPrimary) throws IOException {
		long nextID = symbolTable.getKey();

		// avoiding key 0, as it is reserved for the global namespace
		if (nextID == 0) {
			nextID++;
		}
		return createSymbol(nextID, name, address, namespaceID, symbolType, stringData,
			(byte) source.ordinal(), dataTypeId, varOffset, isPrimary);
	}

	private DBRecord createSymbol(long id, String name, Address address, long namespaceID,
			SymbolType symbolType, String stringData, byte flags,
			Long dataTypeId, Integer varOffset, boolean isPrimary) throws IOException {

		long addressKey = addrMap.getKey(address, true);

		DBRecord rec = symbolTable.getSchema().createRecord(id);
		rec.setString(SYMBOL_NAME_COL, name);
		rec.setLongValue(SYMBOL_ADDR_COL, addressKey);
		rec.setLongValue(SYMBOL_PARENT_COL, namespaceID);
		rec.setByteValue(SYMBOL_TYPE_COL, symbolType.getID());
		rec.setString(SYMBOL_STRING_DATA_COL, stringData);
		rec.setByteValue(SYMBOL_FLAGS_COL, flags);

		// sparse columns - these columns don't apply to all symbols.
		// they default to null unless specifically set. Null values don't consume space.

		rec.setField(SYMBOL_HASH_COL,
			computeLocatorHash(name, namespaceID, addressKey));

		if (isPrimary) {
			rec.setLongValue(SYMBOL_PRIMARY_COL, addressKey);
		}

		if (dataTypeId != null) {
			rec.setLongValue(SYMBOL_DATATYPE_COL, dataTypeId);
		}

		if (varOffset != null) {
			rec.setIntValue(SYMBOL_VAROFFSET_COL, varOffset);
		}

		symbolTable.putRecord(rec);
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
		return symbolTable.getRecord(symbolID);
	}

	@Override
	int getSymbolCount() {
		return symbolTable.getRecordCount();
	}

	@Override
	RecordIterator getSymbolsByAddress(boolean forward) throws IOException {
		return new KeyToRecordIterator(symbolTable,
			new AddressIndexPrimaryKeyIterator(symbolTable, SYMBOL_ADDR_COL, addrMap, forward));
	}

	@Override
	RecordIterator getSymbolsByAddress(Address startAddr, boolean forward) throws IOException {
		return new KeyToRecordIterator(symbolTable, new AddressIndexPrimaryKeyIterator(symbolTable,
			SYMBOL_ADDR_COL, addrMap, startAddr, forward));
	}

	@Override
	void updateSymbolRecord(DBRecord record) throws IOException {
		// make sure hash is updated to current name and name space
		String name = record.getString(SYMBOL_NAME_COL);
		long namespaceId = record.getLongValue(SYMBOL_PARENT_COL);
		long addressKey = record.getLongValue(SYMBOL_ADDR_COL);
		record.setField(SYMBOL_HASH_COL,
			computeLocatorHash(name, namespaceId, addressKey));
		symbolTable.putRecord(record);
	}

	@Override
	RecordIterator getSymbols() throws IOException {
		return symbolTable.iterator();
	}

	@Override
	RecordIterator getSymbols(Address start, Address end, boolean forward) throws IOException {
		return new KeyToRecordIterator(symbolTable, new AddressIndexPrimaryKeyIterator(symbolTable,
			SYMBOL_ADDR_COL, addrMap, start, end, forward));
	}

	@Override
	RecordIterator getSymbols(AddressSetView set, boolean forward) throws IOException {
		return new KeyToRecordIterator(symbolTable, new AddressIndexPrimaryKeyIterator(symbolTable,
			SYMBOL_ADDR_COL, addrMap, set, forward));
	}

	@Override
	protected RecordIterator getPrimarySymbols(AddressSetView set, boolean forward)
			throws IOException {
		return new KeyToRecordIterator(symbolTable, new AddressIndexPrimaryKeyIterator(symbolTable,
			SYMBOL_PRIMARY_COL, addrMap, set, forward));
	}

	@Override
	protected DBRecord getPrimarySymbol(Address address) throws IOException {
		AddressIndexPrimaryKeyIterator it = new AddressIndexPrimaryKeyIterator(symbolTable,
			SYMBOL_PRIMARY_COL, addrMap, address, address, true);
		if (it.hasNext()) {
			return symbolTable.getRecord(it.next());
		}
		return null;
	}

	void deleteExternalEntries(Address start, Address end) throws IOException {
		AddressRecordDeleter.deleteRecords(symbolTable, SYMBOL_ADDR_COL, addrMap, start, end, null);
	}

	@Override
	void moveAddress(Address oldAddr, Address newAddr) throws IOException {
		LongField oldKey = new LongField(addrMap.getKey(oldAddr, false));
		long newKey = addrMap.getKey(newAddr, true);
		Field[] keys = symbolTable.findRecords(oldKey, SYMBOL_ADDR_COL);
		for (Field key : keys) {
			DBRecord rec = symbolTable.getRecord(key);
			rec.setLongValue(SYMBOL_ADDR_COL, newKey);
			symbolTable.putRecord(rec);
		}
	}

	@Override
	Set<Address> deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException, IOException {

		AnchoredSymbolRecordFilter filter = new AnchoredSymbolRecordFilter();
		AddressRecordDeleter.deleteRecords(symbolTable, SYMBOL_ADDR_COL, addrMap, startAddr,
			endAddr, filter);

		return filter.getAddressesForSkippedRecords();
	}

	@Override
	RecordIterator getSymbolsByNamespace(long id) throws IOException {
		LongField field = new LongField(id);
		return symbolTable.indexIterator(SYMBOL_PARENT_COL, field, field, true);
	}

	@Override
	RecordIterator getSymbolsByName(String name) throws IOException {
		StringField field = new StringField(name);
		return symbolTable.indexIterator(SYMBOL_NAME_COL, field, field, true);
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
		return getNameAndNamespaceFilterIterator(name, id, it);
	}

	@Override
	DBRecord getSymbolRecord(Address address, String name, long namespaceId) throws IOException {
		long addressKey = addrMap.getKey(address, false);
		Field search = computeLocatorHash(name, namespaceId, addressKey);
		if (search == null) {
			return null;
		}
		RecordIterator it = symbolTable.indexIterator(SYMBOL_HASH_COL, search, search, true);
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

	private class AnchoredSymbolRecordFilter implements RecordFilter {
		private Set<Address> set = new HashSet<Address>();

		@Override
		public boolean matches(DBRecord record) {
			// only move symbols whose anchor flag is not on
			Address addr = addrMap.decodeAddress(record.getLongValue(SYMBOL_ADDR_COL));
			byte flags = record.getByteValue(SymbolDatabaseAdapter.SYMBOL_FLAGS_COL);
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
