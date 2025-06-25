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
 * SymbolDatabaseAdapter for version 2
 */
class SymbolDatabaseAdapterV2 extends SymbolDatabaseAdapter {

/* Do not remove the following commented out schema! It shows the version 2 symbol table schema. */
//	static final Schema SYMBOL_SCHEMA = new Schema(2, "Key",
//		new Field[] { StringField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE,
//			ByteField.INSTANCE, LongField.INSTANCE, IntField.INSTANCE, StringField.INSTANCE,
//			ByteField.INSTANCE },
//		new String[] { "Name", "Address", "Parent", "Symbol Type", "SymbolData1", "SymbolData2",
//			"SymbolData3", "Flags" });

	private static final int SYMBOL_VERSION = 2;

	private static final int V2_SYMBOL_NAME_COL = 0;
	private static final int V2_SYMBOL_ADDR_COL = 1;
	private static final int V2_SYMBOL_PARENT_ID_COL = 2;
	private static final int V2_SYMBOL_TYPE_COL = 3;
	private static final int V2_SYMBOL_DATA1_COL = 4; // Long data (variable dataTypeId)
	private static final int V2_SYMBOL_DATA2_COL = 5; // Int data (primary flag, variable-offset)
	private static final int V2_SYMBOL_DATA3_COL = 6; // String data (external address)
	private static final int V2_SYMBOL_FLAGS_COL = 7;

	private Table symbolTable;
	private AddressMap addrMap;

	SymbolDatabaseAdapterV2(DBHandle handle, AddressMap addrMap) throws VersionException {

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
		return convertV2Record(symbolTable.getRecord(symbolID));
	}

	@Override
	int getSymbolCount() {
		return symbolTable.getRecordCount();
	}

	@Override
	RecordIterator getSymbolsByAddress(boolean forward) throws IOException {
		KeyToRecordIterator it = new KeyToRecordIterator(symbolTable,
			new AddressIndexPrimaryKeyIterator(symbolTable, SYMBOL_ADDR_COL, addrMap, forward));
		return new V2ConvertedRecordIterator(it);
	}

	@Override
	RecordIterator getSymbolsByAddress(Address startAddr, boolean forward) throws IOException {
		KeyToRecordIterator it =
			new KeyToRecordIterator(symbolTable, new AddressIndexPrimaryKeyIterator(symbolTable,
				SYMBOL_ADDR_COL, addrMap, startAddr, forward));
		return new V2ConvertedRecordIterator(it);
	}

	@Override
	void updateSymbolRecord(DBRecord record) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	RecordIterator getSymbols() throws IOException {
		return new V2ConvertedRecordIterator(symbolTable.iterator());
	}

	@Override
	RecordIterator getSymbols(Address start, Address end, boolean forward) throws IOException {
		KeyToRecordIterator it =
			new KeyToRecordIterator(symbolTable, new AddressIndexPrimaryKeyIterator(symbolTable,
				SYMBOL_ADDR_COL, addrMap, start, end, forward));
		return new V2ConvertedRecordIterator(it);
	}

	@Override
	RecordIterator getSymbols(AddressSetView set, boolean forward) throws IOException {
		KeyToRecordIterator it =
			new KeyToRecordIterator(symbolTable, new AddressIndexPrimaryKeyIterator(symbolTable,
				SYMBOL_ADDR_COL, addrMap, set, forward));
		return new V2ConvertedRecordIterator(it);
	}

	@Override
	RecordIterator getPrimarySymbols(AddressSetView set, boolean forward) throws IOException {
		KeyToRecordIterator it =
			new KeyToRecordIterator(symbolTable, new AddressIndexPrimaryKeyIterator(symbolTable,
				SYMBOL_ADDR_COL, addrMap, set, forward));

		return getPrimaryFilterRecordIterator(new V2ConvertedRecordIterator(it));
	}

	@Override
	DBRecord getPrimarySymbol(Address address) throws IOException {
		RecordIterator it = getPrimarySymbols(new AddressSet(address, address), true);
		if (it.hasNext()) {
			return it.next();
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
		long addrKey = rec.getLongValue(V2_SYMBOL_ADDR_COL);
		Address addr = addrMap.decodeAddress(addrKey);
		if (addr == null || !addr.isExternalAddress()) {
			return null;
		}
		byte symbolTypeId = rec.getByteValue(V2_SYMBOL_TYPE_COL);
		if (symbolTypeId != SYMBOL_TYPE_FUNCTION && symbolTypeId != SYMBOL_TYPE_LABEL) {
			// NOTE: I don't think external functions were supported with this version
			return null;
		}

		return rec.getString(V2_SYMBOL_DATA3_COL);
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
					return convertV2Record(rec);
				}
			}
			return null;
		});
	}

	@Override
	RecordIterator getExternalSymbolsByOriginalImportName(String extLabel) throws IOException {
		return EmptyRecordIterator.INSTANCE;
	}

	@Override
	RecordIterator getSymbolsByNamespace(long id) throws IOException {
		LongField field = new LongField(id);
		RecordIterator it = symbolTable.indexIterator(SYMBOL_PARENT_ID_COL, field, field, true);
		return new V2ConvertedRecordIterator(it);
	}

	@Override
	RecordIterator getSymbolsByName(String name) throws IOException {
		StringField field = new StringField(name);
		RecordIterator it = symbolTable.indexIterator(SYMBOL_NAME_COL, field, field, true);
		return new V2ConvertedRecordIterator(it);
	}

	@Override
	RecordIterator scanSymbolsByName(String startName) throws IOException {
		StringField field = new StringField(startName);
		RecordIterator it = symbolTable.indexIterator(SYMBOL_NAME_COL, field, null, true);
		return new V2ConvertedRecordIterator(it);
	}

	@Override
	RecordIterator getSymbolsByNameAndNamespace(String name, long id) throws IOException {
		RecordIterator it = scanSymbolsByName(name);
		RecordIterator filtered = getNameAndNamespaceFilterIterator(name, id, it);
		return new V2ConvertedRecordIterator(filtered);
	}

	@Override
	DBRecord getSymbolRecord(Address address, String name, long id) throws IOException {
		RecordIterator it = scanSymbolsByName(name);
		long addressKey = addrMap.getKey(address, false);
		RecordIterator filtered = getNameNamespaceAddressFilterIterator(name, id, addressKey, it);
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
	private DBRecord convertV2Record(DBRecord record) {
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

	private class V2ConvertedRecordIterator extends ConvertedRecordIterator {

		V2ConvertedRecordIterator(RecordIterator originalIterator) {
			super(originalIterator, false);
		}

		@Override
		protected DBRecord convertRecord(DBRecord record) {
			return convertV2Record(record);
		}
	}

}
