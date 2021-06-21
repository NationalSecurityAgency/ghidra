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
import ghidra.program.database.map.AddressIndexPrimaryKeyIterator;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * <code>SymbolDatabaseAdapterV0</code> handles symbol tables which were created 
 * prior to the addition of Namespace support and Function symbols.  Function symbols 
 * are synthesized for those functions whose entry point currently has a 
 * label symbol.  The ID of these synthesized function symbols is the max ID plus 
 * the function ID.  The function Namespace ID is the same as the Function ID.
 * The upgrade of this version may also add additional Function symbols for which there
 * is no corresponding label symbol.
 */
class SymbolDatabaseAdapterV0 extends SymbolDatabaseAdapter {

/* Do not remove the following commented out schema! It shows the version 0 symbol table schema. */
//	static final Schema SYMBOL_SCHEMA = new Schema(0, "Key", 
//			new Class[] {StringField.class,
//				BooleanField.class, BooleanField.class,
//				BooleanField.class, LongField.class},
//			new String[] {"Name", "Is Dynamic", "Is Local",
//				"Is Primary", "Address"});

	private static final int SYMBOL_VERSION = 0;

	private static final int V0_SYMBOL_NAME_COL = 0;
	private static final int V0_SYMBOL_IS_DYNAMIC_COL = 1;
	private static final int V0_SYMBOL_LOCAL_COL = 2;
	private static final int V0_SYMBOL_PRIMARY_COL = 3;
	private static final int V0_SYMBOL_ADDR_COL = 4;

	private Table symbolTable;
	private AddressMap addrMap;

	/**
	 * Construct a Version-0 Symbol Table adapter.
	 * @param handle the database handle.
	 * @param addrMap the address map
	 * @throws VersionException if the database version doesn't match this adapter.
	 */
	SymbolDatabaseAdapterV0(DBHandle handle, AddressMap addrMap) throws VersionException {
		this.addrMap = addrMap.getOldAddressMap();
		symbolTable = handle.getTable(SYMBOL_TABLE_NAME);
		if (symbolTable == null) {
			throw new VersionException("Missing Table: " + SYMBOL_TABLE_NAME);
		}
		if (symbolTable.getSchema().getVersion() != SYMBOL_VERSION) {
			throw new VersionException(false);
		}
	}

	/**
	 * Stores local symbols information in a temporary database table because this version
	 * is so old, we don't have enough information in the record to upgrade during the normal
	 * upgrade time. So we store off the information and will complete this upgrade when
	 * {@link SymbolManager#programReady(int, int, TaskMonitor)} is called
	 * 
	 * @param handle handle to temporary database
	 * @param monitor the {@link TaskMonitor}
	 * @return the next available database key after all the records are store
	 * @throws IOException if a database I/O error occurs
	 * @throws CancelledException if the user cancels the upgrade
	 */
	long extractLocalSymbols(DBHandle handle, TaskMonitor monitor)
			throws IOException, CancelledException {

		monitor.setMessage("Extracting Local Symbols...");
		monitor.initialize(symbolTable.getRecordCount());
		int cnt = 0;
		RecordIterator iter = symbolTable.iterator();
		while (iter.hasNext()) {
			monitor.checkCanceled();
			DBRecord rec = iter.next();
			if (rec.getBooleanValue(V0_SYMBOL_LOCAL_COL)) {
				SymbolManager.saveLocalSymbol(handle, rec.getKey(),
					rec.getLongValue(V0_SYMBOL_ADDR_COL), rec.getString(V0_SYMBOL_NAME_COL),
					rec.getBooleanValue(V0_SYMBOL_PRIMARY_COL));
			}
			monitor.setProgress(++cnt);
		}
		return symbolTable.getKey();
	}

	private DBRecord convertRecord(DBRecord record) {
		if (record == null) {
			return null;
		}
		if (record.getBooleanValue(V0_SYMBOL_IS_DYNAMIC_COL) ||
			record.getBooleanValue(V0_SYMBOL_LOCAL_COL)) {
			throw new AssertException("Unexpected Symbol");
		}
		DBRecord rec = SymbolDatabaseAdapter.SYMBOL_SCHEMA.createRecord(record.getKey());

		String symbolName = record.getString(V0_SYMBOL_NAME_COL);
		rec.setString(SymbolDatabaseAdapter.SYMBOL_NAME_COL, symbolName);
		long addressKey = record.getLongValue(V0_SYMBOL_ADDR_COL);
		rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_ADDR_COL,
			addressKey);

		boolean isPrimary = record.getBooleanValue(V0_SYMBOL_PRIMARY_COL);
		if (isPrimary) {
			rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_PRIMARY_COL, addressKey);
		}

		rec.setByteValue(SymbolDatabaseAdapter.SYMBOL_TYPE_COL, SymbolType.LABEL.getID());

		long namespaceId = Namespace.GLOBAL_NAMESPACE_ID;
		rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_PARENT_COL, namespaceId);

		rec.setByteValue(SymbolDatabaseAdapter.SYMBOL_FLAGS_COL,
			(byte) SourceType.USER_DEFINED.ordinal());

		Field hash = computeLocatorHash(symbolName, namespaceId, addressKey);
		rec.setField(SymbolDatabaseAdapter.SYMBOL_HASH_COL, hash);

		return rec;
	}

	@Override
	DBRecord createSymbol(String name, Address address, long namespaceID, SymbolType symbolType,
			String stringData, Long dataTypeId, Integer varOffset, SourceType source,
			boolean isPrimary) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	void removeSymbol(long symbolID) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	boolean hasSymbol(Address addr) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	Field[] getSymbolIDs(Address addr) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	DBRecord getSymbolRecord(long symbolID) throws IOException {
		return convertRecord(symbolTable.getRecord(symbolID));
	}

	@Override
	int getSymbolCount() {
		return symbolTable.getRecordCount();
	}

	@Override
	RecordIterator getSymbolsByAddress(boolean forward) throws IOException {
		return new V0ConvertedRecordIterator(new KeyToRecordIterator(symbolTable,
			new AddressIndexPrimaryKeyIterator(symbolTable, V0_SYMBOL_ADDR_COL, addrMap, forward)));
	}

	@Override
	RecordIterator getSymbolsByAddress(Address startAddr, boolean forward) throws IOException {
		return new V0ConvertedRecordIterator(
			new KeyToRecordIterator(symbolTable, new AddressIndexPrimaryKeyIterator(symbolTable,
				V0_SYMBOL_ADDR_COL, addrMap, startAddr, forward)));
	}

	@Override
	void updateSymbolRecord(DBRecord record) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	RecordIterator getSymbols() throws IOException {
		return new V0ConvertedRecordIterator(symbolTable.iterator());
	}

	@Override
	RecordIterator getSymbols(Address start, Address end, boolean forward) throws IOException {
		return new V0ConvertedRecordIterator(
			new KeyToRecordIterator(symbolTable, new AddressIndexPrimaryKeyIterator(symbolTable,
				V0_SYMBOL_ADDR_COL, addrMap, start, end, forward)));
	}

	@Override
	RecordIterator getSymbols(AddressSetView set, boolean forward) throws IOException {
		return new V0ConvertedRecordIterator(
			new KeyToRecordIterator(symbolTable, new AddressIndexPrimaryKeyIterator(symbolTable,
				V0_SYMBOL_ADDR_COL, addrMap, set, forward)));
	}

	@Override
	RecordIterator getPrimarySymbols(AddressSetView set, boolean forward)
			throws IOException {
		KeyToRecordIterator it =
			new KeyToRecordIterator(symbolTable, new AddressIndexPrimaryKeyIterator(symbolTable,
				SYMBOL_ADDR_COL, addrMap, set, forward));

		return getPrimaryFilterRecordIterator(new V0ConvertedRecordIterator(it));
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

	@Override
	RecordIterator getSymbolsByNamespace(long id) throws IOException {

		if (id == Namespace.GLOBAL_NAMESPACE_ID) {
			return new V0ConvertedRecordIterator(symbolTable.iterator());
		}
		return null;
	}

	@Override
	RecordIterator getSymbolsByName(String name) throws IOException {
		StringField val = new StringField(name);
		return new V0ConvertedRecordIterator(
			symbolTable.indexIterator(V0_SYMBOL_NAME_COL, val, val, true));
	}

	private class V0ConvertedRecordIterator implements RecordIterator {

		private RecordIterator symIter;
		private DBRecord rec;

		/**
		 * Construct a symbol filtered record iterator
		 * @param symIter the {@link RecordIterator} to wrap so that records are adapter to new schema
		 */
		V0ConvertedRecordIterator(RecordIterator symIter) {
			this.symIter = symIter;
		}

		@Override
		public boolean hasNext() throws IOException {
			if (rec == null) {
				while (rec == null && symIter.hasNext()) {
					rec = symIter.next();
					if (rec.getBooleanValue(V0_SYMBOL_LOCAL_COL) ||
						rec.getBooleanValue(V0_SYMBOL_IS_DYNAMIC_COL)) {
						rec = null;
					}
				}
			}
			return rec != null;
		}

		@Override
		public boolean hasPrevious() throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		public DBRecord next() throws IOException {
			if (hasNext()) {
				DBRecord r = rec;
				rec = null;
				return convertRecord(r);
			}
			return null;
		}

		@Override
		public DBRecord previous() throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean delete() throws IOException {
			throw new UnsupportedOperationException();
		}

	}

	@Override
	Table getTable() {
		throw new UnsupportedOperationException();
	}

	@Override
	Address getMaxSymbolAddress(AddressSpace space) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	RecordIterator getSymbolsByNameAndNamespace(String name, long id) throws IOException {
		RecordIterator symbolsByName = getSymbolsByName(name);
		return getNameAndNamespaceFilterIterator(name, id, symbolsByName);
	}

	@Override
	DBRecord getSymbolRecord(Address address, String name, long id) throws IOException {
		StringField value = new StringField(name);
		RecordIterator it = symbolTable.indexIterator(SYMBOL_NAME_COL, value, value, true);
		long addressKey = addrMap.getKey(address, false);
		RecordIterator filtered =
			getNameNamespaceAddressFilterIterator(name, id, addressKey, it);
		if (filtered.hasNext()) {
			return filtered.next();
		}
		return null;
	}

}
