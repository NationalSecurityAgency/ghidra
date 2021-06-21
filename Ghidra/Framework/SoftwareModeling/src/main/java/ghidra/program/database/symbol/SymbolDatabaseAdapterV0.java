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
/*
 *
 */
package ghidra.program.database.symbol;

import java.io.IOException;
import java.util.Set;

import db.*;
import ghidra.program.database.map.AddressIndexPrimaryKeyIterator;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
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
	 * Construct a Version-0 Symbol Table adadpter.
	 * @param handle the database handle.
	 * @param addrMap the address map
	 * @param namespaceMgr namespace manager which already contains function namespaces
	 * @throws VersionException if the database version doesn't match this adapter.
	 * @throws IOException if a database io error occurs.
	 * @throws CancelledException if the user cancels the upgrade.
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

	long extractLocalSymbols(DBHandle handle, TaskMonitor monitor)
			throws IOException, CancelledException {

		monitor.setMessage("Extracting Local and Dynamic Symbols...");
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
		rec.setString(SymbolDatabaseAdapter.SYMBOL_NAME_COL, record.getString(V0_SYMBOL_NAME_COL));
		rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_ADDR_COL,
			record.getLongValue(V0_SYMBOL_ADDR_COL));
		rec.setIntValue(SymbolDatabaseAdapter.SYMBOL_DATA2_COL,
			record.getBooleanValue(V0_SYMBOL_PRIMARY_COL) ? 1 : 0);
		rec.setByteValue(SymbolDatabaseAdapter.SYMBOL_TYPE_COL, SymbolType.LABEL.getID());
		rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_DATA1_COL, -1); // not applicable
		rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_PARENT_COL, Namespace.GLOBAL_NAMESPACE_ID);
		rec.setByteValue(SymbolDatabaseAdapter.SYMBOL_FLAGS_COL,
			(byte) SourceType.USER_DEFINED.ordinal());
		return rec;
	}

	@Override
	DBRecord createSymbol(String name, Address address, long namespaceID, SymbolType symbolType,
			long data1, int data2, String data3, SourceType source) {
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

		if (!forward)
			throw new UnsupportedOperationException();
//TODO: Is there any reason we need to support reverse symbol iteration ???
		// Yes, to search text backwards!
		return new V0ConvertedRecordIterator(
			new KeyToRecordIterator(symbolTable, new AddressIndexPrimaryKeyIterator(symbolTable,
				V0_SYMBOL_ADDR_COL, addrMap, start, end, forward)));
	}

	void deleteExternalEntries(Address start, Address end) {
		throw new UnsupportedOperationException();
	}

	@Override
	void moveAddress(Address oldAddr, Address newAddr) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException, IOException {
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
		 * @param iter
		 * @param locals if true 
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

}
