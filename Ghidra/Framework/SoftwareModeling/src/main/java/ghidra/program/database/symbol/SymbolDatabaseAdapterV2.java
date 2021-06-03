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
import ghidra.program.database.util.DatabaseTableUtils;
import ghidra.program.database.util.RecordFilter;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * SymbolDatabaseAdapter for version 2
 */
class SymbolDatabaseAdapterV2 extends SymbolDatabaseAdapter {

	private static final int SYMBOL_VERSION = 2;
	private Table symbolTable;
	private AddressMap addrMap;

	SymbolDatabaseAdapterV2(DBHandle handle, AddressMap addrMap, boolean create)
			throws VersionException, IOException {

		this.addrMap = addrMap;
		if (create) {

			symbolTable = handle.createTable(SYMBOL_TABLE_NAME, SYMBOL_SCHEMA,
				new int[] { SYMBOL_ADDR_COL, SYMBOL_NAME_COL, SYMBOL_PARENT_COL });
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

	static SymbolDatabaseAdapter upgrade(DBHandle dbHandle, AddressMap addrMap,
			SymbolDatabaseAdapter oldAdapter, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {

		AddressMap oldAddrMap = addrMap.getOldAddressMap();

		DBHandle tmpHandle = dbHandle.getScratchPad();
		long nextKey = 1;
		try {
			if (oldAdapter instanceof SymbolDatabaseAdapterV0) {
				// Defer upgrade of local symbols and remove dynamic symbols
				nextKey =
					((SymbolDatabaseAdapterV0) oldAdapter).extractLocalSymbols(tmpHandle, monitor);
			}

			monitor.setMessage("Upgrading Symbol Table...");
			monitor.initialize((oldAdapter.getSymbolCount()) * 2);
			int count = 0;

			SymbolDatabaseAdapterV2 tmpAdapter =
				new SymbolDatabaseAdapterV2(tmpHandle, addrMap, true);
			RecordIterator iter = oldAdapter.getSymbols();
			DBRecord zeroRecord = null;
			while (iter.hasNext()) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				DBRecord rec = iter.next();
				Address addr = oldAddrMap.decodeAddress(rec.getLongValue(SYMBOL_ADDR_COL));
				rec.setLongValue(SYMBOL_ADDR_COL, addrMap.getKey(addr, true));
				if (rec.getKey() == 0) {
					zeroRecord = rec;
				}
				else {
					tmpAdapter.symbolTable.putRecord(rec);
				}
				monitor.setProgress(++count);
			}
			if (zeroRecord != null) {
				tmpAdapter.createSymbol(Math.max(1, nextKey), zeroRecord);
			}
			// TODO keep this until I fix up SymbolManager
//			AddressKeyIterator entryPts = oldAdapter.getExternalEntryInterator();
//			while (entryPts.hasNext()) {
//				if (monitor.isCancelled()) {
//					throw new CancelledException();
//				}
//				Address addr = oldAddrMap.decodeAddress(entryPts.next());
//				tmpAdapter.setExternalEntry(addr);
//				monitor.setProgress(++count);
//			}

			dbHandle.deleteTable(SYMBOL_TABLE_NAME);
			SymbolDatabaseAdapterV2 newAdapter =
				new SymbolDatabaseAdapterV2(dbHandle, addrMap, true);

			iter = tmpAdapter.getSymbols();
			while (iter.hasNext()) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				DBRecord rec = iter.next();

				// Make sure user symbols do not start with reserved prefix
				String name = rec.getString(SYMBOL_NAME_COL);
				if (SymbolUtilities.startsWithDefaultDynamicPrefix(name)) {
					rec.setString(SYMBOL_NAME_COL,
						fixSymbolName(tmpAdapter, name, rec.getLongValue(SYMBOL_PARENT_COL)));
				}

				// TODO May want to check for default name to set flags when upgrading.
//				long addr = rec.getLongValue(SYMBOL_ADDR_COL);
//				Address address = addrMap.decodeAddress(addr);
//				String defaultName = ???;
//				byte flags = name.equals(defaultName) ? SYMBOL_DEFAULT_FLAG : SYMBOL_USER_DEFINED_FLAG;
//				rec.setByteValue(SYMBOL_FLAGS_COL, SYMBOL_USER_DEFINED_FLAG);

				newAdapter.symbolTable.putRecord(rec);
				monitor.setProgress(++count);
			}
			return newAdapter;
		}
		finally {
			tmpHandle.deleteTable(SYMBOL_TABLE_NAME);
		}
	}

	/**
	 * @param zeroRecord
	 * @throws IOException
	 */
	private void createSymbol(long nextKey, DBRecord zeroRecord) throws IOException {
		zeroRecord.setKey(nextKey);
		symbolTable.putRecord(zeroRecord);
	}

	private static String fixSymbolName(SymbolDatabaseAdapter tmpAdapter, String name,
			long namespaceId) throws IOException {
		String baseName = "_" + name; // dynamic prefix is reserved
		String newName = baseName;
		int cnt = 0;
		while (true) {
			try {
				RecordIterator iter = tmpAdapter.getSymbolsByName(newName);
				while (iter.hasNext()) {
					DBRecord otherRec = iter.next();
					if (namespaceId == otherRec.getLongValue(SYMBOL_PARENT_COL)) {
						throw new DuplicateNameException();
					}
				}
				return newName;
			}
			catch (DuplicateNameException e) {
				newName = baseName + "_" + (++cnt);
			}
		}
	}

	@Override
	DBRecord createSymbol(String name, Address address, long namespaceID, SymbolType symbolType,
			long data1, int data2, String data3, SourceType source) throws IOException {
		long nextID = symbolTable.getKey();

		// avoiding key 0, because we use the negative of the address offset as keys for dynamic symbols
		if (nextID == 0) {
			nextID++;
		}
		return createSymbol(nextID, name, address, namespaceID, symbolType, data1, data2, data3,
			(byte) source.ordinal());
	}

	private DBRecord createSymbol(long id, String name, Address address, long namespaceID,
			SymbolType symbolType, long data1, int data2, String data3, byte flags)
			throws IOException {

		DBRecord rec = symbolTable.getSchema().createRecord(id);
		rec.setString(SYMBOL_NAME_COL, name);
		rec.setLongValue(SYMBOL_ADDR_COL, addrMap.getKey(address, true));
		rec.setLongValue(SYMBOL_PARENT_COL, namespaceID);
		rec.setByteValue(SYMBOL_TYPE_COL, symbolType.getID());
		rec.setLongValue(SYMBOL_DATA1_COL, data1);
		rec.setIntValue(SYMBOL_DATA2_COL, data2);
		rec.setString(SYMBOL_DATA3_COL, data3);
		rec.setByteValue(SYMBOL_FLAGS_COL, flags);
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
	void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException, IOException {

		DatabaseTableUtils.updateIndexedAddressField(symbolTable, SYMBOL_ADDR_COL, addrMap,
			fromAddr, toAddr, length, null, monitor);
	}

	@Override
	Set<Address> deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException, IOException {

		AnchoredSymbolRecordFilter filter = new AnchoredSymbolRecordFilter();
		AddressRecordDeleter.deleteRecords(symbolTable, SYMBOL_ADDR_COL, addrMap, startAddr,
			endAddr, filter);

		return filter.getAddressesForSkippedRecords();
	}

	class AnchoredSymbolRecordFilter implements RecordFilter {
		private Set<Address> set = new HashSet<Address>();

		@Override
		public boolean matches(DBRecord record) {
			// only move symbols whose anchor flag is not on
			Address addr = addrMap.decodeAddress(record.getLongValue(SYMBOL_ADDR_COL));
			byte flags = record.getByteValue(SymbolDatabaseAdapter.SYMBOL_FLAGS_COL);
			if (((flags & SymbolDatabaseAdapter.SYMBOL_PINNED_FLAG) == 0)) {
				return true;
			}
			set.add(addr);
			return false;
		}

		Set<Address> getAddressesForSkippedRecords() {
			return set;
		}
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
}
