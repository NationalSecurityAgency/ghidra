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
import ghidra.program.database.map.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * SymbolDatabaseAdapter for version 1
 */
class SymbolDatabaseAdapterV1 extends SymbolDatabaseAdapter {

/* Do not remove the following commented out schema! It shows the version 1 symbol table schema. */
//	static final Schema SYMBOL_SCHEMA = new Schema(1, "Key", 
//			new Class[] {StringField.class,
//				LongField.class, LongField.class, ByteField.class,
//				LongField.class, IntField.class, StringField.class},
//			new String[] {"Name", "Address", "Parent", "Symbol Type",
//						  "SymbolData1", "SymbolData2", "Comment"});

	private static final int SYMBOL_VERSION = 1;

	private static final int V1_SYMBOL_NAME_COL = 0;
	private static final int V1_SYMBOL_ADDR_COL = 1;
	private static final int V1_SYMBOL_PARENT_COL = 2;
	private static final int V1_SYMBOL_TYPE_COL = 3;
	private static final int V1_SYMBOL_DATA1_COL = 4;
	private static final int V1_SYMBOL_DATA2_COL = 5;
	private static final int V1_SYMBOL_COMMENT_COL = 6;

	private Table symbolTable;
	private AddressMap addrMap;

	SymbolDatabaseAdapterV1(DBHandle handle, AddressMap addrMap) throws VersionException {

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
		long key = addrMap.getKey(addr, false);
		if (key == AddressMap.INVALID_ADDRESS_KEY) {
			return false;
		}
		return symbolTable.hasRecord(new LongField(key), V1_SYMBOL_ADDR_COL);
	}

	@Override
	Field[] getSymbolIDs(Address addr) throws IOException {
		long key = addrMap.getKey(addr, false);
		if (key == AddressMap.INVALID_ADDRESS_KEY) {
			return Field.EMPTY_ARRAY;
		}
		return symbolTable.findRecords(new LongField(key), V1_SYMBOL_ADDR_COL);
	}

	@Override
	DBRecord getSymbolRecord(long symbolID) throws IOException {
		return convertV1Record(symbolTable.getRecord(symbolID));
	}

	/**
	 * Returns a record matching the current data base schema from the version 1 record.
	 * @param recV1 the record matching the version 1 schema.
	 * @return a current symbol record.
	 */
	private DBRecord convertV1Record(DBRecord record) {
		if (record == null) {
			return null;
		}
		DBRecord rec = SymbolDatabaseAdapter.SYMBOL_SCHEMA.createRecord(record.getKey());
		String symbolName = record.getString(V1_SYMBOL_NAME_COL);
		rec.setString(SymbolDatabaseAdapter.SYMBOL_NAME_COL, symbolName);
		long symbolAddrKey = record.getLongValue(V1_SYMBOL_ADDR_COL);
		rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_ADDR_COL, symbolAddrKey);
		rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_PARENT_COL,
			record.getLongValue(V1_SYMBOL_PARENT_COL));
		byte symbolType = record.getByteValue(V1_SYMBOL_TYPE_COL);
		rec.setByteValue(SymbolDatabaseAdapter.SYMBOL_TYPE_COL, symbolType);
		rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_DATA1_COL,
			record.getLongValue(V1_SYMBOL_DATA1_COL));
		rec.setIntValue(SymbolDatabaseAdapter.SYMBOL_DATA2_COL,
			record.getIntValue(V1_SYMBOL_DATA2_COL));
		rec.setString(SymbolDatabaseAdapter.SYMBOL_DATA3_COL,
			record.getString(V1_SYMBOL_COMMENT_COL));
		SourceType source = SourceType.USER_DEFINED;
		if (symbolType == SymbolType.FUNCTION.getID()) {
			Address symbolAddress = addrMap.decodeAddress(symbolAddrKey);
			String defaultName = SymbolUtilities.getDefaultFunctionName(symbolAddress);
			if (symbolName.equals(defaultName)) {
				source = SourceType.DEFAULT;
			}
		}
		rec.setByteValue(SymbolDatabaseAdapter.SYMBOL_FLAGS_COL, (byte) source.ordinal());
		return rec;
	}

	@Override
	int getSymbolCount() {
		return symbolTable.getRecordCount();
	}

	@Override
	RecordIterator getSymbolsByAddress(boolean forward) throws IOException {
		return new V1ConvertedRecordIterator(new KeyToRecordIterator(symbolTable,
			new AddressIndexPrimaryKeyIterator(symbolTable, V1_SYMBOL_ADDR_COL, addrMap, forward)));
	}

	@Override
	RecordIterator getSymbolsByAddress(Address startAddr, boolean forward) throws IOException {
		return new V1ConvertedRecordIterator(
			new KeyToRecordIterator(symbolTable, new AddressIndexPrimaryKeyIterator(symbolTable,
				V1_SYMBOL_ADDR_COL, addrMap, startAddr, forward)));
	}

	@Override
	void updateSymbolRecord(DBRecord record) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	RecordIterator getSymbols() throws IOException {
		return new V1ConvertedRecordIterator(symbolTable.iterator());
	}

	@Override
	RecordIterator getSymbols(Address start, Address end, boolean forward) throws IOException {
		return new V1ConvertedRecordIterator(
			new KeyToRecordIterator(symbolTable, new AddressIndexPrimaryKeyIterator(symbolTable,
				V1_SYMBOL_ADDR_COL, addrMap, start, end, forward)));
	}

	RecordIterator getSymbolsByName() throws IOException {
		return new V1ConvertedRecordIterator(symbolTable.indexIterator(V1_SYMBOL_NAME_COL));
	}

	void deleteExternalEntries(Address start, Address end) throws IOException {
		AddressRecordDeleter.deleteRecords(symbolTable, V1_SYMBOL_ADDR_COL, addrMap, start, end,
			null);
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
		LongField field = new LongField(id);
		return new V1ConvertedRecordIterator(
			symbolTable.indexIterator(V1_SYMBOL_PARENT_COL, field, field, true));
	}

	@Override
	RecordIterator getSymbolsByName(String name) throws IOException {
		StringField field = new StringField(name);
		return new V1ConvertedRecordIterator(
			symbolTable.indexIterator(V1_SYMBOL_NAME_COL, field, field, true));
	}

	private class V1ConvertedRecordIterator extends ConvertedRecordIterator {

		V1ConvertedRecordIterator(RecordIterator originalIterator) {
			super(originalIterator, false);
		}

		@Override
		protected DBRecord convertRecord(DBRecord record) {
			return convertV1Record(record);
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
