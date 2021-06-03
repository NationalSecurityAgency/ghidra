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
import ghidra.program.database.map.AddressIndexKeyIterator;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Implementation for Version 0 of the equate references table.
 * 
 * 
 */
class EquateRefDBAdapterV0 extends EquateRefDBAdapter {

	private Table refTable;
	private AddressMap addrMap;

	static final int V0_EQUATE_ID_COL = 0;
	static final int V0_ADDR_COL = 1;
	static final int V0_OP_INDEX_COL = 2;

	/**
	 * Constructor
	 * 
	 */
	EquateRefDBAdapterV0(DBHandle handle, AddressMap addrMap) throws VersionException {
		this.addrMap = addrMap;
		refTable = handle.getTable(EQUATE_REFS_TABLE_NAME);
		if (refTable == null) {
			throw new VersionException("Missing Table: " + EQUATE_REFS_TABLE_NAME);
		}
		if (refTable.getSchema().getVersion() != 0) {
			throw new VersionException(false);
		}
	}

	/**
	 * @see ghidra.program.database.symbol.EquateRefDBAdapter#getRecord(long)
	 */
	@Override
	DBRecord getRecord(long key) throws IOException {
		return convertV0Record(refTable.getRecord(key));
	}

	/**
	 * @see ghidra.program.database.symbol.EquateRefDBAdapter#createReference(long, short, long, long)
	 */
	@Override
	DBRecord createReference(long addr, short opIndex, long dynamicHash, long equateID) {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.symbol.EquateRefDBAdapter#getRecordKeysFrom(long)
	 */
	@Override
	Field[] getRecordKeysForAddr(long addr) throws IOException {
		return refTable.findRecords(new LongField(addr), ADDR_COL);
	}

	/**
	 * @see ghidra.program.database.symbol.EquateRefDBAdapter#updateRecord(ghidra.framework.store.db.DBRecord)
	 */
	@Override
	void updateRecord(DBRecord record) throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.symbol.EquateRefDBAdapter#getRecordsForEquateID(long)
	 */
	@Override
	Field[] getRecordKeysForEquateID(long equateID) throws IOException {
		return refTable.findRecords(new LongField(equateID), EQUATE_ID_COL);
	}

	/**
	 * @see ghidra.program.database.symbol.EquateRefDBAdapter#getIteratorForAddresses()
	 */
	@Override
	DBLongIterator getIteratorForAddresses() throws IOException {
		return new AddressIndexKeyIterator(refTable, ADDR_COL, addrMap, true);
	}

	/**
	 * @see ghidra.program.database.symbol.EquateRefDBAdapter#getIteratorForAddresses(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	DBLongIterator getIteratorForAddresses(Address start, Address end) throws IOException {
		return new AddressIndexKeyIterator(refTable, ADDR_COL, addrMap, start, end, true);
	}

	/**
	 * @see ghidra.program.database.symbol.EquateRefDBAdapter#getIteratorForAddresses(ghidra.program.model.address.Address)
	 */
	@Override
	DBLongIterator getIteratorForAddresses(Address start) throws IOException {
		return new AddressIndexKeyIterator(refTable, ADDR_COL, addrMap, start, true);
	}

	/**
	 * @see ghidra.program.database.symbol.EquateRefDBAdapter#getIteratorForAddresses(ghidra.program.model.address.AddressSetView)
	 */
	@Override
	DBLongIterator getIteratorForAddresses(AddressSetView set) throws IOException {
		return new AddressIndexKeyIterator(refTable, ADDR_COL, addrMap, set, true);
	}

	/**
	 * @see ghidra.program.database.symbol.EquateRefDBAdapter#removeRecord(long)
	 */
	@Override
	void removeRecord(long key) throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.symbol.EquateRefDBAdapter#getRecords()
	 */
	@Override
	RecordIterator getRecords() throws IOException {
		return new MyRecordConversionIterator(refTable.iterator());
	}

	/**
	 * @see ghidra.program.database.symbol.EquateRefDBAdapter#moveAddressRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address, long, ghidra.program.database.map.AddressMapDB, ghidra.util.task.TaskMonitor)
	 */
	@Override
	void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException, IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.symbol.EquateRefDBAdapter#getRecordCount()
	 */
	@Override
	int getRecordCount() {
		return refTable.getRecordCount();
	}

	private static DBRecord convertV0Record(DBRecord record) {
		if (record == null) {
			return null;
		}
		DBRecord newRec = REFS_SCHEMA.createRecord(record.getKey());
		newRec.setLongValue(EQUATE_ID_COL, record.getLongValue(V0_EQUATE_ID_COL));
		newRec.setLongValue(ADDR_COL, record.getLongValue(V0_ADDR_COL));
		newRec.setShortValue(OP_INDEX_COL, record.getShortValue(V0_OP_INDEX_COL));
		newRec.setLongValue(HASH_COL, 0);
		return newRec;
	}

	private static class MyRecordConversionIterator extends ConvertedRecordIterator {

		MyRecordConversionIterator(RecordIterator originalIterator) {
			super(originalIterator, false);
		}

		@Override
		protected DBRecord convertRecord(DBRecord record) {
			return convertV0Record(record);
		}
	}

}
