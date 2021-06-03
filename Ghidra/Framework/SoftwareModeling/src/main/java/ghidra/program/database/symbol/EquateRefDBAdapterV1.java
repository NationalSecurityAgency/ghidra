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
import ghidra.program.database.util.DatabaseTableUtils;
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
class EquateRefDBAdapterV1 extends EquateRefDBAdapter {

	private Table refTable;
	private AddressMap addrMap;

	/**
	 * Constructor
	 * 
	 */
	EquateRefDBAdapterV1(DBHandle handle, AddressMap addrMap, boolean create)
			throws IOException, VersionException {
		this.addrMap = addrMap;
		if (create) {
			refTable = handle.createTable(EQUATE_REFS_TABLE_NAME, REFS_SCHEMA,
				new int[] { EQUATE_ID_COL, ADDR_COL });
		}
		else {
			refTable = handle.getTable(EQUATE_REFS_TABLE_NAME);
			if (refTable == null) {
				throw new VersionException("Missing Table: " + EQUATE_REFS_TABLE_NAME);
			}
			int version = refTable.getSchema().getVersion();
			if (version != 1) {
				if (version < 1) {
					throw new VersionException(true);
				}
				throw new VersionException(VersionException.NEWER_VERSION, false);
			}
		}
	}

	/**
	 * @see ghidra.program.database.symbol.EquateRefDBAdapter#getRecord(long)
	 */
	@Override
	DBRecord getRecord(long key) throws IOException {
		return refTable.getRecord(key);
	}

	/**
	 * @see ghidra.program.database.symbol.EquateRefDBAdapter#createReference(long, short, long, long)
	 */
	@Override
	DBRecord createReference(long addr, short opIndex, long dynamicHash, long equateID)
			throws IOException {
		DBRecord rec = refTable.getSchema().createRecord(refTable.getKey());
		rec.setLongValue(ADDR_COL, addr);
		rec.setShortValue(OP_INDEX_COL, opIndex);
		rec.setLongValue(HASH_COL, dynamicHash);
		rec.setLongValue(EQUATE_ID_COL, equateID);
		refTable.putRecord(rec);
		return rec;
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
		refTable.putRecord(record);
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
		refTable.deleteRecord(key);
	}

	/**
	 * @see ghidra.program.database.symbol.EquateRefDBAdapter#getRecords()
	 */
	@Override
	RecordIterator getRecords() throws IOException {
		return refTable.iterator();
	}

	/**
	 * @see ghidra.program.database.symbol.EquateRefDBAdapter#moveAddressRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address, long, ghidra.program.database.map.AddressMapDB, ghidra.util.task.TaskMonitor)
	 */
	@Override
	void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException, IOException {
		DatabaseTableUtils.updateIndexedAddressField(refTable, ADDR_COL, addrMap, fromAddr, toAddr,
			length, null, monitor);
	}

	/**
	 * @see ghidra.program.database.symbol.EquateRefDBAdapter#getRecordCount()
	 */
	@Override
	int getRecordCount() {
		return refTable.getRecordCount();
	}

}
