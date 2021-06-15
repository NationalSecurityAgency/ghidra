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
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Adapter to access records in the equate references table.
 * 
 * 
 */
abstract class EquateRefDBAdapter {

	static final String EQUATE_REFS_TABLE_NAME = "Equate References";

	static final Schema REFS_SCHEMA = new Schema(1, "Key",
		new Field[] { LongField.INSTANCE, LongField.INSTANCE, ShortField.INSTANCE,
			LongField.INSTANCE },
		new String[] { "Equate ID", "Equate Reference", "Operand Index", "Varnode Hash" });

	static final int EQUATE_ID_COL = 0;
	static final int ADDR_COL = 1;
	static final int OP_INDEX_COL = 2;
	static final int HASH_COL = 3;

	static EquateRefDBAdapter getAdapter(DBHandle dbHandle, int openMode, AddressMap addrMap,
			TaskMonitor monitor) throws VersionException, IOException {

		if (openMode == DBConstants.CREATE) {
			return new EquateRefDBAdapterV1(dbHandle, addrMap, true);
		}

		try {
			EquateRefDBAdapter adapter = new EquateRefDBAdapterV1(dbHandle, addrMap, false);
			if (addrMap.isUpgraded()) {
				throw new VersionException(true);
			}
			return adapter;
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			EquateRefDBAdapter adapter = findReadOnlyAdapter(dbHandle, addrMap);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(dbHandle, addrMap, adapter, monitor);
			}
			return adapter;
		}
	}

	private static EquateRefDBAdapter findReadOnlyAdapter(DBHandle handle, AddressMap addrMap)
			throws VersionException, IOException {

		try {
			return new EquateRefDBAdapterV1(handle, addrMap, false);
		}
		catch (VersionException e1) {
		}

		return new EquateRefDBAdapterV0(handle, addrMap);
	}

	private static EquateRefDBAdapter upgrade(DBHandle dbHandle, AddressMap addrMap,
			EquateRefDBAdapter oldAdapter, TaskMonitor monitor)
			throws VersionException, IOException {

		AddressMap oldAddrMap = addrMap.getOldAddressMap();

		DBHandle tmpHandle = new DBHandle();
		try {
			tmpHandle.startTransaction();

			monitor.setMessage("Upgrading Equate References...");
			monitor.initialize(oldAdapter.getRecordCount() * 2);

			EquateRefDBAdapter tmpAdapter = new EquateRefDBAdapterV1(tmpHandle, addrMap, true);
			RecordIterator iter = oldAdapter.getRecords();
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				Address addr = oldAddrMap.decodeAddress(rec.getLongValue(ADDR_COL));
				rec.setLongValue(ADDR_COL, addrMap.getKey(addr, true));
				rec.setLongValue(HASH_COL, 0);
				tmpAdapter.updateRecord(rec);
			}

			dbHandle.deleteTable(EQUATE_REFS_TABLE_NAME);
			EquateRefDBAdapter newAdapter = new EquateRefDBAdapterV1(dbHandle, addrMap, true);

			iter = tmpAdapter.getRecords();
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				newAdapter.updateRecord(rec);
			}
			return newAdapter;
		}
		finally {
			tmpHandle.close();
		}
	}

	/**
	 * Create a reference to an equate.
	 * @param addr address of the reference
	 * @param opIndex operand index
	 * @param dynamicHash dynamicHash associated with constant varnode
	 * @param equateNameID ID for the equate
	 * @return new record
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord createReference(long addr, short opIndex, long dynamicHash, long equateNameID)
			throws IOException;

	/**
	 * Get the record for the given key.
	 * @param the key of the record to retrieve.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord getRecord(long key) throws IOException;

	/**
	 * Get an iterator over all the equate reference records.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getRecords() throws IOException;

	/**
	 * Returns record count
	 */
	abstract int getRecordCount();

	/**
	 * Get the records for the given addr value.
	 * @param addr the address to find equates for.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract Field[] getRecordKeysForAddr(long addr) throws IOException;

	/**
	 * Update the table with the given record.
	 * @param record the record to update.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void updateRecord(DBRecord record) throws IOException;

	/**
	 * Get the records that have the given equateID.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract Field[] getRecordKeysForEquateID(long equateID) throws IOException;

	/**
	 * Get an iterator over the addresses.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBLongIterator getIteratorForAddresses() throws IOException;

	/**
	 * Get an iterator over the addresses in the given range.
	 * @param start the first address in the range.
	 * @param end the last address in the range.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBLongIterator getIteratorForAddresses(Address start, Address end) throws IOException;

	/**
	 * Get an iterator over an addresses set.
	 * @param set the set of addresses to consider.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBLongIterator getIteratorForAddresses(AddressSetView set) throws IOException;

	/**
	 * Get an iterator over the addresses starting at the given value.
	 * @param start the address at which to start iterating
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBLongIterator getIteratorForAddresses(Address start) throws IOException;

	/**
	 * Remove the record with the given key. 
	 * @param key the key of the record to remove.
	 * @throws if there was a problem accessing the database
	 */
	abstract void removeRecord(long key) throws IOException;

	/**
	 * Update the addresses in all records to reflect the movement of a memory block.
	 * @param fromAddr minimum address of the original block to be moved
	 * @param toAddr the new minimum address after the block move
	 * @param length the number of bytes in the memory block being moved
	 * @param monitor progress monitor
	 * @throws CancelledException if the user cancelled the operation.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void moveAddressRange(Address fromAddr, Address toAddr, long length,
			TaskMonitor monitor) throws CancelledException, IOException;

}
