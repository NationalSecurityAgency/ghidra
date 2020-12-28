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
package ghidra.program.database.code;

import java.io.IOException;

import db.*;
import ghidra.program.database.map.AddressKeyIterator;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Adapter that accesses the instruction table.
 */
abstract class InstDBAdapter {

	static final String INSTRUCTION_TABLE_NAME = "Instructions";

	static final Schema INSTRUCTION_SCHEMA =
		new Schema(1, "Address", new Field[] { IntField.INSTANCE, ByteField.INSTANCE },
			new String[] { "Proto ID", "Flags" });

	static final int PROTO_ID_COL = 0;
	static final int FLAGS_COL = 1;

	static InstDBAdapter getAdapter(DBHandle dbHandle, int openMode, AddressMap addrMap,
			TaskMonitor monitor) throws VersionException, CancelledException, IOException {

		if (openMode == DBConstants.CREATE) {
			return new InstDBAdapterV1(dbHandle, addrMap, true);
		}

		try {
			InstDBAdapter adapter = new InstDBAdapterV1(dbHandle, addrMap, false);
			if (addrMap.isUpgraded()) {
				throw new VersionException(true);
			}
			return adapter;
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			InstDBAdapter adapter = findReadOnlyAdapter(dbHandle, addrMap);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(dbHandle, addrMap, adapter, monitor);
			}
			return adapter;
		}
	}

	private static InstDBAdapter findReadOnlyAdapter(DBHandle handle, AddressMap addrMap)
			throws VersionException, IOException {
		try {
			return new InstDBAdapterV1(handle, addrMap.getOldAddressMap(), false);
		}
		catch (VersionException e) {
		}

		return new InstDBAdapterV0(handle, addrMap);
	}

	private static InstDBAdapter upgrade(DBHandle dbHandle, AddressMap addrMap,
			InstDBAdapter oldAdapter, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {

		AddressMap oldAddrMap = addrMap.getOldAddressMap();

		DBHandle tmpHandle = new DBHandle();
		try {
			tmpHandle.startTransaction();

			monitor.setMessage("Upgrading Instructions...");
			monitor.initialize(oldAdapter.getRecordCount() * 2);
			int count = 0;

			InstDBAdapter tmpAdapter = new InstDBAdapterV1(tmpHandle, addrMap, true);
			RecordIterator iter = oldAdapter.getRecords();
			while (iter.hasNext()) {
				monitor.checkCanceled();
				DBRecord rec = iter.next();
				Address addr = oldAddrMap.decodeAddress(rec.getKey());
				rec.setKey(addrMap.getKey(addr, true));
				tmpAdapter.putRecord(rec);
				monitor.setProgress(++count);
			}

			dbHandle.deleteTable(INSTRUCTION_TABLE_NAME);
			InstDBAdapter newAdapter = new InstDBAdapterV1(dbHandle, addrMap, true);

			iter = tmpAdapter.getRecords();
			while (iter.hasNext()) {
				monitor.checkCanceled();
				DBRecord rec = iter.next();
				newAdapter.putRecord(rec);
				monitor.setProgress(++count);
			}
			return newAdapter;
		}
		finally {
			tmpHandle.close();
		}
	}

	/**
	 * Create a new instruction.
	 * @param addr address (key for the record)
	 * @param protoID prototype ID
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void createInstruction(long addr, int protoID, byte flags) throws IOException;

	/**
	 * Sets the flag column in the record at addr to the give flags byte.
	 * @param addr key of the record to be changed.
	 * @param flags the flags byte to be stored in the record.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void updateFlags(long addr, byte flags) throws IOException;

	/**
	 * Remove the instruction.
	 * @param addr address (key for the record)
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void deleteRecord(long addr) throws IOException;

	/**
	 * Returns the next record at or after the given address key
	 * @param addr the address to begin the search.
	 * @return the next record or null.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord getRecordAtOrAfter(Address addr) throws IOException;

	/**
	 * Returns the next record after the given address key
	 * @param addr the address to begin the search.
	 * @return the next record or null.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord getRecordAfter(Address addr) throws IOException;

	/**
	 * Returns the record at the given key or null if none exists.
	 * @param addr the key.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord getRecord(long addr) throws IOException;

	/**
	 * Returns the record at the given address or null if none exists.
	 * @param addr the address to use as the key
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord getRecord(Address addr) throws IOException;

	/**
	 * Returns the record just before the given address key.
	 * @param addr the address to begin the search.
	 * @return the previous record or null.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord getRecordBefore(Address addr) throws IOException;

	/**
	 * Returns a record iterator over all records in the given range.
	 * @param start the start of the range.
	 * @param end the end of the range.
	 * @param atStart if true, positions the iterator before start, otherwise after end.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getRecords(Address start, Address end, boolean atStart)
			throws IOException;

	/**
	 * Returns an iterator over all records.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getRecords() throws IOException;

	/**
	 * Returns the total number of records in this adapter.
	 */
	abstract int getRecordCount() throws IOException;

	/**
	 * Returns the next record at or before the given address key
	 * @param addr the address to begin the search.
	 * @return the previous record or null.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord getRecordAtOrBefore(Address addr) throws IOException;

	/**
	 * Returns an AddressKeyIterator over the given range.
	 * @param start the first address in the range.
	 * @param end the last address in the range.
	 * @param atStart if true, positions the iterator before the first address, otherwise after
	 * the last address.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract AddressKeyIterator getKeys(Address start, Address end, boolean atStart)
			throws IOException;

	/**
	 * Deletes all records in the given range.
	 * @param start the first address in the range.
	 * @param end the last address in the range.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract boolean deleteRecords(Address start, Address end) throws IOException;

	/**
	 * Adds or updates the given record.
	 * @param record the record to add or update.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void putRecord(DBRecord record) throws IOException;

	/**
	 * Returns a record iterator starting at the given address.
	 * @param addr the address at which to start.
	 * @param forward if true, positions the iterator before the start address, otherwise after.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getRecords(Address addr, boolean forward) throws IOException;

	/**
	 * Returns an AddressKeyIterator over the given address set.
	 * @param addrSetView the set of address to iterator over.
	 * @param forward the direction to iterate.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract AddressKeyIterator getKeys(AddressSetView addrSetView, boolean forward)
			throws IOException;

	/**
	 * Returns a Record interator over the given address set.
	 * @param set the address set to iterator over.
	 * @param forward if true positions the iterator before the first address, otherwise after the
	 * last address.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getRecords(AddressSetView set, boolean forward) throws IOException;

	/**
	 * Update the addresses in all records to reflect the movement of a memory block.
	 * @param fromAddr minimum address of the original block to be moved
	 * @param toAddr the new minimum address after the block move
	 * @param length the number of bytes in the memory block being moved
	 * @param monitor progress monitor
	 * @throws CancelledException thrown if the user cancels the operation.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void moveAddressRange(Address fromAddr, Address toAddr, long length,
			TaskMonitor monitor) throws CancelledException, IOException;

	/**
	 * Deletes all records in this table
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void deleteAll() throws IOException;

}
