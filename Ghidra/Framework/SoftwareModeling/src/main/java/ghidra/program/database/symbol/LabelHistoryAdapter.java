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
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Adapter for the Label History table.
 */
abstract class LabelHistoryAdapter {

	static final String LABEL_HISTORY_TABLE_NAME = "Label History";

	static final Schema LABEL_HISTORY_SCHEMA = new Schema(0, "Key",
		new Field[] { LongField.INSTANCE, ByteField.INSTANCE, StringField.INSTANCE,
			StringField.INSTANCE, LongField.INSTANCE },
		new String[] { "Address", "Action", "Labels", "User", "Date" });

	static final int HISTORY_ADDR_COL = 0;
	static final int HISTORY_ACTION_COL = 1;
	static final int HISTORY_LABEL_COL = 2;
	static final int HISTORY_USER_COL = 3;
	static final int HISTORY_DATE_COL = 4;

	static LabelHistoryAdapter getAdapter(DBHandle dbHandle, int openMode, AddressMap addrMap,
			TaskMonitor monitor) throws VersionException, CancelledException, IOException {

		if (openMode == DBConstants.CREATE) {
			return new LabelHistoryAdapterV0(dbHandle, true);
		}

		try {
			LabelHistoryAdapter adapter = new LabelHistoryAdapterV0(dbHandle, false);
			if (addrMap.isUpgraded()) {
				throw new VersionException(true);
			}
			return adapter;
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			LabelHistoryAdapter adapter = findReadOnlyAdapter(dbHandle);
			if (openMode == DBConstants.UPGRADE) {
				adapter = LabelHistoryAdapterV0.upgrade(dbHandle, addrMap, adapter, monitor);
			}
			return adapter;
		}
	}

	private static LabelHistoryAdapter findReadOnlyAdapter(DBHandle handle) throws IOException {
		try {
			return new LabelHistoryAdapterV0(handle, false);
		}
		catch (VersionException e) {
		}

		return new LabelHistoryAdapterNoTable(handle);
	}

	/**
	 * Create a label history record.
	 * @param addr address
	 * @param actionID either ADD, REMOVE, or RENAME
	 * @param labelStr current labels at the given address
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void createRecord(long addr, byte actionID, String labelStr) throws IOException;

	/**
	 * Get an iterator over records with the given address.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getRecordsByAddress(long addr) throws IOException;

	/**
	 * Get an iterator over all records.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getAllRecords() throws IOException;

	/**
	 * Returns number of history records
	 */
	abstract int getRecordCount();

	/**
	 * Update the address in all records to reflect the movement of a symbol address.
	 * @param oldAddr the original symbol address key
	 * @param newAddr the new symbol address key
	 * @throws IOException 
	 */
	abstract void moveAddress(long oldAddr, long newAddr) throws IOException;

	/**
	 * Update the addresses in all records to reflect the movement of a memory block.
	 * @param fromAddr minimum address of the original block to be moved
	 * @param toAddr the new minimum address after the block move
	 * @param length the number of bytes in the memory block being moved
	 * @param addrMap address map
	 * @param monitor progress monitor
	 * @throws CancelledException if the user cancels the operation.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void moveAddressRange(Address fromAddr, Address toAddr, long length,
			AddressMap addrMap, TaskMonitor monitor) throws CancelledException, IOException;

	/**
	 * Delete all records which contain addresses within the specified range
	 * @param startAddr minimum address in range
	 * @param endAddr maximum address in range
	 * @param addrMap address map
	 * @param doNotDeleteSet the set of addresses where the label history should NOT be deleted.  Null
	 * indicates that all should be deleted.
	 * @param monitor progress monitor
	 * @throws CancelledException if the user cancels the operation.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void deleteAddressRange(Address startAddr, Address endAddr, AddressMap addrMap,
			Set<Address> doNotDeleteSet, TaskMonitor monitor)
			throws CancelledException, IOException;

}
