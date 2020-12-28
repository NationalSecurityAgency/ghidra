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
package ghidra.program.database.data;

import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

import db.*;

/**
 * Adapter to access the instance settings database tables.
 */
abstract class InstanceSettingsDBAdapter {

	static final String INSTANCE_TABLE_NAME = "Instance Settings";

	static final Schema INSTANCE_SCHEMA = InstanceSettingsDBAdapterV0.V0_INSTANCE_SCHEMA;

	// Instance Settings Columns
	static final int INST_ADDR_COL = InstanceSettingsDBAdapterV0.V0_INST_ADDR_COL;
	static final int INST_NAME_COL = InstanceSettingsDBAdapterV0.V0_INST_NAME_COL;
	static final int INST_LONG_VALUE_COL = InstanceSettingsDBAdapterV0.V0_INST_LONG_VALUE_COL;
	static final int INST_STRING_VALUE_COL = InstanceSettingsDBAdapterV0.V0_INST_STRING_VALUE_COL;
	static final int INST_BYTE_VALUE_COL = InstanceSettingsDBAdapterV0.V0_INST_BYTE_VALUE_COL;

	static InstanceSettingsDBAdapter getAdapter(DBHandle handle, int openMode, AddressMap addrMap,
			TaskMonitor monitor) throws VersionException, CancelledException, IOException {

		if (openMode == DBConstants.CREATE) {
			new InstanceSettingsDBAdapterV0(handle, true);
		}

		try {
			InstanceSettingsDBAdapter adapter = new InstanceSettingsDBAdapterV0(handle, false);
			if (addrMap.isUpgraded()) {
				throw new VersionException(true);
			}
			return adapter;
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			InstanceSettingsDBAdapter adapter = findReadOnlyAdapter(handle);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(handle, adapter, addrMap, monitor);
			}
			return adapter;
		}
	}

	private static InstanceSettingsDBAdapter findReadOnlyAdapter(DBHandle dbHandle)
			throws VersionException, IOException {
		return new InstanceSettingsDBAdapterV0(dbHandle, false);
	}

	private static InstanceSettingsDBAdapter upgrade(DBHandle dbHandle,
			InstanceSettingsDBAdapter oldAdapter, AddressMap addrMap, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {

		monitor.setMessage("Upgrading Instance Data Settings...");
		monitor.initialize(2 * oldAdapter.getRecordCount());
		int cnt = 0;

		AddressMap oldAddrMap = addrMap.getOldAddressMap();

		DBHandle tmpHandle = new DBHandle();
		InstanceSettingsDBAdapter tmpAdapter = null;
		try {
			tmpHandle.startTransaction();

			tmpAdapter = new InstanceSettingsDBAdapterV0(tmpHandle, true);
			RecordIterator iter = oldAdapter.getRecords();
			while (iter.hasNext()) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				DBRecord rec = iter.next();
				Address addr = oldAddrMap.decodeAddress(rec.getLongValue(INST_ADDR_COL));
				rec.setLongValue(INST_ADDR_COL, addrMap.getKey(addr, true));
				tmpAdapter.updateInstanceRecord(rec);
				monitor.setProgress(++cnt);
			}

			dbHandle.deleteTable(INSTANCE_TABLE_NAME);
			InstanceSettingsDBAdapter newAdapter = new InstanceSettingsDBAdapterV0(dbHandle, true);
			iter = tmpAdapter.getRecords();
			while (iter.hasNext()) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				DBRecord rec = iter.next();
				newAdapter.updateInstanceRecord(rec);
				monitor.setProgress(++cnt);
			}
			return newAdapter;
		}
		finally {
			tmpHandle.close();
		}
	}

	/**
	 * Returns number of settings records
	 */
	abstract int getRecordCount();

	/**
	 * Create an instance settings record.
	 * @param addr address where setting is applied
	 * @param name name of the setting
	 * @param strValue string value; null if setting is not String
	 * @param longValue long value; -1 if setting is not a long
	 * @param byteValue byte array value; null if setting is not a byte array
	 * @return
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord createInstanceRecord(long addr, String name, String strValue, long longValue,
			byte[] byteValue) throws IOException;

	/**
	 * Get keys for the instance settings applied at the given address. 
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract Field[] getInstanceKeys(long addr) throws IOException;

	/**
	 * Remove the instance record. 
	 * @param settingsID key
	 * @return true if the record was deleted
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract boolean removeInstanceRecord(long settingsID) throws IOException;

	/**
	 * Get the instance settings record.
	 * @param settingsID key for the record
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord getInstanceRecord(long settingsID) throws IOException;

	/**
	 * Update the instance settings record in the table.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void updateInstanceRecord(DBRecord record) throws IOException;

	/**
	 * Get an iterator over those records that fall in the given range for
	 * the address column in the table. 
	 * @param start start address index
	 * @param end end address index
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getRecords(long start, long end) throws IOException;

	/**
	 * Returns an iterator over all instance setting records (no specific order)
	 * @throws IOException
	 */
	abstract RecordIterator getRecords() throws IOException;

	/**
	 * Delete all instance settings over a range of addresses.
	 * @param start
	 * @param end
	 * @param monitor
	 * @throws CancelledException
	 * @throws IOException
	 */
	abstract void delete(long start, long end, TaskMonitor monitor) throws CancelledException,
			IOException;
}
