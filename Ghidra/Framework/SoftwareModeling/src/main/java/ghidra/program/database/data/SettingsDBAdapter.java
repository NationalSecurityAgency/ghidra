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

import java.io.IOException;
import java.util.Set;

import db.*;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Adapter to access settings database tables.
 * 
 * 
 */
abstract class SettingsDBAdapter {

	static final Schema SETTINGS_SCHEMA = SettingsDBAdapterV1.V1_SETTINGS_SCHEMA;

	// Default Settings Columns
	static final int SETTINGS_ASSOCIATION_ID_COL =
		SettingsDBAdapterV1.V1_SETTINGS_ASSOCIATION_ID_COL; // e.g., Address-key or Datatype-ID
	static final int SETTINGS_NAME_INDEX_COL = SettingsDBAdapterV1.V1_SETTINGS_NAME_INDEX_COL; // short
	static final int SETTINGS_LONG_VALUE_COL = SettingsDBAdapterV1.V1_SETTINGS_LONG_VALUE_COL;
	static final int SETTINGS_STRING_VALUE_COL = SettingsDBAdapterV1.V1_SETTINGS_STRING_VALUE_COL;

	/**
	 * Get a settings adapter.
	 * NOTE: Support for read-only mode for older versions must be retained.
	 * @param tableName settings DB table name
	 * @param handle database handle
	 * @param openMode database open mode
	 * @param addrMap address map (should only be specified when association IDs 
	 * correspond to address key, otherwise should be null).
	 * @param monitor task monitor
	 * @return settings adapter instance
	 * @throws VersionException if schema version does not match current version
	 * @throws IOException if there was a problem accessing the database
	 * @throws CancelledException if task cancelled
	 */
	static SettingsDBAdapter getAdapter(String tableName, DBHandle handle, int openMode,
			AddressMap addrMap, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {

		if (openMode == DBConstants.CREATE) {
			return new SettingsDBAdapterV1(tableName, handle, true);
		}

		if (openMode == DBConstants.READ_ONLY) {
			return findReadOnlyAdapter(tableName, handle);
		}

		try {
			SettingsDBAdapter adapter = new SettingsDBAdapterV1(tableName, handle, false);
			if (addrMap != null && addrMap.isUpgraded()) {
				throw new VersionException(true);
			}
			return adapter;
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			SettingsDBAdapter adapter = findReadOnlyAdapter(tableName, handle);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(handle, adapter, addrMap, monitor);
			}
			return adapter;
		}
	}

	private static SettingsDBAdapter findReadOnlyAdapter(String tableName, DBHandle dbHandle)
			throws VersionException, IOException {
		try {
			return new SettingsDBAdapterV1(tableName, dbHandle, false);
		}
		catch (VersionException e) {
			return new SettingsDBAdapterV0(tableName, dbHandle);
		}
	}

	private static SettingsDBAdapter upgrade(DBHandle dbHandle, SettingsDBAdapter oldAdapter,
			AddressMap addrMap, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {

		String tableName = oldAdapter.getTableName();
		monitor.setMessage("Upgrading " + tableName + "...");
		monitor.initialize(2 * oldAdapter.getRecordCount());
		int cnt = 0;

		AddressMap oldAddrMap = addrMap != null ? addrMap.getOldAddressMap() : null;

		DBHandle tmpHandle = new DBHandle();
		SettingsDBAdapter tmpAdapter = null;
		try {
			tmpHandle.startTransaction();

			tmpAdapter = new SettingsDBAdapterV1(tableName, tmpHandle, true);
			RecordIterator iter = oldAdapter.getRecords();
			while (iter.hasNext()) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				DBRecord rec = iter.next();
				if (oldAddrMap != addrMap) {
					// updated address-based association ID if needed
					Address addr =
						oldAddrMap.decodeAddress(rec.getLongValue(SETTINGS_ASSOCIATION_ID_COL));
					rec.setLongValue(SETTINGS_ASSOCIATION_ID_COL, addrMap.getKey(addr, true));
				}
				tmpAdapter.createSettingsRecord(rec.getLongValue(SETTINGS_ASSOCIATION_ID_COL),
					oldAdapter.getSettingName(rec),
					rec.getString(SETTINGS_STRING_VALUE_COL),
					rec.getLongValue(SETTINGS_LONG_VALUE_COL));
				monitor.setProgress(++cnt);
			}

			// NOTE: If a V2 adapter is ever added multiple tables may need to be removed.
			dbHandle.deleteTable(tableName);

			SettingsDBAdapter newAdapter = new SettingsDBAdapterV1(tableName, dbHandle, true);
			iter = tmpAdapter.getRecords();
			while (iter.hasNext()) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				DBRecord rec = iter.next();
				newAdapter.createSettingsRecord(rec.getLongValue(SETTINGS_ASSOCIATION_ID_COL),
					tmpAdapter.getSettingName(rec),
					rec.getString(SETTINGS_STRING_VALUE_COL),
					rec.getLongValue(SETTINGS_LONG_VALUE_COL));
				monitor.setProgress(++cnt);
			}
			return newAdapter;
		}
		finally {
			tmpHandle.close();
		}
	}

	/**
	 * Get DB table name
	 * @return table name
	 */
	abstract String getTableName();

	/**
	 * Returns number of settings records
	 * @return total settings record count
	 */
	abstract int getRecordCount();

	/**
	 * Get iterator over all settings records
	 * @return record iterator
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getRecords() throws IOException;

	/**
	 * Get an iterator over those records that fall in the given range for
	 * the association ID column in the table. 
	 * @param minAssociationId minimum association ID for range
	 * @param maxAssociationId maximum association ID for range
	 * @return record iterator
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getRecords(long minAssociationId, long maxAssociationId)
			throws IOException;

	/**
	 * Delete all settings records over the specified range of association IDs
	 * @param minAssociationId minimum association ID for range
	 * @param maxAssociationId maximum association ID for range
	 * @param monitor task monitor
	 * @throws CancelledException if task was cancelled
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void delete(long minAssociationId, long maxAssociationId, TaskMonitor monitor)
			throws CancelledException, IOException;

	/**
	 * Create a settings record.
	 * @param associationId ID associated with the use of a setting (e.g., address-key, datatype-ID)
	 * @param name name of the setting
	 * @param strValue string value; null if setting is not String
	 * @param longValue long value; -1 if setting is not a long
	 * @return new record
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord createSettingsRecord(long associationId, String name, String strValue,
			long longValue) throws IOException;

	/**
	 * Get settings record keys for all settings corresponding to the 
	 * specified associationId. 
	 * @param associationId ID associated with the use of a setting (e.g., address-key, datatype-ID)
	 * @return settings record keys returned as LongFields within Field array
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract Field[] getSettingsKeys(long associationId) throws IOException;

	/**
	 * Remove all settings records for specified associationId.
	 * @param associationId ID associated with the use of a setting (e.g., address-key, datatype-ID)
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void removeAllSettingsRecords(long associationId) throws IOException;

	/**
	 * Remove the specified settings record.
	 * @param settingsId key for the record
	 * @return true if the record was deleted
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract boolean removeSettingsRecord(long settingsId) throws IOException;

	/**
	 * Remove the specified settings record if found
	 * @param associationId association ID (e.g., address key, datatype ID)
	 * @param name setting name
	 * @return true if record found and was removed, else false
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract boolean removeSettingsRecord(long associationId, String name) throws IOException;

	/**
	 * Get the specified settings record.
	 * @param settingsId key for the record
	 * @return record corresponding to settingsID or null
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord getSettingsRecord(long settingsId) throws IOException;

	/**
	 * Get the settings record which corresponds to a specific associatedId and setting name.
	 * @param associationId association ID (e.g., address key, datatype ID)
	 * @param name setting name
	 * @return record corresponding to settingsID or null
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord getSettingsRecord(long associationId, String name) throws IOException;

	/**
	 * Update the settings record in the table
	 * IMPORTANT: This method must not be used during upgrades since it bypasses allocation 
	 * of settings name index values.
	 * @param record the new record
	 * @throws IOException if there was a problem accessing the database or an invalid
	 * name index value was used.
	 */
	abstract void updateSettingsRecord(DBRecord record) throws IOException;

	/**
	 * Update the setting record corresponding to the specified setting data.  
	 * Search for existing record will be performed.
	 * @param associationId association ID (e.g., address key, datatype ID)
	 * @param name setting name
	 * @param strValue setting string value or null
	 * @param longValue setting long value
	 * @return updated record if setting was updated, else null
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord updateSettingsRecord(long associationId, String name, String strValue,
			long longValue) throws IOException;

	/**
	 * Get an array of names for settings records which correspond to the specified 
	 * associationId. 
	 * @param associationId association ID (e.g., address key, datatype ID)
	 * @return array of settings names
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract String[] getSettingsNames(long associationId) throws IOException;

	/**
	 * Add all values stored for the specified setting name to the specified set.
	 * @param name setting name
	 * @param set value set
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void addAllValues(String name, Set<String> set) throws IOException;

	/**
	 * Get the setting name which corresponds to the specified record.
	 * @param record normalized settings record (name column is an integer index value)
	 * @return setting name
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract String getSettingName(DBRecord record) throws IOException;

	/**
	 * Invalidate name cache
	 */
	abstract void invalidateNameCache();

}
