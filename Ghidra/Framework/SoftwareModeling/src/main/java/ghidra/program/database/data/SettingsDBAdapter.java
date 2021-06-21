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

import db.*;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Adapter to access the default settings and instance settings database tables.
 * 
 * 
 */
abstract class SettingsDBAdapter {

	static final String SETTINGS_TABLE_NAME = "Default Settings";

	static final Schema SETTINGS_SCHEMA = SettingsDBAdapterV0.V0_SETTINGS_SCHEMA;

	// Default Settings Columns
	static final int SETTINGS_DT_ID_COL = SettingsDBAdapterV0.V0_SETTINGS_DT_ID_COL;
	static final int SETTINGS_NAME_COL = SettingsDBAdapterV0.V0_SETTINGS_NAME_COL;
	static final int SETTINGS_LONG_VALUE_COL = SettingsDBAdapterV0.V0_SETTINGS_LONG_VALUE_COL;
	static final int SETTINGS_STRING_VALUE_COL = SettingsDBAdapterV0.V0_SETTINGS_STRING_VALUE_COL;
	static final int SETTINGS_BYTE_VALUE_COL = SettingsDBAdapterV0.V0_SETTINGS_BYTE_VALUE_COL;

	static SettingsDBAdapter getAdapter(DBHandle handle, int openMode, TaskMonitor monitor)
			throws VersionException, IOException {
		return new SettingsDBAdapterV0(handle, openMode == DBConstants.CREATE);
	}

	/**
	 * Returns number of settings records
	 * @return total settings record count
	 */
	abstract int getRecordCount();

	/**
	 * Create a default settings record.
	 * @param dataTypeID data type ID associated with the setting
	 * @param name name of the setting
	 * @param strValue string value; null if setting is not String
	 * @param longValue long value; -1 if setting is not a long
	 * @param byteValue byte array value; null if setting is not a byte array
	 * @return new record
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord createSettingsRecord(long dataTypeID, String name, String strValue,
			long longValue, byte[] byteValue) throws IOException;

	/**
	 * Get settings record keys for the default settings corresponding to the 
	 * specified data type ID. 
	 * @param dataTypeID datatype ID
	 * @return settings record keys returned as LongFields within Field array
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract Field[] getSettingsKeys(long dataTypeID) throws IOException;

	/**
	 * Remove the default settings record.
	 * @param settingsID key for the record
	 * @return true if the record was deleted
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract boolean removeSettingsRecord(long settingsID) throws IOException;

	/**
	 * Get the default settings record.
	 * @param settingsID key for the record
	 * @return record corresponding to settingsID or null
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord getSettingsRecord(long settingsID) throws IOException;

	/**
	 * Update the default settings record in the table.
	 * @param record the new record
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void updateSettingsRecord(DBRecord record) throws IOException;

}
