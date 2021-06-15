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

/**
 * Version 0 implementation for the accessing the data type settings database table.
 */
class SettingsDBAdapterV0 extends SettingsDBAdapter {

	// Default Settings Columns
	static final int V0_SETTINGS_DT_ID_COL = 0;
	static final int V0_SETTINGS_NAME_COL = 1;
	static final int V0_SETTINGS_LONG_VALUE_COL = 2;
	static final int V0_SETTINGS_STRING_VALUE_COL = 3;
	static final int V0_SETTINGS_BYTE_VALUE_COL = 4;

	static final Schema V0_SETTINGS_SCHEMA = new Schema(0, "DT Settings ID",
		new Field[] { LongField.INSTANCE, StringField.INSTANCE, LongField.INSTANCE,
			StringField.INSTANCE, BinaryField.INSTANCE },
		new String[] { "Data Type ID", "Settings Name", "Long Value", "String Value",
			"Byte Value" });
	private Table settingsTable;

	SettingsDBAdapterV0(DBHandle handle, boolean create) throws VersionException, IOException {

		if (create) {
			settingsTable = handle.createTable(SETTINGS_TABLE_NAME, V0_SETTINGS_SCHEMA,
				new int[] { V0_SETTINGS_DT_ID_COL });
		}
		else {
			settingsTable = handle.getTable(SETTINGS_TABLE_NAME);
			if (settingsTable == null) {
				throw new VersionException("Missing Table: " + SETTINGS_TABLE_NAME);
			}
			if (settingsTable.getSchema().getVersion() != 0) {
				throw new VersionException("Expected version 0 for table " + SETTINGS_TABLE_NAME +
					" but got " + settingsTable.getSchema().getVersion());
			}
		}
	}

	@Override
	public DBRecord createSettingsRecord(long dataTypeID, String name, String strValue,
			long longValue, byte[] byteValue) throws IOException {

		DBRecord record = V0_SETTINGS_SCHEMA.createRecord(settingsTable.getKey());
		record.setLongValue(V0_SETTINGS_DT_ID_COL, dataTypeID);
		record.setString(V0_SETTINGS_NAME_COL, name);
		record.setString(V0_SETTINGS_STRING_VALUE_COL, strValue);
		record.setLongValue(V0_SETTINGS_LONG_VALUE_COL, longValue);
		record.setBinaryData(V0_SETTINGS_BYTE_VALUE_COL, byteValue);
		settingsTable.putRecord(record);
		return record;
	}

	@Override
	public Field[] getSettingsKeys(long dataTypeID) throws IOException {
		return settingsTable.findRecords(new LongField(dataTypeID), V0_SETTINGS_DT_ID_COL);
	}

	@Override
	public boolean removeSettingsRecord(long settingsID) throws IOException {
		return settingsTable.deleteRecord(settingsID);
	}

	@Override
	public DBRecord getSettingsRecord(long settingsID) throws IOException {
		return settingsTable.getRecord(settingsID);
	}

	@Override
	public void updateSettingsRecord(DBRecord record) throws IOException {
		settingsTable.putRecord(record);
	}

	@Override
	int getRecordCount() {
		return settingsTable.getRecordCount();
	}

}
