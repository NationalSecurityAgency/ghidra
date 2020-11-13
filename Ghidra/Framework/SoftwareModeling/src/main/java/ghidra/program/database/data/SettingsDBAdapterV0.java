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

import ghidra.util.exception.VersionException;

import java.io.IOException;

import db.*;

/**
 *
 * To change the template for this generated type comment go to
 * {@literal Window>Preferences>Java>Code Generation>Code and Comments}
 * 
 * 
 */
class SettingsDBAdapterV0 extends SettingsDBAdapter {

	// Default Settings Columns
	static final int V0_SETTINGS_DT_ID_COL = 0;
	static final int V0_SETTINGS_NAME_COL = 1;
	static final int V0_SETTINGS_LONG_VALUE_COL = 2;
	static final int V0_SETTINGS_STRING_VALUE_COL = 3;
	static final int V0_SETTINGS_BYTE_VALUE_COL = 4;

	static final Schema V0_SETTINGS_SCHEMA = new Schema(0, "DT Settings ID",
		new Class[] { LongField.class, StringField.class, LongField.class, StringField.class,
			BinaryField.class }, new String[] { "Data Type ID", "Settings Name", "Long Value",
			"String Value", "Byte Value" });
	private Table settingsTable;

	/**
	 * Constructor
	 * 
	 */
	SettingsDBAdapterV0(DBHandle handle, boolean create) throws VersionException, IOException {

		if (create) {
			settingsTable =
				handle.createTable(SETTINGS_TABLE_NAME, V0_SETTINGS_SCHEMA,
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

	/**
	 * @see ghidra.program.database.data.SettingsDBAdapter#createSettingsRecord(long, java.lang.String, java.lang.String, long, byte[])
	 */
	@Override
	public Record createSettingsRecord(long dataTypeID, String name, String strValue,
			long longValue, byte[] byteValue) throws IOException {

		Record record = V0_SETTINGS_SCHEMA.createRecord(settingsTable.getKey());
		record.setLongValue(V0_SETTINGS_DT_ID_COL, dataTypeID);
		record.setString(V0_SETTINGS_NAME_COL, name);
		record.setString(V0_SETTINGS_STRING_VALUE_COL, strValue);
		record.setLongValue(V0_SETTINGS_LONG_VALUE_COL, longValue);
		record.setBinaryData(V0_SETTINGS_BYTE_VALUE_COL, byteValue);
		settingsTable.putRecord(record);
		return record;
	}

	/**
	 * @see ghidra.program.database.data.SettingsDBAdapter#getSettingsKeys(long)
	 */
	@Override
	public long[] getSettingsKeys(long dataTypeID) throws IOException {
		return settingsTable.findRecords(new LongField(dataTypeID), V0_SETTINGS_DT_ID_COL);
	}

	/**
	 * @see ghidra.program.database.data.SettingsDBAdapter#removeSettingsRecord(long)
	 */
	@Override
	public boolean removeSettingsRecord(long settingsID) throws IOException {
		return settingsTable.deleteRecord(settingsID);
	}

	/**
	 * @see ghidra.program.database.data.SettingsDBAdapter#getSettingsRecord(long)
	 */
	@Override
	public Record getSettingsRecord(long settingsID) throws IOException {
		return settingsTable.getRecord(settingsID);
	}

	/**
	 * @see ghidra.program.database.data.SettingsDBAdapter#updateSettingsRecord(ghidra.framework.store.db.Record)
	 */
	@Override
	public void updateSettingsRecord(Record record) throws IOException {
		settingsTable.putRecord(record);
	}

	/*
	 * @see ghidra.program.database.data.SettingsDBAdapter#getRecordCount()
	 */
	@Override
	int getRecordCount() {
		return settingsTable.getRecordCount();
	}

}
