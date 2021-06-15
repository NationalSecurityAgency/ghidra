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
import java.util.*;

import db.DBRecord;
import db.Field;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;

/**
 * Database implementation for settings.
 * 
 * 
 */
class SettingsDBManager implements Settings {

	private DataTypeManagerDB dataMgr;
	private long dataTypeID;
	private SettingsDBAdapter adapter;
	private DataType dataType;
	private DataTypeComponent dtc;

	/**
	 * Constructor
	 * 
	 */
	public SettingsDBManager(DataTypeManagerDB dataMgr, DataType dataType, long dataTypeID) {

		this.dataMgr = dataMgr;
		this.dataType = dataType;
		this.dataTypeID = dataTypeID;
		adapter = dataMgr.getSettingsAdapter();
	}

	/**
	 * Constructor
	 * 
	 */
	public SettingsDBManager(DataTypeManagerDB dataMgr, DataTypeComponent dtc, long dataTypeID) {

		this.dataMgr = dataMgr;
		this.dtc = dtc;
		this.dataType = dtc.getDataType();
		this.dataTypeID = dataTypeID;
		adapter = dataMgr.getSettingsAdapter();
	}

	private void settingsChanged() {
		// NOTE: There is currently no merge support for settings so recording within
		// domain object change set is unneccessary
		if (dtc != null) {
			dataMgr.dataTypeChanged(dtc.getParent(), true);
		}
		else {
			dataMgr.dataTypeChanged(dataType, true);
		}
	}

	@Override
	public Long getLong(String name) {
		SettingsDB settingsDB = getSettingsDB(name);
		if (settingsDB != null) {
			return settingsDB.getLongValue();
		}
		if (dtc != null) {
			return dataType.getDefaultSettings().getLong(name);
		}
		return null;
	}

	@Override
	public String getString(String name) {
		SettingsDB settingsDB = getSettingsDB(name);
		if (settingsDB != null) {
			return settingsDB.getStringValue();
		}
		if (dtc != null) {
			return dataType.getDefaultSettings().getString(name);
		}
		return null;
	}

	@Override
	public byte[] getByteArray(String name) {
		SettingsDB settingsDB = getSettingsDB(name);
		if (settingsDB != null) {
			return settingsDB.getByteValue();
		}
		if (dtc != null) {
			return dataType.getDefaultSettings().getByteArray(name);
		}
		return null;
	}

	@Override
	public Object getValue(String name) {
		SettingsDB settingsDB = getSettingsDB(name);
		if (settingsDB != null) {
			return settingsDB.getValue();
		}
		if (dtc != null) {
			return dataType.getDefaultSettings().getValue(name);
		}
		return null;
	}

	@Override
	public void setLong(String name, long value) {
		try {
			if (updateSettingsRecord(name, null, value, null)) {
				settingsChanged();
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}

	}

	@Override
	public void setString(String name, String value) {

		try {
			if (updateSettingsRecord(name, value, -1, null)) {
				settingsChanged();
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
	}

	@Override
	public void setByteArray(String name, byte[] value) {
		try {
			if (updateSettingsRecord(name, null, -1, value)) {
				settingsChanged();
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
	}

	@Override
	public void setValue(String name, Object value) {
		if (value instanceof Long) {
			setLong(name, ((Long) value).longValue());
		}
		else if (value instanceof String) {
			setString(name, (String) value);
		}
		else if (value instanceof byte[]) {
			setByteArray(name, (byte[]) value);
		}
		else {
			throw new IllegalArgumentException("Value is not a known settings type");
		}
	}

	@Override
	public void clearSetting(String name) {

		try {
			Field[] keys = adapter.getSettingsKeys(dataTypeID);
			for (Field key : keys) {
				DBRecord rec = adapter.getSettingsRecord(key.getLongValue());
				String settingsName = rec.getString(SettingsDBAdapter.SETTINGS_NAME_COL);
				if (settingsName.equals(name)) {
					adapter.removeSettingsRecord(key.getLongValue());
					settingsChanged();
					return;
				}
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
	}

	@Override
	public void clearAllSettings() {
		try {
			Field[] keys = adapter.getSettingsKeys(dataTypeID);
			for (Field key : keys) {
				adapter.removeSettingsRecord(key.getLongValue());
			}
			settingsChanged();
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
	}

	@Override
	public String[] getNames() {
		List<String> list = new ArrayList<String>();
		try {
			Field[] keys = adapter.getSettingsKeys(dataTypeID);
			for (Field key : keys) {
				DBRecord rec = adapter.getSettingsRecord(key.getLongValue());
				String name = rec.getString(SettingsDBAdapter.SETTINGS_NAME_COL);
				if (!list.contains(name)) {
					list.add(name);
				}
			}
			String[] names = new String[list.size()];
			return list.toArray(names);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		return new String[0];
	}

	@Override
	public boolean isEmpty() {
		try {
			return adapter.getSettingsKeys(dataTypeID).length == 0;
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		return true;
	}

	void update(Settings settings) {
		clearAllSettings();
		String[] names = settings.getNames();
		for (String name : names) {
			setValue(name, settings.getValue(name));
		}
	}

	/**
	 * Following settings value change compare old and new values and return 
	 * true if old and new values are different.
	 * @param oldStrValue old settings string value
	 * @param newStrValue new settings string value
	 * @param oldByteValue old settings byte array value
	 * @param newByteValue new settings byte array value
	 * @param oldLongValue old settings long value
	 * @param newLongValue new settings long value
	 * @return true true if value change detected else false
	 */
	static boolean valuesChanged(String oldStrValue, String newStrValue, byte[] oldByteValue,
			byte[] newByteValue, long oldLongValue, long newLongValue) {

		if ((oldStrValue != null && !oldStrValue.equals(newStrValue)) ||
			(oldStrValue == null && newStrValue != null)) {
			return true;
		}
		if (oldByteValue != null && newByteValue != null) {
			return Arrays.equals(oldByteValue, newByteValue);
		}
		if ((oldByteValue != null && newByteValue == null) ||
			(oldByteValue == null && newByteValue != null)) {
			return true;
		}
		return oldLongValue != newLongValue;
	}

	private DBRecord getRecord(String name) {
		try {
			Field[] keys = adapter.getSettingsKeys(dataTypeID);
			for (Field key : keys) {
				DBRecord rec = adapter.getSettingsRecord(key.getLongValue());
				if (rec.getString(SettingsDBAdapter.SETTINGS_NAME_COL).equals(name)) {
					return rec;
				}
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		return null;

	}

	private SettingsDB getSettingsDB(String name) {

		DBRecord record = getRecord(name);
		if (record != null) {
			return new SettingsDB(record);
		}
		return null;
	}

	private boolean updateSettingsRecord(String name, String strValue, long longValue,
			byte[] byteValue) throws IOException {

		boolean wasChanged = false;
		DBRecord record = getRecord(name);
		if (record == null) {
			wasChanged = true;
			record = adapter.createSettingsRecord(dataTypeID, name, strValue, longValue, byteValue);
		}
		else {
			String recStrValue = record.getString(SettingsDBAdapter.SETTINGS_STRING_VALUE_COL);
			byte[] recByteValue = record.getBinaryData(SettingsDBAdapter.SETTINGS_BYTE_VALUE_COL);
			long recLongValue = record.getLongValue(SettingsDBAdapter.SETTINGS_LONG_VALUE_COL);

			wasChanged = valuesChanged(recStrValue, strValue, recByteValue, byteValue, recLongValue,
				longValue);
			if (wasChanged) {
				record.setString(SettingsDBAdapter.SETTINGS_STRING_VALUE_COL, strValue);
				record.setLongValue(SettingsDBAdapter.SETTINGS_LONG_VALUE_COL, longValue);
				record.setBinaryData(SettingsDBAdapter.SETTINGS_BYTE_VALUE_COL, byteValue);
				adapter.updateSettingsRecord(record);
			}
		}
		return wasChanged;
	}

	@Override
	public Settings getDefaultSettings() {
		// This settings object already represents the default settings
		return null;
	}
}
