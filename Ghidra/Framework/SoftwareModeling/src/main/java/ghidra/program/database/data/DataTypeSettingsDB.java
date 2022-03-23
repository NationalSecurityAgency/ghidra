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

import com.google.common.base.Predicate;

import ghidra.docking.settings.*;
import ghidra.program.model.data.*;
import ghidra.util.Msg;

/**
 * Default {@link Settings} handler for those datatypes managed
 * by an associated {@link DataTypeManagerDB}.
 */
class DataTypeSettingsDB implements Settings {

	private final DataTypeManagerDB dataMgr;
	private final long dataTypeID;
	private final DataType dataType;

	private boolean locked;
	private Predicate<String> allowedSettingPredicate;

	private Settings defaultSettings;

	/**
	 * Constructor for settings storage manager.
	 * Initial state is locked for non-ProgramBasedDataTypeManager.
	 * @param dataMgr  data type manager
	 * @param dataType built-in datatype
	 * @param dataTypeID resolved datatype ID
	 */
	DataTypeSettingsDB(DataTypeManagerDB dataMgr, BuiltInDataType dataType, long dataTypeID) {
		this.dataMgr = dataMgr;
		this.dataType = dataType;
		this.dataTypeID = dataTypeID;
		this.locked = !(dataMgr instanceof ProgramBasedDataTypeManager);
	}

	/**
	 * Constructor for settings storage manager.
	 * Initial state is locked for non-ProgramBasedDataTypeManager.
	 * @param dataMgr  data type manager
	 * @param dataType DB datatype
	 * @param dataTypeID resolved datatype ID
	 */
	DataTypeSettingsDB(DataTypeManagerDB dataMgr, DataTypeDB dataType, long dataTypeID) {
		this.dataMgr = dataMgr;
		this.dataType = dataType;
		this.dataTypeID = dataTypeID;
		this.locked = !(dataMgr instanceof ProgramBasedDataTypeManager);
	}

	/**
	 * Change the current settings lock.  Attempts to modify locked
	 * settings will be ignored with a logged error.  This is done
	 * to write-protect settings at the public API level.
	 * @param lock true to lock, false to unlock
	 * @return previous lock state
	 */
	boolean setLock(boolean lock) {
		boolean wasLocked = locked;
		locked = lock;
		return wasLocked;
	}

	@Override
	public boolean isChangeAllowed(SettingsDefinition settingsDefinition) {
		if (locked) {
			return false;
		}
		if (allowedSettingPredicate != null &&
			!allowedSettingPredicate.apply(settingsDefinition.getStorageKey())) {
			return false;
		}
		return true;
	}

	@Override
	public String[] getSuggestedValues(StringSettingsDefinition settingsDefinition) {
		return dataMgr.getSuggestedValues(settingsDefinition);
	}

	/**
	 * Set predicate for settings modification
	 * @param allowedSettingPredicate callback for checking an allowed setting modification
	 */
	void setAllowedSettingPredicate(Predicate<String> allowedSettingPredicate) {
		this.allowedSettingPredicate = allowedSettingPredicate;
	}

	/**
	 * Check for immutable settings and log error of modification not permitted
	 * @param type setting type or null
	 * @param name setting name or null
	 * @return true if change permitted
	 */
	private boolean checkSetting(String type, String name) {
		if (!checkImmutableSetting(type, name)) {
			return false;
		}
		if (name != null && allowedSettingPredicate != null &&
			!allowedSettingPredicate.apply(name)) {
			Msg.warn(this, "Ignored disallowed setting '" + name + "'");
			return false;
		}
		return true;
	}

	/**
	 * Check for immutable settings and log error of modification not permitted.
	 * Does not check for other setting restrictions.
	 * @param type setting type or null
	 * @param name setting name or null
	 * @return true if change permitted
	 */
	private boolean checkImmutableSetting(String type, String name) {
		if (locked) {
			String typeStr = "";
			if (type != null) {
				typeStr = type + " ";
			}
			String nameStr = ": " + name;
			if (name == null) {
				nameStr = "s";
			}
			Msg.warn(SettingsImpl.class,
				"Ignored invalid attempt to modify immutable " + typeStr + "component setting" +
					nameStr);
			return false;
		}
		return true;
	}

	private void settingsChanged() {
		// NOTE: Merge currently only supports TypeDefDB default settings changes which correspond
		// to TypeDefSettingsDefinition established by the base datatype
		// and does not consider DataTypeComponent default settings changes or other setting types.
		dataMgr.dataTypeSettingsChanged(dataType);
	}

	@Override
	public Long getLong(String name) {
		SettingDB settingDB = dataMgr.getSetting(dataTypeID, name);
		if (settingDB != null) {
			return settingDB.getLongValue();
		}
		if (defaultSettings != null) {
			return defaultSettings.getLong(name);
		}
		return null;
	}

	@Override
	public String getString(String name) {
		SettingDB settingDB = dataMgr.getSetting(dataTypeID, name);
		if (settingDB != null) {
			return settingDB.getStringValue();
		}
		if (defaultSettings != null) {
			return defaultSettings.getString(name);
		}
		return null;
	}

	@Override
	public Object getValue(String name) {
		SettingDB settingDB = dataMgr.getSetting(dataTypeID, name);
		if (settingDB != null) {
			return settingDB.getValue();
		}
		if (defaultSettings != null) {
			return defaultSettings.getValue(name);
		}
		return null;
	}

	@Override
	public void setLong(String name, long value) {
		if (checkSetting("long", name) &&
			dataMgr.updateSettingsRecord(dataTypeID, name, null, value)) {
			settingsChanged();
		}
	}

	@Override
	public void setString(String name, String value) {
		if (checkSetting("string", name) &&
			dataMgr.updateSettingsRecord(dataTypeID, name, value, -1)) {
			settingsChanged();
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
		else {
			throw new IllegalArgumentException("Value is not a known settings type: " + name);
		}
	}

	@Override
	public void clearSetting(String name) {
		if (checkImmutableSetting(null, name) && dataMgr.clearSetting(dataTypeID, name)) {
			settingsChanged();
		}
	}

	@Override
	public void clearAllSettings() {
		if (checkImmutableSetting(null, null) && dataMgr.clearAllSettings(dataTypeID)) {
			settingsChanged();
		}
	}

	@Override
	public String[] getNames() {
		return dataMgr.getSettingsNames(dataTypeID);
	}

	@Override
	public boolean isEmpty() {
		return getNames().length == 0;
	}

	public void setDefaultSettings(Settings settings) {
		defaultSettings = settings;
	}

	@Override
	public Settings getDefaultSettings() {
		return defaultSettings;
	}
}
