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

import java.util.ArrayList;
import java.util.List;

import ghidra.docking.settings.Settings;

/**
 * Settings for typedefs that combines the default settings with instance
 * settings if instance settings for a setting name does not exist.
 * 
 * 
 *
 */
class TypedefSettings implements Settings {

	private Settings defaultSettings;
	private Settings instanceSettings;

	TypedefSettings(Settings defaultSettings, Settings instanceSettings) {
		this.defaultSettings = defaultSettings;
		this.instanceSettings = instanceSettings;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.Settings#clearAllSettings()
	 */
	public void clearAllSettings() {
		defaultSettings.clearAllSettings();
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.Settings#clearSetting(java.lang.String)
	 */
	public void clearSetting(String name) {
		defaultSettings.clearSetting(name);
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.Settings#getByteArray(java.lang.String)
	 */
	public byte[] getByteArray(String name) {
		byte[] b = instanceSettings.getByteArray(name);
		if (b == null) {
			b = defaultSettings.getByteArray(name);
		}
		return b;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.Settings#getLong(java.lang.String)
	 */
	public Long getLong(String name) {
		Long value = instanceSettings.getLong(name);
		if (value == null) {
			value = defaultSettings.getLong(name);
		}
		return value;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.Settings#getNames()
	 */
	public String[] getNames() {
		List<String> list = new ArrayList<String>();
		String[] instNames = instanceSettings.getNames();
		for (int i = 0; i < instNames.length; i++) {
			list.add(instNames[i]);
		}
		String[] defNames = defaultSettings.getNames();
		for (int i = 0; i < defNames.length; i++) {
			if (!list.contains(defNames[i])) {
				list.add(defNames[i]);
			}
		}
		String[] names = new String[list.size()];
		return list.toArray(names);
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.Settings#getString(java.lang.String)
	 */
	public String getString(String name) {
		String value = instanceSettings.getString(name);
		if (value == null) {
			value = defaultSettings.getString(name);
		}
		return value;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.Settings#getValue(java.lang.String)
	 */
	public Object getValue(String name) {
		Object value = instanceSettings.getValue(name);
		if (value == null) {
			value = defaultSettings.getValue(name);
		}
		return value;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.Settings#isEmpty()
	 */
	public boolean isEmpty() {
		return instanceSettings.isEmpty() && defaultSettings.isEmpty();
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.Settings#setByteArray(java.lang.String, byte[])
	 */
	public void setByteArray(String name, byte[] value) {
		defaultSettings.setByteArray(name, value);
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.Settings#setLong(java.lang.String, long)
	 */
	public void setLong(String name, long value) {
		defaultSettings.setLong(name, value);
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.Settings#setString(java.lang.String, java.lang.String)
	 */
	public void setString(String name, String value) {
		defaultSettings.setString(name, value);
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.Settings#setValue(java.lang.String, java.lang.Object)
	 */
	public void setValue(String name, Object value) {
		defaultSettings.setValue(name, value);
	}

	/**
	 * @see ghidra.docking.settings.Settings#getDefaultSettings()
	 */
	public Settings getDefaultSettings() {
		return defaultSettings;
	}
}
