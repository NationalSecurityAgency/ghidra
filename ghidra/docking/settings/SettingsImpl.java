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
package ghidra.docking.settings;

import java.io.Serializable;
import java.util.*;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

/**
 * Basic implementation of the Settings object
 */
public class SettingsImpl implements Settings, Serializable {
	private final static long serialVersionUID = 1;

	private Map<String, Object> map;
	private Settings defaultSettings;
	private ChangeListener listener;
	private Object changeSourceObj;

	//@formatter:off
	public static final Settings NO_SETTINGS = new SettingsImpl() {
		@Override public void setByteArray(String name, byte[] value) { /* nada */ }
		@Override public void setDefaultSettings(Settings settings) { /* nada*/ }
		@Override public void setLong(String name, long value) { /* nada */ }
		@Override public void setString(String name, String value) { /* nada */ }
		@Override public void setValue(String name, Object value) { /* nada */ }
	};
	//@formatter:on

	/**
	 *  Construct a new SettingsImpl
	 */
	public SettingsImpl() {
		map = new HashMap<>();
	}

	/**
	 * Construct a new SettingsImpl with the given listener
	 * @param listener object to be notified as settings values change
	 * @param changeSourceObj source object to be associated with change events
	 */
	public SettingsImpl(ChangeListener listener, Object changeSourceObj) {
		this();
		this.listener = listener;
		this.changeSourceObj = changeSourceObj;
	}

	/**
	 * Construct a new SettingsImpl object with the same set of name-value pairs
	 * as the given settings object
	 * @param settings the settings object to copy
	 */
	public SettingsImpl(Settings settings) {
		this();
		String[] names = settings.getNames();
		for (int i = 0; i < names.length; i++) {
			map.put(names[i], settings.getValue(names[i]));
		}
	}

	@Override
	public String toString() {
		return map.toString();
	}

	/**
	 *
	 * @see ghidra.docking.settings.Settings#isEmpty()
	 */
	@Override
	public boolean isEmpty() {
		return map.isEmpty();
	}

	/**
	 * @see ghidra.docking.settings.Settings#getLong(java.lang.String)
	 */
	@Override
	public Long getLong(String name) {
		Long value = (Long) map.get(name);
		if (value == null && defaultSettings != null) {
			value = defaultSettings.getLong(name);
		}
		return value;
	}

	/**
	 * @see ghidra.docking.settings.Settings#getString(java.lang.String)
	 */
	@Override
	public String getString(String name) {
		String value = (String) map.get(name);
		if (value == null && defaultSettings != null) {
			value = defaultSettings.getString(name);
		}
		return value;
	}

	/**
	 * @see ghidra.docking.settings.Settings#getByteArray(java.lang.String)
	 */
	@Override
	public byte[] getByteArray(String name) {
		byte[] bytes = (byte[]) map.get(name);
		if (bytes == null && defaultSettings != null) {
			bytes = defaultSettings.getByteArray(name);
		}
		return bytes;
	}

	/**
	 * @see ghidra.docking.settings.Settings#setLong(java.lang.String, long)
	 */
	@Override
	public void setLong(String name, long value) {
		map.put(name, new Long(value));
		changed();
	}

	/**
	 * @see ghidra.docking.settings.Settings#setString(java.lang.String, java.lang.String)
	 */
	@Override
	public void setString(String name, String value) {
		map.put(name, value);
		changed();
	}

	/**
	 * @see ghidra.docking.settings.Settings#setByteArray(java.lang.String, byte[])
	 */
	@Override
	public void setByteArray(String name, byte[] value) {
		map.put(name, value);
		changed();
	}

	/**
	 *
	 * @see ghidra.docking.settings.Settings#clearSetting(java.lang.String)
	 */
	@Override
	public void clearSetting(String name) {
		map.remove(name);
		changed();
	}

	/**
	 * @see ghidra.docking.settings.Settings#getNames()
	 */
	@Override
	public String[] getNames() {
		String[] names = new String[map.size()];
		Iterator<String> it = map.keySet().iterator();
		int i = 0;
		while (it.hasNext()) {
			names[i++] = it.next();
		}
		return names;
	}

	/**
	 * @see ghidra.docking.settings.Settings#getValue(java.lang.String)
	 */
	@Override
	public Object getValue(String name) {
		Object value = map.get(name);
		if (value == null && defaultSettings != null) {
			value = defaultSettings.getValue(name);
		}
		return value;
	}

	/**
	 * @see ghidra.docking.settings.Settings#setValue(java.lang.String, java.lang.Object)
	 */
	@Override
	public void setValue(String name, Object value) {
		if (value instanceof Long || value instanceof String || value instanceof byte[]) {
			map.put(name, value);
			changed();
			return;
		}
		throw new IllegalArgumentException("Value is not a known settings type");
	}

	private void changed() {
		if (listener != null) {
			ChangeEvent evt = null;
			if (changeSourceObj != null) {
				evt = new ChangeEvent(changeSourceObj);
			}
			listener.stateChanged(evt);
		}
	}

	/**
	 * @see ghidra.docking.settings.Settings#clearAllSettings()
	 */
	@Override
	public void clearAllSettings() {
		map.clear();
		changed();
	}

	public void setDefaultSettings(Settings settings) {
		defaultSettings = settings;
	}

	/**
	 * @see ghidra.docking.settings.Settings#getDefaultSettings()
	 */
	@Override
	public Settings getDefaultSettings() {
		return defaultSettings;
	}

}
