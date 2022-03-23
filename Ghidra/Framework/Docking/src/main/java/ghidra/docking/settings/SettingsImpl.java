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

import javax.help.UnsupportedOperationException;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import com.google.common.base.Predicate;

import ghidra.util.Msg;

/**
 * Basic implementation of the Settings object
 */
public class SettingsImpl implements Settings, Serializable {
	private final static long serialVersionUID = 1;

	private Map<String, Object> map;
	private Settings defaultSettings;
	private ChangeListener listener;
	private Object changeSourceObj;
	private boolean immutable;
	private Predicate<String> allowedSettingPredicate;

	//@formatter:off
	public static final Settings NO_SETTINGS = new SettingsImpl(true) {
		@Override
		public void setDefaultSettings(Settings settings) {
			throw new UnsupportedOperationException();
		}
	};
	//@formatter:on

	/**
	 *  Construct a new SettingsImpl.
	 */
	public SettingsImpl() {
		map = new HashMap<>();
	}

	/**
	 *  Construct a new SettingsImpl with a modification predicate.
	 *  @param allowedSettingPredicate callback for checking an allowed setting modification
	 */
	public SettingsImpl(Predicate<String> allowedSettingPredicate) {
		map = new HashMap<>();
		this.allowedSettingPredicate = allowedSettingPredicate;
	}

	/**
	 * Construct a new SettingsImpl object.  If settings object is specified this
	 * settings will copy all name/value pairs and underlying defaults.
	 * @param settings the settings object to copy
	 */
	public SettingsImpl(Settings settings) {
		this();
		if (settings != null) {
			String[] names = settings.getNames();
			for (int i = 0; i < names.length; i++) {
				map.put(names[i], settings.getValue(names[i]));
			}
			defaultSettings = settings.getDefaultSettings();
		}
	}

	/**
	 *  Construct a new SettingsImpl.
	 *  @param immutable if true settings are immutable with the exception of
	 *  setting its default settings.  If false settings may be modified.
	 */
	public SettingsImpl(boolean immutable) {
		this.immutable = immutable;
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

	@Override
	public boolean isChangeAllowed(SettingsDefinition settingsDefinition) {
		if (immutable) {
			return false;
		}
		if (allowedSettingPredicate != null &&
			!allowedSettingPredicate.apply(settingsDefinition.getStorageKey())) {
			return false;
		}
		return true;
	}

	/**
	 * Check for immutable or restricted settings and log error of modification not permitted
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
		if (immutable) {
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

	@Override
	public String toString() {
		return map.toString();
	}

	@Override
	public boolean isEmpty() {
		return map.isEmpty();
	}

	@Override
	public Long getLong(String name) {
		Long value = (Long) map.get(name);
		if (value == null && defaultSettings != null) {
			value = defaultSettings.getLong(name);
		}
		return value;
	}

	@Override
	public String getString(String name) {
		if (map.containsKey(name)) {
			return (String) map.get(name); // null may be allowed/set
		}
		if (defaultSettings != null) {
			return defaultSettings.getString(name);
		}
		return null;
	}

	@Override
	public void setLong(String name, long value) {
		if (checkSetting("long", name)) {
			map.put(name, Long.valueOf(value));
			changed();
		}
	}

	@Override
	public void setString(String name, String value) {
		if (checkSetting("string", name)) {
			map.put(name, value);
			changed();
		}
	}

	@Override
	public void clearSetting(String name) {
		if (checkImmutableSetting(null, name)) {
			map.remove(name);
			changed();
		}
	}

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

	@Override
	public Object getValue(String name) {
		Object value = map.get(name);
		if (value == null && defaultSettings != null) {
			value = defaultSettings.getValue(name);
		}
		return value;
	}

	@Override
	public void setValue(String name, Object value) {
		if (!checkSetting(null, name)) {
			return;
		}
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

	@Override
	public void clearAllSettings() {
		if (map.isEmpty()) {
			return;
		}
		if (checkImmutableSetting(null, null)) {
			map.clear();
			changed();
		}
	}

	public void setDefaultSettings(Settings settings) {
		defaultSettings = settings;
	}

	@Override
	public Settings getDefaultSettings() {
		return defaultSettings;
	}

}
