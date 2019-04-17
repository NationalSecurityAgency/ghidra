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

/**
 * A {@link SettingsDefinition} implementation that uses a real java {@link Enum}.
 *
 * @param <T> java Enum that defines the possible values to store.
 */
public class JavaEnumSettingsDefinition<T extends Enum<T>> implements EnumSettingsDefinition {

	private final String name;
	private final String settingName;
	private final String description;
	private final T[] values;
	protected final String[] valueNames;
	private final T defaultValue;

	/**
	 * Creates a new {@link JavaEnumSettingsDefinition}.
	 *
	 * @param settingName String that specifies how this setting is stored
	 * @param name Descriptive name of this setting
	 * @param description Longer description
	 * @param defaultValue Enum instance that will be returned when this {@link SettingsDefinition}
	 * has not been specified yet.
	 */
	public JavaEnumSettingsDefinition(String settingName, String name, String description,
			T defaultValue) {
		this.name = name;
		this.settingName = settingName;
		this.description = description;
		this.values = defaultValue.getDeclaringClass().getEnumConstants();
		this.defaultValue = defaultValue;
		String[] tmp = new String[values.length];
		for (int i = 0; i < values.length; i++) {
			tmp[i] = values[i].toString();
		}
		this.valueNames = tmp;
	}

	/**
	 * Returns the Enum instance that is the default Enum for this {@link SettingsDefinition}.
	 *
	 * @return Enum
	 */
	public T getDefaultEnum() {
		return defaultValue;
	}

	/**
	 * Returns an enum instance that corresponds to the setting stored, or the
	 * {@link #getDefaultEnum() default enum} if the setting has not been assigned yet.
	 *
	 * @param settings {@link Settings} object that stores the settings values.
	 * @return Enum&lt;T&gt; value, or {@link #getDefaultEnum()} if not present.
	 */
	public T getEnumValue(Settings settings) {
		return getEnumValue(settings, defaultValue);
	}

	/**
	 * Returns an enum instance that corresponds to the setting stored, or the
	 * a custom default value if the setting has not been assigned yet.
	 *
	 * @param settings {@link Settings} object that stores the settings values.
	 * @return Enum&lt;T&gt; value, or the specified defaultValueOveride if not present.
	 */
	public T getEnumValue(Settings settings, T defaultValueOverride) {
		Long lvalue = settings.getLong(getSettingName());
		if (lvalue == null) {
			return defaultValueOverride;
		}

		int valueOrdinal = (int) (long) lvalue;
		return (0 <= valueOrdinal && valueOrdinal < values.length) ? values[valueOrdinal]
				: defaultValueOverride;
	}

	/**
	 * Sets the value of this {@link SettingsDefinition} using the ordinal of the specified
	 * enum.
	 *
	 * @param settings Where {@link SettingsDefinition} values are stored.
	 * @param enumValue Enum to store
	 */
	public void setEnumValue(Settings settings, T enumValue) {
		setChoice(settings, enumValue.ordinal());
	}

	/**
	 * Returns the Enum instance that corresponds to the specified ordinal value.
	 *
	 * @param ordinal integer that corresponds to an Enum.
	 * @return Enum
	 */
	public T getEnumByOrdinal(int ordinal) {
		return values[ordinal];
	}

	/**
	 * returns the Enum's ordinal using the Enum's string representation.
	 *
	 * @param stringValue Enum's string rep
	 * @return integer index of the Enum
	 */
	public int getOrdinalByString(String stringValue) {
		for (int i = 0; i < valueNames.length; i++) {
			if (valueNames[i].equals(stringValue)) {
				return i;
			}
		}
		return -1;
	}

	/**
	 * The name of this setting as it is stored in a {@link Settings} object.
	 *
	 * @return String name.
	 */
	public String getSettingName() {
		return settingName;
	}

	@Override
	public boolean hasValue(Settings setting) {
		return setting.getValue(getSettingName()) != null;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getDescription() {
		return description;
	}

	@Override
	public void clear(Settings settings) {
		settings.clearSetting(getSettingName());
	}

	@Override
	public void copySetting(Settings srcSettings, Settings destSettings) {
		Long l = srcSettings.getLong(getSettingName());
		if (l == null) {
			clear(destSettings);
		}
		else {
			setChoice(destSettings, (int) (long) l);
		}
	}

	@Override
	public int getChoice(Settings settings) {
		Long lvalue = settings.getLong(getSettingName());

		int value = (lvalue != null) ? (int) (long) lvalue : defaultValue.ordinal();
		return Math.min(Math.max(value, 0), values.length - 1);
	}

	@Override
	public void setChoice(Settings settings, int value) {
		settings.setLong(getSettingName(), value);
	}

	@Override
	public String getDisplayChoice(int value, Settings settings) {
		return values[value].toString();
	}

	@Override
	public String[] getDisplayChoices(Settings settings) {
		return valueNames;
	}

}
