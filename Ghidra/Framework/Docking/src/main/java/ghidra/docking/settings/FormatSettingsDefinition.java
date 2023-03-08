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
 * The settings definition for the numeric display format
 */
public class FormatSettingsDefinition implements EnumSettingsDefinition {

	public static final int HEX = 0;
	public static final int DECIMAL = 1;
	public static final int BINARY = 2;
	public static final int OCTAL = 3;
	public static final int CHAR = 4;

	//NOTE: if these strings change, the XML needs to changed also...
	private static final String[] choices = { "hex", "decimal", "binary", "octal", "char" };
	private static final String[] valuePostfix = { "h", "", "b", "o", "" };
	private static final int[] radix = { 16, 10, 2, 8, 0 };

	protected static final String FORMAT = "format";

	// Definitions with each settings as a default
	public static final FormatSettingsDefinition DEF_HEX = new FormatSettingsDefinition(HEX);
	public static final FormatSettingsDefinition DEF_DECIMAL =
		new FormatSettingsDefinition(DECIMAL);
	public static final FormatSettingsDefinition DEF_BINARY = new FormatSettingsDefinition(BINARY);
	public static final FormatSettingsDefinition DEF_OCTAL = new FormatSettingsDefinition(OCTAL);
	public static final FormatSettingsDefinition DEF_CHAR = new FormatSettingsDefinition(CHAR);

	public static final FormatSettingsDefinition DEF = DEF_HEX; // Default is HEX

	private final int defaultFormat;

	private FormatSettingsDefinition(int defaultFormat) {
		this.defaultFormat = defaultFormat;
	}

	/**
	 * Returns the format based on the specified settings
	 * 
	 * @param settings the instance settings or null for default value.
	 * @return the format value (HEX, DECIMAL, BINARY, OCTAL, CHAR), or HEX if invalid
	 * data in the FORMAT settings value
	 */
	public int getFormat(Settings settings) {
		if (settings == null) {
			return defaultFormat;
		}
		Long value = settings.getLong(FORMAT);
		if (value == null) {
			return defaultFormat;
		}
		int format = (int) value.longValue();
		if ((format < 0) || (format > CHAR)) {
			format = HEX;
		}
		return format;
	}

	/**
	 * Returns the numeric radix associated with the format identified by the specified settings.
	 * 
	 * @param settings the instance settings.
	 * @return the format radix
	 */
	public int getRadix(Settings settings) {
		return radix[getFormat(settings)];
	}

	/**
	 * Returns a descriptive string suffix that should be appended after converting a value
	 * using the radix returned by {@link #getRadix(Settings)}.
	 * 
	 * @param settings the instance settings
	 * @return string suffix, such as "h" for HEX, "o" for octal
	 */
	public String getRepresentationPostfix(Settings settings) {
		return valuePostfix[getFormat(settings)];
	}

	@Override
	public int getChoice(Settings settings) {
		return getFormat(settings);
	}

	@Override
	public String getValueString(Settings settings) {
		return choices[getChoice(settings)];
	}

	@Override
	public void setChoice(Settings settings, int value) {
		if (value < 0 || value > CHAR) {
			settings.clearSetting(FORMAT);
		}
		else {
			settings.setLong(FORMAT, value);
		}
	}

	@Override
	public String[] getDisplayChoices(Settings settings) {
		return choices;
	}

	@Override
	public String getName() {
		return "Format";
	}

	@Override
	public String getStorageKey() {
		return FORMAT;
	}

	@Override
	public String getDescription() {
		return "Selects the display format";
	}

	@Override
	public String getDisplayChoice(int value, Settings s1) {
		return choices[value];
	}

	@Override
	public void clear(Settings settings) {
		settings.clearSetting(FORMAT);
	}

	@Override
	public void copySetting(Settings settings, Settings destSettings) {
		Long l = settings.getLong(FORMAT);
		if (l == null) {
			destSettings.clearSetting(FORMAT);
		}
		else {
			destSettings.setLong(FORMAT, l);
		}
	}

	@Override
	public boolean hasValue(Settings setting) {
		return setting.getValue(FORMAT) != null;
	}

	public String getDisplayChoice(Settings settings) {
		return choices[getChoice(settings)];
	}

	/**
	 * Sets the settings object to the enum value indicating the specified choice as a string.
	 * 
	 * @param settings the settings to store the value.
	 * @param choice enum string representing a choice in the enum.
	 */
	public void setDisplayChoice(Settings settings, String choice) {
		for (int i = 0; i < choices.length; i++) {
			if (choices[i].equals(choice)) {
				setChoice(settings, i);
				break;
			}
		}
	}

}
