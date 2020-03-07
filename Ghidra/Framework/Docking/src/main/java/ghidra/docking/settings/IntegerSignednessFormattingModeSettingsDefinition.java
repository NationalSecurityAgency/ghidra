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

import ghidra.util.SignednessFormatMode;

/**
 * The settings definition for the numeric display format for handling signed values.
 * <br>
 */
public class IntegerSignednessFormattingModeSettingsDefinition implements EnumSettingsDefinition {

	//NOTE: if these strings change, the XML needs to changed also...
	private static final String[] choices = { "Default", "Unsigned", "Signed" };

	protected static final String SIGN_FORMAT = "signedness-mode";

	public static final IntegerSignednessFormattingModeSettingsDefinition DEF =
			new IntegerSignednessFormattingModeSettingsDefinition(SignednessFormatMode.DEFAULT);
	public static final IntegerSignednessFormattingModeSettingsDefinition DEF_SIGNED =
			new IntegerSignednessFormattingModeSettingsDefinition(SignednessFormatMode.SIGNED);
	public static final IntegerSignednessFormattingModeSettingsDefinition DEF_UNSIGNED =
			new IntegerSignednessFormattingModeSettingsDefinition(SignednessFormatMode.UNSIGNED);

	private final SignednessFormatMode defaultFormat;

	private IntegerSignednessFormattingModeSettingsDefinition(SignednessFormatMode defaultFormat) {
		this.defaultFormat = defaultFormat;
	}

	/**
	 * Returns the format based on the specified settings
	 * @param settings the instance settings or null for default value.
	 * @return the format mode
	 */
	public SignednessFormatMode getFormatMode(Settings settings) {
		if (settings == null) {
			return defaultFormat;
		}
		Long value = settings.getLong(SIGN_FORMAT);
		if (value == null) {
			return defaultFormat;
		}
		int format = (int) value.longValue();

		SignednessFormatMode mode = SignednessFormatMode.DEFAULT;
		try {
			mode = SignednessFormatMode.parse(format);
		}
		catch (IllegalArgumentException iae) {
			// ignored
		}

		return mode;
	}

	@Override
	public int getChoice(Settings settings) {
		return getFormatMode(settings).ordinal();
	}

	/**
	 * Set, or clear if <code>mode</code> is null, the new mode in the provided settings
	 * @param settings settings object
	 * @param mode new value to assign, or null to clear
	 */
	public void setFormatMode(Settings settings, SignednessFormatMode mode) {
		if (mode == null) {
			settings.clearSetting(SIGN_FORMAT);
			return;
		}
		settings.setLong(SIGN_FORMAT, mode.ordinal());
	}

	@Override
	public void setChoice(Settings settings, int value) {

		try {
			SignednessFormatMode mode = SignednessFormatMode.parse(value);
			settings.setLong(SIGN_FORMAT, mode.ordinal());

		}
		catch (IllegalArgumentException iae) {
			settings.clearSetting(SIGN_FORMAT);
		}
	}

	@Override
	public String[] getDisplayChoices(Settings settings) {
		return choices;
	}

	@Override
	public String getName() {
		return "Signedness Mode";
	}

	@Override
	public String getDescription() {
		return "Selects the display mode for signed values";
	}

	@Override
	public String getDisplayChoice(int value, Settings s1) {
		return choices[value];
	}

	@Override
	public void clear(Settings settings) {
		settings.clearSetting(SIGN_FORMAT);
	}

	@Override
	public void copySetting(Settings settings, Settings destSettings) {
		Long l = settings.getLong(SIGN_FORMAT);
		if (l == null) {
			destSettings.clearSetting(SIGN_FORMAT);
		}
		else {
			destSettings.setLong(SIGN_FORMAT, l);
		}
	}

	@Override
	public boolean hasValue(Settings setting) {
		return setting.getValue(SIGN_FORMAT) != null;
	}

	public String getDisplayChoice(Settings settings) {
		return choices[getChoice(settings)];
	}

	/**
	 * Sets the settings object to the enum value indicating the specified choice as a string.
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
