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
package ghidra.program.model.data;

import ghidra.docking.settings.EnumSettingsDefinition;
import ghidra.docking.settings.Settings;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.mem.MemBuffer;

/**
 *  SettingsDefinition for endianess
 */
public class EndianSettingsDefinition implements EnumSettingsDefinition {

	private static final String[] choices = { "default", "little", "big" };
	private static final String ENDIAN_SETTING_NAME = "endian";

	public static final EndianSettingsDefinition DEF = new EndianSettingsDefinition();
	public static final EndianSettingsDefinition ENDIAN = DEF;
	public static final int DEFAULT = 0;
	public static final int LITTLE = 1;
	public static final int BIG = 2;

	/**
	 * Constructs a new EndianSettingsDefinition
	 */
	private EndianSettingsDefinition() {
	}

	/**
	 * Returns the endianess settings.  First looks in settings, then defaultSettings
	 * and finally returns a default value if the first two have no value for this definition.
	 * @param settings the instance settings to search for the value
	 * @param buf the data context
	 * @return a boolean value for the endianess setting
	 */
	public boolean isBigEndian(Settings settings, MemBuffer buf) {
		int val = getChoice(settings);
		if (val == DEFAULT) {
			return buf.isBigEndian();
		}
		return val == BIG;
	}

	public Endian getEndianess(Settings settings, Endian defaultValue) {
		int val = getChoice(settings);
		switch (val) {
			default:
			case DEFAULT:
				return defaultValue;
			case BIG:
				return Endian.BIG;
			case LITTLE:
				return Endian.LITTLE;
		}
	}

	public void setBigEndian(Settings settings, boolean isBigEndian) {
		setChoice(settings, isBigEndian ? BIG : LITTLE);
	}

	@Override
	public int getChoice(Settings settings) {
		if (settings == null) {
			return DEFAULT;
		}
		Long value = settings.getLong(ENDIAN_SETTING_NAME);
		if (value == null) {
			return DEFAULT;
		}
		int val = value.intValue();
		if (val < DEFAULT || val > BIG) {
			val = DEFAULT;
		}
		return val;
	}

	@Override
	public void setChoice(Settings settings, int value) {
		settings.setLong(ENDIAN_SETTING_NAME, value);
	}

	@Override
	public String[] getDisplayChoices(Settings settings) {
		return choices;
	}

	@Override
	public String getName() {
		return "Endian";
	}

	@Override
	public String getDescription() {
		return "Selects the endianess of the data";
	}

	@Override
	public String getDisplayChoice(int value, Settings settings) {
		return choices[value];
	}

	@Override
	public void clear(Settings settings) {
		settings.clearSetting(ENDIAN_SETTING_NAME);

	}

	@Override
	public void copySetting(Settings settings, Settings destSettings) {
		Long l = settings.getLong(ENDIAN_SETTING_NAME);
		if (l == null) {
			destSettings.clearSetting(ENDIAN_SETTING_NAME);
		}
		else {
			destSettings.setLong(ENDIAN_SETTING_NAME, l);
		}
	}

	@Override
	public boolean hasValue(Settings setting) {
		return setting.getValue(ENDIAN_SETTING_NAME) != null;
	}

}
