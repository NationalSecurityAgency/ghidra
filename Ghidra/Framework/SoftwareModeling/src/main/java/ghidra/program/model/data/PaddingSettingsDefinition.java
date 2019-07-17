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

/**
 * The Settings definition for setting the padded/unpadded setting
 */
public class PaddingSettingsDefinition implements EnumSettingsDefinition {

	private static final int PADDED_VALUE = 1;
	private static final int UNPADDED_VALUE = 0;
	private static final String[] choices = { "unpadded", "padded" };
	private static final String PADDED = "padded";

	public static final PaddingSettingsDefinition DEF = new PaddingSettingsDefinition();

	private PaddingSettingsDefinition() {
	}

	/**
	 * Checks if the current settings are padded or unpadded
	 * @param settings the instance settings to check
	 * @return true if the value is "padded".
	 */
	public boolean isPadded(Settings settings) {
		if (settings == null) {
			return false;
		}
		Long value = settings.getLong(PADDED);
		if (value == null) {
			return false;
		}
		return (value.longValue() != UNPADDED_VALUE);
	}

	/**
	 * Set true if value should display padded out with zero's
	 * @param settings settings to set padded value
	 * @param isPadded true for padding
	 */
	public void setPadded(Settings settings, boolean isPadded) {
		setChoice(settings, isPadded ? PADDED_VALUE : UNPADDED_VALUE);
	}

	@Override
	public int getChoice(Settings settings) {
		if (isPadded(settings)) {
			return PADDED_VALUE;
		}
		return UNPADDED_VALUE;
	}

	@Override
	public void setChoice(Settings settings, int value) {
		settings.setLong(PADDED, value);
	}

	@Override
	public String[] getDisplayChoices(Settings settings) {
		return choices;
	}

	@Override
	public String getName() {
		return "Padding";
	}

	@Override
	public String getDescription() {
		return "Selects if the data is padded or not";
	}

	@Override
	public String getDisplayChoice(int value, Settings s1) {
		return choices[value];
	}

	@Override
	public void clear(Settings settings) {
		settings.clearSetting(PADDED);
	}

	@Override
	public void copySetting(Settings settings, Settings destSettings) {
		Long l = settings.getLong(PADDED);
		if (l == null) {
			destSettings.clearSetting(PADDED);
		}
		else {
			destSettings.setLong(PADDED, l);
		}
	}

	@Override
	public boolean hasValue(Settings setting) {
		return setting.getValue(PADDED) != null;
	}

}
