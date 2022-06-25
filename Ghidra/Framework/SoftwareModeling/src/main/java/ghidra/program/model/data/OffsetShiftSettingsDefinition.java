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

import java.math.BigInteger;

import ghidra.docking.settings.NumberSettingsDefinition;
import ghidra.docking.settings.Settings;

public class OffsetShiftSettingsDefinition
		implements NumberSettingsDefinition, TypeDefSettingsDefinition {

	private static final String OFFSET_SHIFT_SETTING_NAME = "offset_shift";
	private static final String DESCRIPTION =
		"Identifies bit-shift to be applied to a stored pointer offset (+left/-right)";
	private static final String DISPLAY_NAME = "Offset Shift";
	private static BigInteger MAX_VALUE = BigInteger.valueOf(64);

	private static final int DEFAULT = 0;

	public static final OffsetShiftSettingsDefinition DEF =
		new OffsetShiftSettingsDefinition();

	private OffsetShiftSettingsDefinition() {
	}

	@Override
	public BigInteger getMaxValue() {
		return MAX_VALUE;
	}

	@Override
	public boolean allowNegativeValue() {
		return true;
	}

	@Override
	public boolean isHexModePreferred() {
		return false;
	}

	@Override
	public long getValue(Settings settings) {
		if (settings == null) {
			return DEFAULT;
		}
		Long value = settings.getLong(OFFSET_SHIFT_SETTING_NAME);
		if (value == null) {
			return DEFAULT;
		}
		return value;
	}

	@Override
	public void setValue(Settings settings, long value) {
		if (value == DEFAULT) {
			settings.clearSetting(OFFSET_SHIFT_SETTING_NAME);
		}
		else {
			settings.setLong(OFFSET_SHIFT_SETTING_NAME, value);
		}
	}

	@Override
	public boolean hasValue(Settings settings) {
		return getValue(settings) != DEFAULT;
	}

	@Override
	public String getName() {
		return DISPLAY_NAME;
	}

	@Override
	public String getStorageKey() {
		return OFFSET_SHIFT_SETTING_NAME;
	}

	@Override
	public String getDescription() {
		return DESCRIPTION;
	}

	@Override
	public void clear(Settings settings) {
		settings.clearSetting(OFFSET_SHIFT_SETTING_NAME);
	}

	@Override
	public void copySetting(Settings srcSettings, Settings destSettings) {
		Long value = srcSettings.getLong(OFFSET_SHIFT_SETTING_NAME);
		if (value == null) {
			destSettings.clearSetting(OFFSET_SHIFT_SETTING_NAME);
		}
		else {
			destSettings.setLong(OFFSET_SHIFT_SETTING_NAME, value);
		}
	}

	@Override
	public String getAttributeSpecification(Settings settings) {
		if (hasValue(settings)) {
			long shift = getValue(settings);
			return "shift(" + Long.toString(shift) + ")";
		}
		return null;
	}

}
