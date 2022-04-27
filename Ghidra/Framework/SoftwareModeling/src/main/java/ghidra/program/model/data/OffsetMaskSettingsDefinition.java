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

/**
 * Setting definition for a pointer offset bit-mask to be applied prior to any 
 * bit-shift (if specified) during the computation of an actual address offset.  
 * Mask is defined as an unsigned long value where
 * a value of zero (0) is ignored and has no affect on pointer computation.
 */
public class OffsetMaskSettingsDefinition
		implements NumberSettingsDefinition, TypeDefSettingsDefinition {

	private static final String OFFSET_MASK_SETTING_NAME = "offset_mask";
	private static final String DESCRIPTION =
		"Identifies bit-mask to be applied to a stored pointer offset prior to any shift";
	private static final String DISPLAY_NAME = "Offset Mask";
	private static BigInteger MAX_VALUE = new BigInteger("0ffffffffffffffff", 16);

	public static final long DEFAULT = -1; // unsigned mask - all bits are ones

	public static final OffsetMaskSettingsDefinition DEF =
		new OffsetMaskSettingsDefinition();

	private OffsetMaskSettingsDefinition() {
	}

	@Override
	public BigInteger getMaxValue() {
		return MAX_VALUE;
	}

	@Override
	public boolean allowNegativeValue() {
		return false;
	}

	@Override
	public boolean isHexModePreferred() {
		return true;
	}

	@Override
	public long getValue(Settings settings) {
		if (settings == null) {
			return DEFAULT;
		}
		Long value = settings.getLong(OFFSET_MASK_SETTING_NAME);
		if (value == null) {
			return DEFAULT;
		}
		return value;
	}

	@Override
	public void setValue(Settings settings, long value) {
		if (value == 0 || value == DEFAULT) {
			settings.clearSetting(OFFSET_MASK_SETTING_NAME);
		}
		else {
			settings.setLong(OFFSET_MASK_SETTING_NAME, value);
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
		return OFFSET_MASK_SETTING_NAME;
	}

	@Override
	public String getDescription() {
		return DESCRIPTION;
	}

	@Override
	public void clear(Settings settings) {
		settings.clearSetting(OFFSET_MASK_SETTING_NAME);
	}

	@Override
	public void copySetting(Settings srcSettings, Settings destSettings) {
		Long value = srcSettings.getLong(OFFSET_MASK_SETTING_NAME);
		if (value == null) {
			destSettings.clearSetting(OFFSET_MASK_SETTING_NAME);
		}
		else {
			destSettings.setLong(OFFSET_MASK_SETTING_NAME, value);
		}
	}

	@Override
	public String getAttributeSpecification(Settings settings) {
		if (hasValue(settings)) {
			long mask = getValue(settings);
			return "mask(0x" + Long.toHexString(mask) + ")";
		}
		return null;
	}

}
