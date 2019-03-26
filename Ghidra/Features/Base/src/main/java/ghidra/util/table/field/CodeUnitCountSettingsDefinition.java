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
package ghidra.util.table.field;

import ghidra.docking.settings.EnumSettingsDefinition;
import ghidra.docking.settings.Settings;

public class CodeUnitCountSettingsDefinition implements EnumSettingsDefinition {

	private static final String CODE_UNIT_COUNT = "Code-unit count";
	public static final CodeUnitCountSettingsDefinition DEF = new CodeUnitCountSettingsDefinition();

	public static final int MAX_CODE_UNIT_COUNT = 8;

	private static final String[] choices = { "1", "2", "3", "4", "5", "6", "7", "8" };

	private CodeUnitCountSettingsDefinition() {
	}

	public int getCount(Settings settings) {
		return getChoice(settings) + 1;
	}

	public void setCount(Settings settings, int count) {
		if (count < 1) {
			settings.clearSetting(CODE_UNIT_COUNT);
		}
		else {
			if (count > MAX_CODE_UNIT_COUNT) {
				count = MAX_CODE_UNIT_COUNT;
			}
			settings.setLong(CODE_UNIT_COUNT, count - 1);
		}
	}

	@Override
	public int getChoice(Settings settings) {
		if (settings == null) {
			return 0;
		}
		Long value = settings.getLong(CODE_UNIT_COUNT);
		if (value == null) {
			return 0;
		}
		return value.intValue();
	}

	@Override
	public void setChoice(Settings settings, int value) {
		if (value < 0) {
			settings.clearSetting(CODE_UNIT_COUNT);
		}
		else {
			if (value > choices.length - 1) {
				value = choices.length - 1;
			}
			settings.setLong(CODE_UNIT_COUNT, value);
		}
	}

	public String getDisplayValue(Settings settings) {
		return choices[getChoice(settings)];
	}

	@Override
	public String[] getDisplayChoices(Settings settings) {
		return choices;
	}

	@Override
	public String getName() {
		return CODE_UNIT_COUNT;
	}

	@Override
	public String getDescription() {
		return "Selects the number of bytes to display";
	}

	@Override
	public String getDisplayChoice(int value, Settings s1) {
		return choices[value];
	}

	@Override
	public void clear(Settings settings) {
		settings.clearSetting(CODE_UNIT_COUNT);
	}

	@Override
	public void copySetting(Settings settings, Settings destSettings) {
		Long l = settings.getLong(CODE_UNIT_COUNT);
		if (l == null) {
			destSettings.clearSetting(CODE_UNIT_COUNT);
		}
		else {
			destSettings.setLong(CODE_UNIT_COUNT, l);
		}
	}

	@Override
	public boolean hasValue(Settings setting) {
		return setting.getValue(CODE_UNIT_COUNT) != null;
	}

}
