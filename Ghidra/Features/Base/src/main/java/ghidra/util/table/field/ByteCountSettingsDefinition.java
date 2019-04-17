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

public class ByteCountSettingsDefinition implements EnumSettingsDefinition {

	private static final String BYTE_COUNT = "Byte count";
	public static final ByteCountSettingsDefinition DEF = new ByteCountSettingsDefinition();

	public static final int DEFAULT = 0;
	public static final int MAX_BYTE_COUNT = 8;

	private static final String[] choices = { "default", "1", "2", "3", "4", "5", "6", "7", "8" };

	private ByteCountSettingsDefinition() {
	}

	@Override
	public int getChoice(Settings settings) {
		if (settings == null) {
			return DEFAULT;
		}
		Long value = settings.getLong(BYTE_COUNT);
		if (value == null) {
			return DEFAULT;
		}
		return value.intValue();
	}

	@Override
	public void setChoice(Settings settings, int value) {
		if (value < DEFAULT) {
			settings.clearSetting(BYTE_COUNT);
		}
		else {
			if (value > MAX_BYTE_COUNT) {
				value = MAX_BYTE_COUNT;
			}
			settings.setLong(BYTE_COUNT, value);
		}
	}

	@Override
	public String[] getDisplayChoices(Settings settings) {
		return choices;
	}

	@Override
	public String getName() {
		return BYTE_COUNT;
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
		settings.clearSetting(BYTE_COUNT);
	}

	@Override
	public void copySetting(Settings settings, Settings destSettings) {
		Long l = settings.getLong(BYTE_COUNT);
		if (l == null) {
			destSettings.clearSetting(BYTE_COUNT);
		}
		else {
			destSettings.setLong(BYTE_COUNT, l);
		}
	}

	@Override
	public boolean hasValue(Settings setting) {
		return setting.getValue(BYTE_COUNT) != null;
	}

}
