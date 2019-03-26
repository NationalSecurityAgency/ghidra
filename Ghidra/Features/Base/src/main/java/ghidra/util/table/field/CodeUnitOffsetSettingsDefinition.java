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

public class CodeUnitOffsetSettingsDefinition implements EnumSettingsDefinition {

	private static final String MEMORY_OFFSET = "Code-unit offset";
	public static final CodeUnitOffsetSettingsDefinition DEF =
		new CodeUnitOffsetSettingsDefinition();

	public static final int DEFAULT_OFFSET = 0;
	public static final int MIN_OFFSET = -8;
	public static final int MAX_OFFSET = 8;

	public static final int DEFAULT_CHOICE = 8; // index into choices

	private static final String[] choices = { "-8", "-7", "-6", "-5", "-4", "-3", "-2", "-1", "0",
		"+1", "+2", "+3", "+4", "+5", "+6", "+7", "+8" };

	private CodeUnitOffsetSettingsDefinition() {
	}

	public int getOffset(Settings settings) {
		return getChoice(settings) - DEFAULT_CHOICE;
	}

	public void setOffset(Settings settings, int offset) {
		if (offset < MIN_OFFSET) {
			offset = MIN_OFFSET;
		}
		if (offset > MAX_OFFSET) {
			offset = MAX_OFFSET;
		}
		settings.setLong(MEMORY_OFFSET, offset + DEFAULT_CHOICE);
	}

	@Override
	public int getChoice(Settings settings) {
		if (settings == null) {
			return DEFAULT_CHOICE;
		}
		Long value = settings.getLong(MEMORY_OFFSET);
		if (value == null) {
			return DEFAULT_CHOICE;
		}
		return value.intValue();
	}

	@Override
	public void setChoice(Settings settings, int value) {
		if (value < 0) {
			value = 0;
		}
		if (value > choices.length - 1) {
			value = choices.length - 1;
		}
		settings.setLong(MEMORY_OFFSET, value);
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
		return MEMORY_OFFSET;
	}

	@Override
	public String getDescription() {
		return "Selects the relative byte offset from which to display";
	}

	@Override
	public String getDisplayChoice(int value, Settings s1) {
		return choices[value];
	}

	@Override
	public void clear(Settings settings) {
		settings.clearSetting(MEMORY_OFFSET);
	}

	@Override
	public void copySetting(Settings settings, Settings destSettings) {
		Long l = settings.getLong(MEMORY_OFFSET);
		if (l == null) {
			destSettings.clearSetting(MEMORY_OFFSET);
		}
		else {
			destSettings.setLong(MEMORY_OFFSET, l);
		}
	}

	@Override
	public boolean hasValue(Settings setting) {
		return setting.getValue(MEMORY_OFFSET) != null;
	}

}
