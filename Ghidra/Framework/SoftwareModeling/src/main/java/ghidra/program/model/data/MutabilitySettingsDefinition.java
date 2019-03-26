/* ###
 * IP: GHIDRA
 * NOTE: seriously?  how many different ways can YOU spell "mutable?"
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
 * The settings definition for the numeric display format
 */
public class MutabilitySettingsDefinition implements EnumSettingsDefinition {

	public static final int NORMAL = 0;
	public static final int VOLATILE = 1;
	public static final int CONSTANT = 2;

	//NOTE: if these strings change, the XML needs to changed also...
	private static final String[] choices = { "normal", "volatile", "constant" };
	public static final String MUTABILITY = "mutability";

	public static final MutabilitySettingsDefinition DEF = new MutabilitySettingsDefinition();

	private MutabilitySettingsDefinition() {
	}

	/**
	 * Returns the mutability mode based on the current settings
	 * @param settings the instance settings.
	 * @return the current format value
	 */
	public int getMutabilityMode(Settings settings) {
		if (settings == null) {
			return NORMAL;
		}
		Long value = settings.getLong(MUTABILITY);
		if (value == null) {
			return NORMAL;
		}
		int mode = (int) value.longValue();
		if ((mode < 0) || (mode > CONSTANT)) {
			mode = NORMAL;
		}
		return mode;
	}

	@Override
	public int getChoice(Settings settings) {
		return getMutabilityMode(settings);
	}

	@Override
	public void setChoice(Settings settings, int value) {
		if (value < 0 || value > CONSTANT) {
			settings.clearSetting(MUTABILITY);
		}
		else {
			settings.setLong(MUTABILITY, value);
		}
	}

	@Override
	public String[] getDisplayChoices(Settings settings) {
		return choices;
	}

	@Override
	public String getName() {
		return "Mutability";
	}

	@Override
	public String getDescription() {
		return "Selects the data mutability";
	}

	@Override
	public String getDisplayChoice(int value, Settings s1) {
		return choices[value];
	}

	@Override
	public void clear(Settings settings) {
		settings.clearSetting(MUTABILITY);
	}

	@Override
	public void copySetting(Settings settings, Settings destSettings) {
		Long l = settings.getLong(MUTABILITY);
		if (l == null) {
			destSettings.clearSetting(MUTABILITY);
		}
		else {
			destSettings.setLong(MUTABILITY, l);
		}
	}

	@Override
	public boolean hasValue(Settings setting) {
		return setting.getValue(MUTABILITY) != null;
	}

}
