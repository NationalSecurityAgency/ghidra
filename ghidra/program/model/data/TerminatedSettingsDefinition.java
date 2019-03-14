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
 * Settings definition for strings being terminated or unterminated
 */
public class TerminatedSettingsDefinition implements EnumSettingsDefinition {

	private static final int UNTERMINATED_VALUE = 0;
	private static final int TERMINATED_VALUE = 1;
	private static final String[] choices = { "unterminated", "terminated" };
	private static final String TERMINATED = "terminated";

	public static final TerminatedSettingsDefinition DEF = new TerminatedSettingsDefinition();

	private TerminatedSettingsDefinition() {
	}

	/**
	 * Gets the current termination setting from the given settings objects or returns
	 * the default if not in either settings object
	 * @param settings the instance settings
	 * @return the current value for this settings definition
	 */
	public boolean isTerminated(Settings settings) {
		if (settings == null) {
			return false;
		}
		Long value = settings.getLong(TERMINATED);
		if (value == null) {
			return false;
		}
		return (value.longValue() == TERMINATED_VALUE);
	}

	public void setTerminated(Settings settings, boolean isTerminated) {
		setChoice(settings, isTerminated ? TERMINATED_VALUE : UNTERMINATED_VALUE);
	}

	@Override
	public int getChoice(Settings settings) {
		if (isTerminated(settings)) {
			return TERMINATED_VALUE;
		}
		return UNTERMINATED_VALUE;
	}

	@Override
	public void setChoice(Settings settings, int value) {
		settings.setLong(TERMINATED, value);
	}

	@Override
	public String[] getDisplayChoices(Settings settings) {
		return choices;
	}

	@Override
	public String getName() {
		return "Termination";
	}

	@Override
	public String getDescription() {
		return "Selects if the string is terminated or unterminated";
	}

	@Override
	public String getDisplayChoice(int value, Settings s1) {
		return choices[value];
	}

	@Override
	public void clear(Settings settings) {
		settings.clearSetting(TERMINATED);

	}

	@Override
	public void copySetting(Settings settings, Settings destSettings) {
		Long l = settings.getLong(TERMINATED);
		if (l == null) {
			destSettings.clearSetting(TERMINATED);
		}
		else {
			destSettings.setLong(TERMINATED, l);
		}
	}

	@Override
	public boolean hasValue(Settings setting) {
		return setting.getValue(TERMINATED) != null;
	}

}
