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

import ghidra.docking.settings.BooleanSettingsDefinition;
import ghidra.docking.settings.Settings;

public class FunctionThunkSettingsDefinition implements BooleanSettingsDefinition {

	public static final FunctionThunkSettingsDefinition DEF = new FunctionThunkSettingsDefinition();

	private static final String THUNK = "Show thunk";
	private static final String NAME = THUNK;
	private static final String DESCRIPTION =
		"On siganls to show the thunk " + "function attribute when present";
	private static final boolean DEFAULT = true;

	@Override
	public boolean getValue(Settings settings) {
		if (settings == null) {
			return DEFAULT;
		}
		String value = settings.getString(THUNK);
		if (value == null) {
			return DEFAULT;
		}
		return Boolean.parseBoolean(value);
	}

	@Override
	public void setValue(Settings settings, boolean value) {
		settings.setString(THUNK, Boolean.toString(value));
	}

	@Override
	public void copySetting(Settings srcSettings, Settings destSettings) {
		String value = srcSettings.getString(THUNK);
		if (value == null) {
			destSettings.clearSetting(THUNK);
		}
		else {
			destSettings.setString(THUNK, value);
		}
	}

	@Override
	public void clear(Settings settings) {
		settings.clearSetting(THUNK);
	}

	@Override
	public String getDescription() {
		return DESCRIPTION;
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public boolean hasValue(Settings settings) {
		return settings.getValue(THUNK) != null;
	}

}
