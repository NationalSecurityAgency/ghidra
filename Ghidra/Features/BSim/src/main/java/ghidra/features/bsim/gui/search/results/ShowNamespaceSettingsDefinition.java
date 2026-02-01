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
package ghidra.features.bsim.gui.search.results;

import ghidra.docking.settings.BooleanSettingsDefinition;
import ghidra.docking.settings.Settings;

/**
 * Settings definition for showing function namespaces in the BSim Results table
 */
public class ShowNamespaceSettingsDefinition implements BooleanSettingsDefinition {

	public static final ShowNamespaceSettingsDefinition DEF =
		new ShowNamespaceSettingsDefinition();

	private static final boolean DEFAULT = true;
	private static final String DESCRIPTION =
		"Toggles showing namespace when displaying function name";

	private static final String SHOW_NAMESPACE = "Show Namespace";

	@Override
	public boolean getValue(Settings settings) {
		if (settings == null) {
			return DEFAULT;
		}
		String value = settings.getString(SHOW_NAMESPACE);
		if (value == null) {
			return DEFAULT;
		}
		return Boolean.parseBoolean(value);
	}

	@Override
	public String getValueString(Settings settings) {
		return Boolean.toString(getValue(settings));
	}

	@Override
	public void setValue(Settings settings, boolean value) {
		settings.setString(SHOW_NAMESPACE, Boolean.toString(value));
	}

	@Override
	public void copySetting(Settings srcSettings, Settings destSettings) {
		String value = srcSettings.getString(SHOW_NAMESPACE);
		if (value == null) {
			destSettings.clearSetting(SHOW_NAMESPACE);
		}
		else {
			destSettings.setString(SHOW_NAMESPACE, value);
		}
	}

	@Override
	public void clear(Settings settings) {
		settings.clearSetting(SHOW_NAMESPACE);
	}

	@Override
	public String getDescription() {
		return DESCRIPTION;
	}

	@Override
	public String getName() {
		return SHOW_NAMESPACE;
	}

	@Override
	public String getStorageKey() {
		return SHOW_NAMESPACE;
	}

	@Override
	public boolean hasValue(Settings settings) {
		return settings.getValue(SHOW_NAMESPACE) != null;
	}
}
