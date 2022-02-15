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
package ghidra.docking.settings;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.function.Predicate;

/**
 * Generic interface for defining display options on data and dataTypes.  Uses
 * Settings objects to store values which are interpreted by SettingsDefinition objects.
 */
public interface SettingsDefinition {

	/**
	 * Create a new list of {@link SettingsDefinition}s by concat'ing a base list with
	 * a var-arg'ish additional list of setting defs.  Any additional duplicates are discarded.
	 * @param settings List of settings defs.
	 * @param additional More settings defs to add
	 * @return new array with all the settings defs joined together.
	 */
	public static SettingsDefinition[] concat(SettingsDefinition[] settings,
			SettingsDefinition... additional) {
		if (additional == null) {
			return settings;
		}
		if (settings == null) {
			return additional;
		}
		ArrayList<SettingsDefinition> list = new ArrayList<>();
		list.addAll(Arrays.asList(settings));
		for (SettingsDefinition def : additional) {
			if (!list.contains(def)) {
				list.add(def);
			}
		}
		return list.toArray(new SettingsDefinition[list.size()]);
	}

	/**
	 * Get datatype settings definitions for the specified datatype exclusive of any default-use-only definitions.
	 * @param definitions settings definitions to be filtered
	 * @param filter callback which determines if definition should be included in returned array
	 * @return filtered settings definitions
	 */
	public static SettingsDefinition[] filterSettingsDefinitions(SettingsDefinition[] definitions,
			Predicate<SettingsDefinition> filter) {
		ArrayList<SettingsDefinition> list = new ArrayList<>();
		for (SettingsDefinition def : definitions) {
			if (filter.test(def)) {
				list.add(def);
			}
		}
		SettingsDefinition[] defs = new SettingsDefinition[list.size()];
		return list.toArray(defs);
	}

	/**
	 * Determine if a setting value has been stored
	 * @param setting stored settings
	 * @return true if a value has been stored, else false
	 */
	public boolean hasValue(Settings setting);

	/**
	 * Get the setting value as a string which corresponds to this definition.
	 * A default value string will be returned if a setting has not been stored.
	 * @param settings settings
	 * @return value string or null if not set and default has not specified by this definition
	 */
	public String getValueString(Settings settings);

	/**
	 * Returns the display name of this SettingsDefinition
	 * @return display name for setting
	 */
	public String getName();

	/**
	 * Get the {@link Settings} key which is used when storing a key/value entry.
	 * @return settings storage key
	 */
	String getStorageKey();

	/**
	 * Returns a description of this settings definition
	 * @return setting description
	 */
	public String getDescription();

	/**
	 * Removes any values in the given settings object assocated with this settings definition
	 * @param settings the settings object to be cleared.
	 */
	public void clear(Settings settings);

	/**
	 * Copies any setting value associated with this settings definition from the
	 * srcSettings settings to the destSettings.
	 * @param srcSettings the settings to be copied
	 * @param destSettings the settings to be updated.
	 */
	public void copySetting(Settings srcSettings, Settings destSettings);

	/**
	 * Check two settings for equality which correspond to this 
	 * settings definition.
	 * @param settings1 first settings
	 * @param settings2 second settings
	 * @return true if the same else false
	 */
	public boolean hasSameValue(Settings settings1, Settings settings2);

}
