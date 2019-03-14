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

/**
 * Generic interface for defining display options on data and dataTypes.  Uses
 * Settings objects to store values which are interpreted by SettingsDefinition objects.
 */
public interface SettingsDefinition {

	/**
	 * Create a new list of {@link SettingsDefinition}s by concat'ing a base list with
	 * a var-arg'ish additional list of setting defs.
	 *
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

		SettingsDefinition[] result = new SettingsDefinition[settings.length + additional.length];
		System.arraycopy(settings, 0, result, 0, settings.length);
		System.arraycopy(additional, 0, result, settings.length, additional.length);
		return result;
	}

	public boolean hasValue(Settings setting);

	/**
	 * Returns the name of this SettingsDefinition
	 */
	public String getName();

	/**
	 * Returns a description of this settings definition
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

}
