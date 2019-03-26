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
 * Interface for a SettingsDefinition with enumerated values.
 */
public interface EnumSettingsDefinition extends SettingsDefinition {

	/**
	 * Returns the current value for this settings
	 * @param settings The settings to search
	 * @return the value for the settingsDefintions
	 */
	public int getChoice(Settings settings);

	/**
	 * Sets the given value into the settings object using this definition as a key
	 * @param settings the settings to store the value.
	 * @param value the settings value to be stored.
	 */
	public void setChoice(Settings settings, int value);

	/**
	 * Returns the String for the given enum value
	 * @param value the value to get a display string for
	 * @param settings the instance settings which may affect the results
	 * @return the display string for the given settings.
	 */
	public String getDisplayChoice(int value, Settings settings);

	/**
	 * Gets the list of choices as strings based on the current settings
	 * @param settings the instance settings
	 * @return an array of strings which represent valid choices based on the current
	 * settings.
	 */
	public String[] getDisplayChoices(Settings settings);

}
