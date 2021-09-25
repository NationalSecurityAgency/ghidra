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
 *  The inteface for SettingsDefinitions that have boolean values.  SettingsDefinitions
 * objects are used as keys into Settings objects that contain the values using a name-value
 * type storage mechanism.
 */
public interface BooleanSettingsDefinition extends SettingsDefinition {

	/**
	 * gets the value for this SettingsDefinition given a Settings object.
	 * @param settings the set of Settings values for a particular location or null for default value.
	 * @return the values for this settings object given the context.
	 */
	public abstract boolean getValue(Settings settings);

	/**
	 * Sets the given value into the given settings object using this settingsDefinition as the key.
	 * @param settings the settings object to store the value in.
	 * @param value the value to store in the settings object using this settingsDefinition as the key.
	 */
	public abstract void setValue(Settings settings, boolean value);

}
