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

import java.util.Objects;
import java.util.Set;

public interface StringSettingsDefinition extends SettingsDefinition {

	/**
	 * Gets the value for this SettingsDefinition given a Settings object.
	 * @param settings the set of Settings values for a particular location or null for default value.
	 * @return the value for this settings object given the context.
	 */
	public abstract String getValue(Settings settings);

	/**
	 * Sets the given value into the given settings object using this settingsDefinition as the key.
	 * @param settings the settings object to store the value in.
	 * @param value the value to store in the settings object using this settingsDefinition as the key.
	 */
	public abstract void setValue(Settings settings, String value);

	@Override
	public default String getValueString(Settings settings) {
		String str = getValue(settings);
		return str != null ? str : "";
	}

	@Override
	public default boolean hasSameValue(Settings settings1, Settings settings2) {
		return Objects.equals(getValue(settings1), getValue(settings2));
	}

	/**
	 * Get suggested setting values
	 * @param settings settings object
	 * @return suggested settings or null if none or unsupported;
	 */
	public default String[] getSuggestedValues(Settings settings) {
		return null;
	}

	/**
	 * Determine if this settings definition supports suggested values.
	 * See {@link #getSuggestedValues(Settings)}.
	 * @return true if suggested values are supported, else false.
	 */
	public default boolean supportsSuggestedValues() {
		return false;
	}

	/**
	 * Add preferred setting values to the specified set as obtained from the specified
	 * settingsOwner.
	 * @param settingsOwner settings owner from which a definition may query preferred values.
	 * Supported values are specific to this settings definition.  An unsupported settingsOwner
	 * will return false.
	 * @param set value set to which values should be added
	 * @return true if settingsOwner is supported and set updated, else false.
	 */
	public default boolean addPreferredValues(Object settingsOwner, Set<String> set) {
		// TODO: improve specification of settingsOwner
		return false;
	}
}
