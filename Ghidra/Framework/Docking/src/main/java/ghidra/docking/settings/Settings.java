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
 * Settings objects store name-value pairs.  Each SettingsDefinition defines one
 * or more names to use to store values in settings objects.  Exactly what type
 * of value and how to interpret the value is done by the SettingsDefinition object.
 */
public interface Settings {

	static final String[] EMPTY_STRING_ARRAY = new String[0];

	/**
	 * {@return true if settings may not be modified}
	 */
	boolean isImmutableSettings();

	/**
	 * Determine if a settings change corresponding to the specified 
	 * settingsDefinition is permitted.
	 * @param settingsDefinition settings definition
	 * @return true if change permitted else false
	 */
	boolean isChangeAllowed(SettingsDefinition settingsDefinition);

	/**
	 * Get an array of suggested values for the specified string settings definition.
	 * @param settingsDefinition string settings definition
	 * @return suggested values array (may be empty)
	 */
	default String[] getSuggestedValues(StringSettingsDefinition settingsDefinition) {
		return EMPTY_STRING_ARRAY;
	}

	/**
	 * Gets the Long value associated with the given name
	 * @param name the key used to retrieve a value
	 * @return the Long value for a key
	 */
	Long getLong(String name);

	/**
	 * Gets the String value associated with the given name
	 * @param name the key used to retrieve a value
	 * @return the String value for a key
	 */
	String getString(String name);

	/**
	 * Gets the object associated with the given name
	 * @param name the key used to retrieve a value
	 * @return the object associated with a given key
	 */
	Object getValue(String name);

	/**
	 * Associates the given long value with the name.
	 * Note that an attempted setting change may be ignored if prohibited
	 * (e.g., immutable Settings, undefined setting name).
	 * @param name the key
	 * @param value the value associated with the key
	 */
	void setLong(String name, long value);

	/**
	 * Associates the given String value with the name.
	 * Note that an attempted setting change may be ignored if prohibited
	 * (e.g., immutable Settings, undefined setting name).
	 * @param name the key
	 * @param value the value associated with the key
	 */
	void setString(String name, String value);

	/**
	 * Associates the given object with the name.
	 * Note that an attempted setting change may be ignored if prohibited
	 * (e.g., immutable Settings, undefined setting name).
	 * @param name the key
	 * @param value the value to associate with the key
	 */
	void setValue(String name, Object value);

	/**
	 * Removes any value associated with the given name
	 * @param name the key to remove any association
	 */
	void clearSetting(String name);

	/**
	 * Removes all name-value pairs from this settings object
	 */
	void clearAllSettings();

	/**
	 * Get this list of keys that currently have values associated with them
	 * @return an array of string keys.
	 */
	String[] getNames();

	/**
	 * Returns true if there are no key-value pairs stored in this settings object.
	 * This is not a reflection of the underlying default settings which may still
	 * contain a key-value pair when this settings object is empty.
	 * @return true if there are no key-value pairs stored in this settings object
	 */
	boolean isEmpty();

	/**
	 * Returns the underlying default settings for these settings or null if there are none
	 * @return underlying default settings or null
	 */
	Settings getDefaultSettings();

}
