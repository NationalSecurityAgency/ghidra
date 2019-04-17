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
	 * Gets the byte[] value associated with the given name
	 * @param name the key used to retrieve a value
	 * @return the byte[] value for a key
	 */
	byte[] getByteArray(String name);
	
	/**
	 * Gets the object associated with the given name
	 * @param name the key used to retrieve a value
	 * @return the object associated with a given key
	 */
	Object getValue(String name);
	
	/**
	 * Associates the given long value with the name
	 * @param name the key
	 * @param value the value associated with the key
	 */
	void setLong(String name, long value);
	/**
	 * Associates the given String value with the name
	 * @param name the key
	 * @param value the value associated with the key
	 */
	void setString(String name, String value);
	/**
	 * Associates the given byte[] with the name
	 * @param name the key
	 * @param value the value associated with the key
	 */
	void setByteArray(String name, byte[] value);
	
	/**
	 * Associates the given object with the name
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
	 * Returns true if there are no key-value pairs stored in this settings object
	 */
	boolean isEmpty();
	
//	/**
//	 * Sets the settings object to use if this settings object does not have the requested settings name.
//	 * @param settings the settings object to use if this settings object does not have the requested settings name.
//	 */
//	void setDefaultSettings(Settings settings);
	
	/**
	 * Returns the underlying default settings for these settings or null if there are none
	 */
	Settings getDefaultSettings();

}
