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

import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Extends DataTypeManager to include methods specific to a data type manager for
 * a program.
 */
public interface ProgramBasedDataTypeManager extends DomainFileBasedDataTypeManager {
	
	/**
	 * Get the program instance associated with this datatype manager
	 * @return program instance associated with this datatype manager
	 */
	Program getProgram();

	/**
	 * Determine if a settings change is permitted for the specified settingsDefinition.
	 * @param data                data code unit
	 * @param settingsDefinition  settings definition
	 * @return true if change permitted else false
	 */
	public boolean isChangeAllowed(Data data, SettingsDefinition settingsDefinition);

	/**
	 * Set the long value for data instance settings.
	 * 
	 * @param data     data code unit
	 * @param name     settings name
	 * @param value    value of setting
	 * @return true if the settings actually changed
	 */
	public boolean setLongSettingsValue(Data data, String name, long value);

	/**
	 * Set the string value for data instance settings.
	 * 
	 * @param data     data code unit
	 * @param name     settings name
	 * @param value    value of setting
	 * @return true if the settings actually changed
	 */
	public boolean setStringSettingsValue(Data data, String name, String value);

	/**
	 * Set the Object value for data instance settings.
	 * 
	 * @param data     data code unit
	 * @param name     the name of the settings
	 * @param value    the value for the settings, must be either a String, byte[]
	 *                 or Long
	 * @return true if the settings were updated
	 */
	public boolean setSettings(Data data, String name, Object value);

	/**
	 * Get the long value for data instance settings.
	 * 
	 * @param data     data code unit
	 * @param name     settings name
	 * @return null if the named setting was not found
	 */
	public Long getLongSettingsValue(Data data, String name);

	/**
	 * Get the String value for data instance settings.
	 * 
	 * @param data     data code unit
	 * @param name     settings name
	 * @return null if the named setting was not found
	 */
	public String getStringSettingsValue(Data data, String name);

	/**
	 * Gets the value for data instance settings in Object form.
	 * 
	 * @param data     data code unit
	 * @param name     the name of settings.
	 * @return the settings object
	 */
	public Object getSettings(Data data, String name);

	/**
	 * Clear the specified setting for the given data
	 * 
	 * @param data data code unit 
	 * @param name settings name
	 * @return true if the settings were cleared
	 */
	public boolean clearSetting(Data data, String name);

	/**
	 * Clear all settings for the given data.
	 * 
	 * @param data data code unit
	 */
	public void clearAllSettings(Data data);

	/**
	 * Returns all the instance Settings names used for the specified data
	 * 
	 * @param data data code unit
	 * @return the names
	 */
	public String[] getInstanceSettingsNames(Data data);

	/**
	 * Returns true if no settings are set for the given data
	 * 
	 * @param data data code unit
	 * @return true if not settings
	 */
	public boolean isEmptySetting(Data data);

	/**
	 * Move the settings in the range to the new start address
	 * 
	 * @param fromAddr start address from where to move
	 * @param toAddr   new Address to move to
	 * @param length   number of addresses to move
	 * @param monitor  progress monitor
	 * @throws CancelledException if the operation was cancelled
	 */
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException;

	/**
	 * Removes all settings in the range
	 * 
	 * @param startAddr the first address in the range.
	 * @param endAddr   the last address in the range.
	 * @param monitor   the progress monitor
	 * @throws CancelledException if the user cancelled the operation.
	 */
	public void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException;
}
