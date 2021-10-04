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

import ghidra.program.model.address.Address;
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
	 * Set the long value for instance settings.
	 * 
	 * @param dataAddr min address of data
	 * @param name     settings name
	 * @param value    value of setting
	 * @return true if the settings actually changed
	 */
	public boolean setLongSettingsValue(Address dataAddr, String name, long value);

	/**
	 * Set the string value for instance settings.
	 * 
	 * @param dataAddr min address of data
	 * @param name     settings name
	 * @param value    value of setting
	 * @return true if the settings actually changed
	 */
	public boolean setStringSettingsValue(Address dataAddr, String name, String value);

	/**
	 * Set the Object settings.
	 * 
	 * @param dataAddr min address of data
	 * @param name     the name of the settings
	 * @param value    the value for the settings, must be either a String, byte[]
	 *                 or Long
	 * @return true if the settings were updated
	 */
	public boolean setSettings(Address dataAddr, String name, Object value);

	/**
	 * Get the long value for an instance setting.
	 * 
	 * @param dataAddr min address of data
	 * @param name     settings name
	 * @return null if the named setting was not found
	 */
	public Long getLongSettingsValue(Address dataAddr, String name);

	/**
	 * Get the String value for an instance setting.
	 * 
	 * @param dataAddr min address of data
	 * @param name     settings name
	 * @return null if the named setting was not found
	 */
	public String getStringSettingsValue(Address dataAddr, String name);

	/**
	 * Gets the value of a settings as an object (either String, byte[], or Long).
	 * 
	 * @param dataAddr the address of the data for this settings
	 * @param name     the name of settings.
	 * @return the settings object
	 */
	public Object getSettings(Address dataAddr, String name);

	/**
	 * Clear the setting
	 * 
	 * @param dataAddr min address of data
	 * @param name settings name
	 * @return true if the settings were cleared
	 */
	public boolean clearSetting(Address dataAddr, String name);

	/**
	 * Clear all settings at the given address.
	 * 
	 * @param dataAddr the address for this settings.
	 */
	public void clearAllSettings(Address dataAddr);

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
	 * Returns all the instance Settings names used at the given address
	 * 
	 * @param dataAddr the address
	 * @return the names
	 */
	public String[] getInstanceSettingsNames(Address dataAddr);

	/**
	 * Returns true if no settings are set for the given address
	 * 
	 * @param dataAddr the address to test
	 * @return true if not settings
	 */
	public boolean isEmptySetting(Address dataAddr);

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
