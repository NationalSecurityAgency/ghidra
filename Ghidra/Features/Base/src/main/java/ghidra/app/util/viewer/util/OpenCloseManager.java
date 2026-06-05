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
package ghidra.app.util.viewer.util;

import ghidra.program.model.address.Address;

/**
 * Interface for tracking the open/close state at an address.
 */
public interface OpenCloseManager {

	/**
	 * Checks if the state is "open" for the given address.
	 * @param address the address to test
	 * @return true if the state of the given address is "open"
	 */
	public boolean isOpen(Address address);

	/**
	 * Sets the state at the given address to be "open".
	 * @param address the address to set "open"
	 */
	public void open(Address address);

	/**
	 * Sets the state at the given address to be "closed".
	 * @param address the address to set "closed"
	 */
	public void close(Address address);

	/**
	 * Checks if the default state is "open".
	 * @return true if the default state for addresses is "open"
	 */
	public boolean isOpenByDefault();

	/**
	 * Sets all address to "open" (Makes "open" the default state and clears all individual
	 * settings.
	 */
	public void openAll();

	/**
	 * Sets all address to "closed" (Makes "closed" the default state and clears all individual
	 * settings.
	 */
	public void closeAll();

}
