/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util;

import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;

/**
 * Data that is the transferable in SelectionTransferable; it contains an address set and the
 * path of the program.
 * 
 * 
 *
 */
public class SelectionTransferData { 

	private String programPath;
	private AddressSetView addressSet;

	/**
	 * Constructor
	 * @param set address set to transfer
	 * @param programPath path to the program that contains the set
	 */
	public SelectionTransferData(AddressSetView set, String programPath) {
		addressSet = new AddressSet( set);
		this.programPath = programPath;
	}
	/**
	 * Return the program path.
	 */
	public String getProgramPath() {
		return programPath;
	}

	/**
	 * Return the address set.
	 */
	public AddressSetView getAddressSet() {
		return addressSet;
	}
}
