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
package ghidra.app.util.pdb.classtype;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;

/**
 * Manages virtual base table lookup for PDB classes.
 */
public class VxtManager {

	protected ClassTypeManager ctm;

	protected Map<Address, VirtualBaseTable> vbtByAddress;
	protected Map<Address, VirtualFunctionTable> vftByAddress;

	/**
	 * Virtual Base Table Lookup Manager
	 * @param ctm class type manager
	 */
	public VxtManager(ClassTypeManager ctm) {
		this.ctm = ctm;
		vbtByAddress = new HashMap<>();
		vftByAddress = new HashMap<>();
	}

	/**
	 * Returns the default VBT pointer type for the program
	 * @return the pointer type
	 */
	public PointerDataType getDefaultVbtPtr() {
		return ctm.getDefaultVbtPtr();
	}

	/**
	 * Returns the default VFT pointer type for the program
	 * @return the pointer type
	 */
	public PointerDataType getDefaultVftPtr() {
		return ctm.getDefaultVftPtr();
	}

	/**
	 * Returns the VBT located at the address
	 * @param address the address
	 * @return the VBT or null if a table is not found
	 */
	public VirtualBaseTable getVbt(Address address) {
		return vbtByAddress.get(address);
	}

	/**
	 * Returns the VFT located at the address
	 * @param address the address
	 * @return the VFT or null if a table is not found
	 */
	public VirtualFunctionTable getVft(Address address) {
		return vftByAddress.get(address);
	}

}
