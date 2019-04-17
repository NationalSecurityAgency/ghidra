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
package ghidra.program.model.listing;

import ghidra.framework.model.ChangeSet;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;

/**
 * Interface for an Address Change set.  Objects that implements this interface track
 * various change information on a set of addresses where the program has changed.
 */
public interface AddressChangeSet extends ChangeSet {

	/**
	 * Returns the address set of all addresses where the listing has changed.
	 */
	AddressSetView getAddressSet();
	
	/**
	 * Adds the address set to the set addresses where changes occurred.
	 * @param addrSet the set of addresses to add as changes.
	 */
	void add(AddressSetView addrSet);

	/**
	 * Adds the range of addresses to the set addresses where changes occurred.
	 * @param addr1 the first address in the range
	 * @param addr2 the last address in the range. (inclusive)
	 */
	void addRange(Address addr1, Address addr2);

}
