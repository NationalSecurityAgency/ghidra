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
package ghidra.feature.vt.gui.provider.markuptable;

import ghidra.feature.vt.gui.editors.DisplayableAddress;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.table.field.AddressBasedLocation;

public class DisplayableListingAddress implements DisplayableAddress {

	protected final Program program;
	protected Address address;

	public DisplayableListingAddress(Program program, Address listingAddress) {
		this.program = program;
		this.address = listingAddress;
	}

	public Program getProgram() {
		return program;
	}

	@Override
	public Address getAddress() {
		return address;
	}

	@Override
	public String getDisplayString() {
		if (address == null || address == Address.NO_ADDRESS) {
			return NO_ADDRESS;
		}
		AddressBasedLocation location = new AddressBasedLocation(program, address);
		return location.toString();
	}

	@Override
	public String toString() {
		return getDisplayString();
	}

	@Override
	public int compareTo(DisplayableAddress otherDisplayableAddress) {
		if (otherDisplayableAddress == null) {
			return 1;
		}
		Address otherAddress = otherDisplayableAddress.getAddress();
		if (address == null) {
			return (otherAddress == null) ? 0 : -1;
		}
		if (otherAddress == null) {
			return 1;
		}
		return address.compareTo(otherAddress);
	}

}
