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
package ghidra.program.util;

import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * The <CODE>AddressFieldLocation</CODE> class provides specific information
 * about a program location within the ADDRESS field.
 */

public class AddressFieldLocation extends CodeUnitLocation {

	private String addrRepresentation;

	/**
	 * Construct a new AddressFieldLocation object with the 
	 * standard string representation
	 * and a position within that string.
	 *
	 * @param program the program of the location
	 * @param addr address of the location
	 * @param componentPath if not null, it is the array of indexes that point
	 * to a specific data type inside of another data type
	 * @param addrRepresentation the string representation of the address
	 * @param charOffset the position into the string representation indicating the exact
	 * position within the Address Field.
	 */
	public AddressFieldLocation(Program program, Address addr, int[] componentPath,
			String addrRepresentation, int charOffset) {

		super(program, addr, componentPath, 0, 0, charOffset);

		this.addrRepresentation = addrRepresentation;
	}

	/**
	 * Construct a new default AddressFieldLocation for a given program address.
	 * 
	 * @param program the program of the location
	 * @param addr address of the location
	 */
	public AddressFieldLocation(Program program, Address addr) {
		super(program, addr, 0, 0, 0);
		this.addrRepresentation = addr.toString();
	}

	/**
	 * Default constructor needed for restoring
	 * an address field location from XML.
	 */
	public AddressFieldLocation() {
	}

	/**
	 * Returns the standard string representation of the address in the
	 * address field.  If there is no address, then null should be returned.
	 */
	public String getAddressRepresentation() {
		return addrRepresentation;
	}

	/**
	 * Returns a String representation of this location.
	 */
	@Override
	public String toString() {
		return super.toString() + ", AddressRep = " + addrRepresentation;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result =
			prime * result + ((addrRepresentation == null) ? 0 : addrRepresentation.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		AddressFieldLocation other = (AddressFieldLocation) obj;
		if (addrRepresentation == null) {
			if (other.addrRepresentation != null)
				return false;
		}
		else if (!addrRepresentation.equals(other.addrRepresentation))
			return false;
		return true;
	}

	@Override
	public void saveState(SaveState obj) {
		super.saveState(obj);
		obj.putString("_ADDR_REP", addrRepresentation);
	}

	@Override
	public void restoreState(Program restoreProgram, SaveState obj) {
		super.restoreState(restoreProgram, obj);
		addrRepresentation = obj.getString("_ADDR_REP", null);
	}
}
