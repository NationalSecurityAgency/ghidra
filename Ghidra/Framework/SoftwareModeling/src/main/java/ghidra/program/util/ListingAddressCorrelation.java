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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

/**
 * This is the interface for a correlator that associates addresses from one program with
 * addresses from another program or it can associate addresses from one part of a program 
 * with addresses from another part of the same program. Given an address from the address set
 * in the first program it determines the matching address from the address set for the second 
 * program if possible.
 */
public interface ListingAddressCorrelation {

	/**
	 * Gets the program containing the first set of addresses.
	 * @return the program for the first set of addresses.
	 */
	public abstract Program getFirstProgram();

	/**
	 * Gets the program containing the second set of addresses.
	 * This program may be different from or the same as the first program.
	 * @return the program for the second set of addresses.
	 */
	public abstract Program getSecondProgram();

	/**
	 * Gets the first set of addresses for this correlator.
	 * @return the first set of addresses.
	 */
	public abstract AddressSetView getAddressesInFirst();

	/**
	 * Gets the second set of addresses for this correlator.
	 * @return the second set of addresses.
	 */
	public abstract AddressSetView getAddressesInSecond();

	/**
	 * Determine the address from the second set that matches the specified address in the first set.
	 * @param addressInFirst the address in the first address set.
	 * @return the matching address in the second set or null if a match couldn't be determined.
	 */
	public abstract Address getAddressInSecond(Address addressInFirst);

	/**
	 * Determine the address from the first set that matches the specified address in the second set.
	 * @param addressInSecond the address in the second address set.
	 * @return the matching address in the first set or null if a match couldn't be determined.
	 */
	public abstract Address getAddressInFirst(Address addressInSecond);

}
