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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Duo.Side;

/**
 * This is the interface for a correlator that associates addresses from one program with
 * addresses from another program or it can associate addresses from one part of a program 
 * with addresses from another part of the same program. Given an address from one program, it
 * can provide the corresponding address for the other program. The two programs are referred to
 * as the LEFT program and the RIGHT program. See {@link ghidra.util.datastruct.Duo.Side}
 */
public interface ListingAddressCorrelation {

	/**
	 * Gets the program for the given side.
	 * @param side LEFT or RIGHT
	 * @return the program for the given side
	 */
	public abstract Program getProgram(Side side);

	/**
	 * Gets the function for the given side. This will be null if the addresses are not function
	 * based.
	 * @param side LEFT or RIGHT
	 * @return the function for the given side or null if not function based
	 */
	public abstract Function getFunction(Side side);

	/**
	 * Gets the addresses that are part of the correlator for the given side
	 * @param side LEFT or RIGHT
	 * @return the addresses that are part of the correlator for the given side
	 */
	public abstract AddressSetView getAddresses(Side side);

	/**
	 * Gets the address for the given side that matches the given address from the other side.
	 * @param side the side to get an address for
	 * @param otherSideAddress the address from the other side to find a match for
	 * @return  the address for the given side that matches the given address from the other side.
	 */
	public abstract Address getAddress(Side side, Address otherSideAddress);

}
