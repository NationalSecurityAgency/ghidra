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

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;

public interface AddressTranslator {

	/** Gets the destination program for addresses that have been translated.
	 * @return program1.
	 */
	public Program getDestinationProgram();

	/** Gets the source program for obtaining the addresses that need to be translated.
	 * @return program2.
	 */
	public Program getSourceProgram();

	/**
	 * Converts the given source address to the returned destination address.
	 * This interface is intended to translate an address from the source program to an 
	 * address in the destination program.
	 * @param sourceAddress the source address to be converted.
	 * @return the destination address that is equivalent in some way to the source address.
	 * How the address is equivalent depends upon the particular translator.
	 * throws AddressTranslationException if the address can't be translated to an equivalent
	 * address in the other program.
	 */
	public Address getAddress(Address sourceAddress) throws AddressTranslationException;

	/**
	 * This method should return true if it can translate an address set from the source program 
	 * to an address set for the destination program and there is a one to one correspondence 
	 * between the two programs addresses. 
	 * In other words two addresses that make up the start and end of an address range
	 * would be at the same distance and relative location from each other as the equivalent two 
	 * individual translated addresses are from each other.
	 * Otherwise this should return false.
	 */
	public boolean isOneForOneTranslator();

	/**
	 * Converts the given source address range to the returned destination address range.
	 * This interface is intended to translate an address range from the source program to an 
	 * address range in the destination program.
	 * <br>This method should be implemented if isOneForOneTranslator() returns true.
	 * @param sourceAddressRange the source address range to be converted.
	 * @return the destination address range that is equivalent in some way to the source address range.
	 * How the address range is equivalent depends upon the particular translator.
	 * throws AddressTranslationException if the address set can't be translated to an equivalent
	 * address range in the other program.
	 */
	public AddressRange getAddressRange(AddressRange sourceAddressRange)
			throws AddressTranslationException;

	/**
	 * Converts the given source address set to the returned destination address set.
	 * This interface is intended to translate an address set from the source program to an 
	 * address set in the destination program.
	 * <br>This method should be implemented if isOneForOneTranslator() returns true.
	 * @param sourceAddressSet the source address set to be converted.
	 * @return the destination address set that is equivalent in some way to the source address set.
	 * How the address set is equivalent depends upon the particular translator.
	 * throws AddressTranslationException if the address set can't be translated to an equivalent
	 * address set in the other program.
	 */
	public AddressSet getAddressSet(AddressSetView sourceAddressSet)
			throws AddressTranslationException;
}
