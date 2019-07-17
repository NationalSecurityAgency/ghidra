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
package ghidra.program.model.address;

public interface AddressFactory {

	/**
	 * Create an address from String. Attempts to use the "default" address space
	 * first.  Otherwise loops through each addressSpace, returning the first valid
	 * address that any addressSpace creates from the string.
	 * Returns an Address if the string is valid, otherwise null.
	 */
	public Address getAddress(String addrString);

	/**
	 * Generates all reasonable addresses that can be interpreted from
	 * the given string.  Each Address Space is given a change to parse
	 * the string and all the valid results are return in the array.
	 * @param addrString the address string to parse.
	 * @return Address[] The list of addresses generated from the string.
	 */
	public Address[] getAllAddresses(String addrString);

	/**
	 * Generates all reasonable addresses that can be interpreted from
	 * the given string.  Each Address Space is given a change to parse
	 * the string and all the valid results are return in the array.
	 * @param addrString the address string to parse.
	 * @param caseSensitive determines if addressSpace names must be case sensitive to match. 
	 * @return Address[] The list of addresses generated from the string.
	 */
	public Address[] getAllAddresses(String addrString, boolean caseSensitive);

	/**
	 * Returns the default AddressSpace
	 */
	public AddressSpace getDefaultAddressSpace();

	/**
	 * Get the array of all "physical" AddressSpaces.
	 */
	public AddressSpace[] getAddressSpaces();

	/**
	 * Returns an array of all address spaces, including analysis spaces.
	 * @return an array of all the address spaces.
	 */
	public AddressSpace[] getAllAddressSpaces();

	/**
	 * Returns the space with the given name or null if no space
	 * exists with that name.
	 */
	public AddressSpace getAddressSpace(String name);

	/**
	 * Returns the space with the given spaceID or null if none exists
	 */
	public AddressSpace getAddressSpace(int spaceID);

	/**
	 * Returns the number of physical AddressSpaces.
	 */
	public int getNumAddressSpaces();

	/**
	 * Tests if the given address is valid for at least one of the 
	 * Address Spaces in this factory
	 * @param addr The address to test
	 * @return boolean true if the address valid, false otherwise
	 */
	public boolean isValidAddress(Address addr);

	/**
	 * @see java.lang.Object#equals(Object)
	 */
	@Override
	public boolean equals(Object o);

	/**
	 * Returns the index (old encoding) for the given address.
	 * @param addr the address to encode.
	 */
	public long getIndex(Address addr);

	/**
	 * Gets the physical address space associated with the given address space. If 
	 * the given space is physical, then it will be returned.
	 * @param space the addressSpace for which the physical space is requested.
	 * @return the physical address space associated with the given address space.
	 */
	public AddressSpace getPhysicalSpace(AddressSpace space);

	/**
	 * Returns an array of all the physical address spaces.
	 * @return an array of all the physical address spaces.
	 */
	public AddressSpace[] getPhysicalSpaces();

	/**
	 * Get an address using the addressSpace with the given id and having the given offset.
	 * @param spaceID the id of the address space to use to create the new address.
	 * @param offset the offset of the new address to be created.
	 * @return the new address.
	 */
	public Address getAddress(int spaceID, long offset);

	/**
	 * Returns the "constant" address space.
	 */
	public AddressSpace getConstantSpace();

	/**
	 * Returns the "unique" address space.
	 */
	public AddressSpace getUniqueSpace();

	/**
	 * Returns the "stack" address space.
	 */
	public AddressSpace getStackSpace();

	/**
	 * Returns the "register" address space.
	 */
	public AddressSpace getRegisterSpace();

	/**
	 * Returns an address in "constant" space with the given offset.
	 * @param offset the offset in "constant" space for the new address.
	 * @return a new address in the "constant" space with the given offset.
	 */
	public Address getConstantAddress(long offset);

	/**
	 * Computes an address set from a start and end address that may span address spaces.  Although 
	 * in general, it is not meaningful to compare addresses from multiple spaces, but since there 
	 * is an absolute ordering of address spaces it can be useful for iterating over all addresses
	 * in a program with multiple address spaces.
	 * @param min the start address
	 * @param max the end address.
	 * @return an addressSet containing ranges that don't span address spaces.
	 */
	public AddressSet getAddressSet(Address min, Address max);

	/**
	 * Returns an addressSet containing all possible "real" addresses for this address factory.
	 */
	public AddressSet getAddressSet();

	/**
	 * Returns the address using the old encoding format.
	 * @param value to decode into an address.
	 */
	public Address oldGetAddressFromLong(long value);

	/**
	 * Returns true if there is more than one memory address space
	 */
	public boolean hasMultipleMemorySpaces();

}
