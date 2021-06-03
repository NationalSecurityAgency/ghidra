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
package ghidra.program.model.address;

import java.math.BigInteger;

import ghidra.program.model.data.DataOrganization;

/**
 * An address represents a location in a program.  Conceptually, addresses consist
 * of an "address space" and an offset within that space.  Many processors have only
 * one "real" address space, but some have several spaces. Also, there are
 * "artificial" address spaces used for analysis and representing other non-memory locations
 * such as a register or an offset on the stack relative to a functions frame pointer.
 * 
 */

public interface Address extends Comparable<Address> {
	/**
	 * Address object representing an invalid address.
	 */
	public static final Address NO_ADDRESS = new SpecialAddress("NO ADDRESS");
	/**
	 * Address object representing an extenal entry address.
	 */
	public static final Address EXT_FROM_ADDRESS = new SpecialAddress("Entry Point");
	/**
	 * Character used to separate space names from offsets.
	 */
	public final char SEPARATOR_CHAR = ':';

	/**
	 * Creates a new Address by parsing a String representation of an address. The
	 * string may be either a simple number (just the offset part of an address) or take
	 * the form "addressSpaceName:offset".  If the latter form is used, the 
	 * "addressSpaceName" must match the name of the space for this address.
	 *
	 * @param addrString the String to parse.
	 * @return the new Address if the string is a legally formed address or null
	 * if the string contains an address space name that does not match this address's space.
	 * @throws AddressFormatException if the string cannot be parsed or the
	 * parsed offset is larger than the size for this address' space.
	 */
	public Address getAddress(String addrString) throws AddressFormatException;

	/**
	 * Creates a new Address in this address's space with the given byte offset.
	 *
	 * @param byteOffset the byte offset for the new address.
	 * @return the new Address.
	 * @throws AddressOutOfBoundsException if the offset is less than the minimum offset or 
	 * greater than the max offset allowed for this space.
	 */
	public Address getNewAddress(long byteOffset);

	/**
	 * Returns a new address in this address's space with the given offset.  
	 * NOTE: for those spaces with an addressable unit size other than 1, the address
	 * returned may not correspond to an addressable unit/word boundary if a byte-offset 
	 * is specified.
	 * @param offset the offset for the new address.
	 * @param isAddressableWordOffset if true the specified offset is an addressable unit/word offset,
	 * otherwise offset is a byte offset.  See {@link ghidra.program.model.address.AddressSpace#getAddressableUnitSize()
	 * AddressSpace#getAddressableUnitSize()} to understand the distinction
	 * (i.e., wordOffset = byteOffset * addressableUnitSize).
	 * @return address with given offset
	 * @throws AddressOutOfBoundsException if the offset is less than 0 or greater
	 * than the max offset allowed for this space.
	 */
	Address getNewAddress(long offset, boolean isAddressableWordOffset)
			throws AddressOutOfBoundsException;

	/**
	 * Returns a new address in this address's space with the given offset.  The specified 
	 * offset will be truncated within the space and will not throw an exception.
	 * NOTE: for those spaces with an addressable unit size other than 1, the address
	 * returned may not correspond to a word boundary (addressable unit) if a byte-offset 
	 * is specified.
	 * @param offset the offset for the new address.
	 * @param isAddressableWordOffset if true the specified offset is an addressable unit/word offset,
	 * otherwise offset is a byte offset.  See {@link ghidra.program.model.address.AddressSpace#getAddressableUnitSize()
	 * AddressSpace#getAddressableUnitSize()} to understand the distinction
	 * (i.e., wordOffset = byteOffset * addressableUnitSize).
	 * @return address with given byte offset truncated to the physical space size
	 */
	Address getNewTruncatedAddress(long offset, boolean isAddressableWordOffset);

	/**
	 * Returns the number of bytes needed to form a pointer to this address.  The
	 * result will be one of {1,2,4,8}.
	 * @see DataOrganization#getPointerSize() for compiler-specific size of pointers stored in memory.
	 */
	public int getPointerSize();

	/**
	 * Returns the address's successor.  In most cases, this is equivalent
	 * to addr.add(1), but segmented addresses could span segments.  The result
	 * of calling this on the highest address will result in a null return value.
	 * @return the next higher address, or null if already at the
	 * highest address.
	 */
	public Address next();

	/**
	 * Returns the address's predecessor.  In most cases, this is equivalent to
	 * addr.subtract(1), but segmented addresses could span segments.  The
	 * result of calling this on the lowest address will result in a null return value.
	 * @return the next lower address, or null if already at the
	 *  lowest address.
	 */
	public Address previous();

	/**
	 * Get the offset of this Address.
	 *
	 * @return the offset of this Address.
	 */
	public long getOffset();

	/**
	 * Get the offset of this Address as a BigInteger
	 *
	 * @return the offset of this Address.
	 */
	public BigInteger getOffsetAsBigInteger();

	/**
	 * Get the address offset as an unsigned number.
	 * This may be useful when dealing with signed spaces (e.g. stack)
	 * @return unsigned address offset
	 */
	public long getUnsignedOffset();

	/**
	 * Get the addressable memory word offset which corresponds to this address.
	 * @return addressable memory word offset
	 */
	public long getAddressableWordOffset();

	/**
	 * Returns the address space associated with this address.
	 */
	public AddressSpace getAddressSpace();

	/**
	 * Return true if this address' address space is equal to the
	 * address space for addr.
	 */
	public boolean hasSameAddressSpace(Address addr);

	/** Returns the number of bits that are used to form the address.  Thus
	 * the maximum offset for this address space will be 2^size-1.
	 */
	public int getSize();

	/**
	 * Calculates the displacement between two addresses (<code>this - addr</code>)
	 *
	 * @param addr  the Address to subtract from <code>this</code> address
	 * @return the difference (thisAddress.offset - thatAddress.offset)
	 * @throws IllegalArgumentException if the two addresses are not in the same address space
	 */
	public long subtract(Address addr);

	/**
	 * Creates a new address by subtracting the displacement from the current 
	 * address. The new address will wrap in a manner that depends on the 
	 * address space. For a generic address space this will wrap at the 
	 * extents of the address space. For a segmented address space it will 
	 * wrap at the extents of the segment.
	 *
	 * @param displacement  the displacement to subtract.
	 * @return The new Address formed by subtracting the displacement for the offset.
	 */
	public Address subtractWrap(long displacement);

	/**
	 * Creates a new address by subtracting the displacement from the current 
	 * address. If the offset is greater than the max offset of the address space, the high
	 * order bits are masked off, making the address wrap.  For non-segmented addresses this
	 * will be the same as subtractWrap().  For segmented addresses, the address will wrap when
	 * the 20 bit (oxfffff) offset is exceeded, as opposed to when the segment offset is exceeded.
	 * @param displacement  the displacement to add.
	 * @return The new Address formed by subtracting the displacement from this address's offset.
	 */
	public Address subtractWrapSpace(long displacement);

	/**
	 * Creates a new Address by subtracting displacement from the
	 * Address.  The Address will not wrap within the space and in fact will throw
	 * an exception if the result is less than the min address in this space or
	 * greater than the max address in this space.
	 *
	 * @param displacement  the displacement to subtract.
	 * @return The new Address
	 * @throws AddressOverflowException if the offset in this Address would
	 *  overflow due to this operation.
	 */
	public Address subtractNoWrap(long displacement) throws AddressOverflowException;

	/**
	 * Creates a new address (possibly in a new space) by subtracting the displacement to 
	 * this address.
	 * @param displacement the amount to subtract from this offset.
	 * @return The address using the subtracted offset.
	 */
	public Address subtract(long displacement);

	/**
	 * Creates a new address by adding the displacement to the current 
	 * address. The new address will wrap in a manner that depends on the 
	 * address space. For a generic address space this will wrap at the 
	 * extents of the address space. For a segmented address space it will 
	 * wrap at the extents of the segment.
	 *
	 * @param displacement  the displacement to add.
	 * @return The new Address formed by adding the displacement to this address's offset.
	 */
	public Address addWrap(long displacement);

	/**
	 * Creates a new address by adding the displacement to the current 
	 * address. If the offset is greater than the max offset of the address space, the high
	 * order bits are masked off, making the address wrap.  For non-segmented addresses this
	 * will be the same as addWrap().  For segmented addresses, the address will wrap when
	 * the 20 bit (oxfffff) offset is exceeded, as opposed to when the segment offset is exceeded.
	 * @param displacement  the displacement to add.
	 * @return The new Address formed by adding the displacement to this address's offset.
	 */
	public Address addWrapSpace(long displacement);

	/**
	 *  Creates a new Address with a displacement relative to this
	 *  Address.  The Address will not wrap around!  An exception will be
	 * throw if the result is not within this address space.
	 *
	 * @param displacement  the displacement to add.
	 * @return The new Address
	 * @throws AddressOverflowException if the offset in this Address would
	 *  overflow (wrap around) due to this operation.
	 */
	public Address addNoWrap(long displacement) throws AddressOverflowException;

	public Address addNoWrap(BigInteger displacement) throws AddressOverflowException;

	/**
	 * Creates a new address (possibly in a new space) by adding the displacement to 
	 * this address.
	 * @param displacement the amount to add to this offset.
	 * @return The new address.
	 * @throws AddressOutOfBoundsException if wrapping is not supported by the 
	 * corresponding address space and the addition causes an out-of-bounds
	 * error
	 */
	public Address add(long displacement) throws AddressOutOfBoundsException;

	/**
	 * Tests whether the given address immediately follows this address.
	 *
	 * @param addr   the address to test.
	 */
	public boolean isSuccessor(Address addr);

	/**
	 * Returns a String representation of the address in hex and padded
	 * to the appropriate size.
	 */
	@Override
	public String toString();

	/** 
	 * Returns a String representation of the address using the
	 * given string as a prefix.  Equivalent of prefix + ":" + toString(false)
	 * @param prefix the string to prepend to the address string.  
	 */
	public String toString(String prefix);

	/**
	 * Returns a String representation that may include the address space name
	 * @param showAddressSpace true if the address space should be included in 
	 * resulting string.
	 * @return String the string representation of the address
	 */
	public String toString(boolean showAddressSpace);

	/**
	 * Returns a String representation that may include the address space name and may or may
	 * not pad the address with leading zeros.
	 * @param showAddressSpace if true, the addressSpace name will be prepended to the address string.
	 * @param pad if true, the address will be prepended with leading zeros to completely fill out
	 * the max digits the address could contain.  If false, the address will be prepended only to make
	 * the number of hex digits at least 4.
	 * @return the address as a String.
	 */
	public String toString(boolean showAddressSpace, boolean pad);

	/**
	 * Returns a String representation that may include the address space name and may or may
	 * not pad the address with leading zeros.
	 * @param showAddressSpace if true, the addressSpace name will be prepended to the address string.
	 * @param minNumDigits specifies the minimum number of digits to use.  If the address space size
	 * is less that minNumDigits, the address will be padded to the address space size.  If the address
	 * space size is larger that minNumDigits, the address will be displayed with as many digits as
	 * necessary, but will contain leading zeros to make the address string have at least minNumDigits.
	 * @return the address as a String.
	 */
	public String toString(boolean showAddressSpace, int minNumDigits);

	/**
	 * Compares this Address to the specified object.
	 * The result is <code>true</code> if and only if the argument is not 
	 * <code>null</code> and is a <code>Address</code> object that represents 
	 * the same address as this object. 
	 *
	 * @param   o   the object to compare this <code>String</code>
	 *              against.
	 * @return  <code>true</code> if the <code>Addresses</code>are equal;
	 *          <code>false</code> otherwise.
	 */
	@Override
	public boolean equals(Object o);

	/**
	 * Returns a hashcode for this Address. The hashcode for an 
	 * <code>Address</code> should be a value such that two Address
	 * objects which are equal will return the same hashcode.
	 * This method should generally return the same value as getLong().
	 *
	 * @return  a hash code value for this object. 
	 */
	@Override
	public int hashCode();

	/**
	 * Returns the physical Address that corresponds to this Address.
	 * 
	 * @return address in a physical space corresponding to this
	 * address.
	 */
	public Address getPhysicalAddress();

	/**
	 * Returns true if this address represents a location in memory
	 */
	public boolean isMemoryAddress();

	/**
	 * Returns true if this address represents an address in a loaded memory block
	 */
	public boolean isLoadedMemoryAddress();

	/**
	 * Returns true if this address represents an address not loaded in real memory (i.e. OTHER)
	 */
	public boolean isNonLoadedMemoryAddress();

	/**
	 * Returns true if this address represents a location in stack space
	 */
	public boolean isStackAddress();

	/**
	 * Returns true if this address represents a location in unique space
	 */
	public boolean isUniqueAddress();

	/**
	 * Returns true if this address represents a location in constant space
	 */
	public boolean isConstantAddress();

	/**
	 * Returns true if this address represents a location in the HASH space
	 */
	public boolean isHashAddress();

	/**
	 * Returns true if this address represents a location in register space.
	 * @deprecated use of this method is highly discouraged since since registers
	 * may also exist in a memory space. The address for such registers 
	 * would return false from this method. 
	 */
	@Deprecated
	public boolean isRegisterAddress();

	/**
	 * Returns true if this address represents a location in variable space
	 */
	public boolean isVariableAddress();

	/**
	 * Returns true if this address represents an external location in the external address space
	 */
	public boolean isExternalAddress();

	/**
	 * Return the minimum of two addresses using Address.compareTo
	 * @param a first address
	 * @param b second address
	 * @return minimum of two addresses
	 */
	public static Address min(Address a, Address b) {
		return a.compareTo(b) <= 0 ? a : b;
	}

	/**
	 * Return the maximum of two addresses using Address.compareTo
	 * @param a first address
	 * @param b second address
	 * @return maximum of two addresses
	 */
	public static Address max(Address a, Address b) {
		return a.compareTo(b) > 0 ? a : b;
	}
}
