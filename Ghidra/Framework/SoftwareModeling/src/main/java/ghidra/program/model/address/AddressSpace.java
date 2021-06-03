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

import ghidra.program.model.lang.BasicCompilerSpec;
import ghidra.program.model.listing.Program;

/**
 * The AddressSpace class is used to represent a unique context for addresses.  Programs can
 * have multiple address spaces and address 0 in one space is not the same as address 0 in
 * another space.
 */
public interface AddressSpace extends Comparable<AddressSpace> {

	public static final int TYPE_CONSTANT = 0; // signed offset space
	public static final int TYPE_RAM = 1;
	public static final int TYPE_CODE = 2; // Deprecated - required for backward compatibility/upgrade
	public static final int TYPE_UNIQUE = 3;
	public static final int TYPE_REGISTER = 4;
	public static final int TYPE_STACK = 5; // signed offset space for stack
	public static final int TYPE_JOIN = 6; // used for variable join space (see decompiler)
	public static final int TYPE_OTHER = 7; // used for storing debug info and displaced code in memory 

	public static final int TYPE_SYMBOL = 9; // symbol space used for analysis only
	public static final int TYPE_EXTERNAL = 10;
	public static final int TYPE_VARIABLE = 11;

	public static final int TYPE_DELETED = 13;
	public static final int TYPE_UNKNOWN = 14;
	public static final int TYPE_NONE = 15;

	/**
	 * @see #TYPE_CONSTANT
	 */
	public static final int TYPE_IPTR_CONSTANT = TYPE_CONSTANT;
	/**
	 * @see #TYPE_UNIQUE
	 */
	public static final int TYPE_IPTR_INTERNAL = TYPE_UNIQUE;
	/**
	 * @see #TYPE_STACK
	 */
	public static final int TYPE_IPTR_SPACEBASE = TYPE_STACK;

	// Space ID Encoding
	// NOTE: The spaceID format may be sensitive to change due to backward data compatibility
	//       and possible decoding of the spaceID within the Decompiler
	public static final int ID_SIZE_MASK = 0x0070;
	public static final int ID_SIZE_SHIFT = 4;
	public static final int ID_TYPE_MASK = 0x000f;
	public static final int ID_UNIQUE_SHIFT = 7;

	/**
	 * The <code>OTHER_SPACE</code> is used to store data from the original program file that doesn't
	 * get loaded into the final memory image and for user-defined spaces.
	 */
	public static final AddressSpace OTHER_SPACE = new GenericAddressSpace(
		BasicCompilerSpec.OTHER_SPACE_NAME, 64, TYPE_OTHER, BasicCompilerSpec.OTHER_SPACE_INDEX);

	/**
	 * The <code>EXTERNAL_SPACE</code> is used to contain all external locations (i.e., data and functions) 
	 * defined within a given library namespace.  All external locations within a program
	 * are given a unique offset within the EXTERNAL space.
	 */
	public static final AddressSpace EXTERNAL_SPACE =
		new GenericAddressSpace("EXTERNAL", 32, TYPE_EXTERNAL, 0);

	/**
	 * The <code>VARIABLE_SPACE</code> is used to contain all variables and parameters 
	 * defined within a given namespace (i.e., function).  All variables within a program
	 * are given a unique offset within the VARIABLE space.
	 */
	public static final AddressSpace VARIABLE_SPACE =
		new GenericAddressSpace("VARIABLE", 32, TYPE_VARIABLE, 0);

	/**
	 * The <code>HASH_SPACE</code> provides a 60-bit space for encoding of unique hashcodes. 
	 */
	public static final AddressSpace HASH_SPACE =
		new GenericAddressSpace("HASH", 60, TYPE_UNKNOWN, 0);

	/**
	 * A language may only define a single REGISTER space.  If one is not defined, this 
	 * DEFAULT_REGISTER_SPACE definition will be used.
	 */
	public static final AddressSpace DEFAULT_REGISTER_SPACE =
		new GenericAddressSpace("REGISTER", 32, TYPE_REGISTER, 0);

	/**
	 * Returns the name of this address space.
	 */
	String getName();

	/**
	 * Get the ID for this space
	 * 
	 * @return space ID
	 */
	int getSpaceID();

	/** Returns the number of bits that are used to form the address.  Thus
	 * the maximum offset for this address space will be 2^size-1.
	 */
	int getSize();

	/**
	 * Returns the number of data bytes which correspond to each addressable 
	 * location within this space (i.e., word-size in bytes).
	 * NOTE: When transforming a byte-offset to an addressable word
	 * offset the method {@link #getAddressableWordOffset(long)} should
	 * be used instead of simple division.  When transforming an addressable word-offset
	 * to a byte-offset simple multiplication may be used.  Neither of these
	 * transformations perform address space bounds checking.
	 * <pre>
	 *   byteOffset = wordOffset * addressUnitSize
	 *   wordOffset = getAddressableWordOffset(byteOffset)
	 * </pre>
	 */
	int getAddressableUnitSize();

	/**
	 * Get the addressable memory word offset which corresponds to the specified 
	 * memory byte offset.  This method handles some of the issues of unsigned 
	 * math when stuck using Java's signed long primitives. No space bounds
	 * checking is performed.
	 * @param byteOffset memory byte offset
	 * @return addressable memory word offset
	 */
	public long getAddressableWordOffset(long byteOffset);

	/**
	 * Returns the absolute size of a pointer into this space (in bytes).
	 * @see Program#getDefaultPointerSize() for a user adjustable pointer size which is derived from the
	 * CompilerSpec store pointer size.
	 */
	int getPointerSize();

	/** Returns the type of this address space
	 */
	int getType();

	/** Returns the unique index for this address space
	 */
	int getUnique();

	/**
	 * Parses the String into an address.
	 * @param addrString the string to parse as an address.
	 * @return an address if the string parsed successfully or null if the
	 * AddressSpace specified in the addrString is not this space.
	 * @throws AddressFormatException if the string cannot be parsed or the
	 * parsed offset is larger than the size for this space.
	 */
	Address getAddress(String addrString) throws AddressFormatException;

	/**
	 * Parses the String into an address.
	 * @param addrString the string to parse as an address.
	 * @param caseSensitive specifies if addressSpace names must match case.
	 * @return an address if the string parsed successfully or null if the
	 * AddressSpace specified in the addrString is not this space.
	 * @throws AddressFormatException if the string cannot be parsed or the
	 * parsed offset is larger than the size for this space.
	 */
	Address getAddress(String addrString, boolean caseSensitive) throws AddressFormatException;

	/**
	 * Returns a new address in this space with the given byte offset.
	 * NOTE: This method is the same as invoking getAddress(long byteOffset, false).
	 * @param byteOffset the byte offset for the new address.
	 * @return address with given byte offset
	 * @throws AddressOutOfBoundsException if the offset is less than 0 or greater
	 * than the max offset allowed for this space.
	 */
	Address getAddress(long byteOffset) throws AddressOutOfBoundsException;

	/**
	 * Returns a new address in this space with the given offset.  
	 * NOTE: for those spaces with an addressable unit size other than 1, the address
	 * returned may not correspond to an addressable unit/word boundary if a byte-offset 
	 * is specified.
	 * @param offset the offset for the new address.
	 * @param isAddressableWordOffset if true the specified offset is an addressable unit/word offset,
	 * otherwise offset is a byte offset.  See {@link #getAddressableUnitSize()}
	 * to understand the distinction (i.e., wordOffset = byteOffset * addressableUnitSize).
	 * @return address with given offset
	 * @throws AddressOutOfBoundsException if the offset is less than 0 or greater
	 * than the max offset allowed for this space.
	 */
	Address getAddress(long offset, boolean isAddressableWordOffset)
			throws AddressOutOfBoundsException;

	/**
	 * Returns a new address in this space with the given offset.  The specified 
	 * offset will be truncated within the space and will not throw an exception.
	 * NOTE: for those spaces with an addressable unit size other than 1, the address
	 * returned may not correspond to a word boundary (addressable unit) if a byte-offset 
	 * is specified.
	 * @param offset the offset for the new address.
	 * @param isAddressableWordOffset if true the specified offset is an addressable unit/word offset,
	 * otherwise offset is a byte offset.  See {@link #getAddressableUnitSize()}
	 * to understand the distinction (i.e., wordOffset = byteOffset * addressableUnitSize).
	 * @return address with given byte offset truncated to the physical space size
	 */
	Address getTruncatedAddress(long offset, boolean isAddressableWordOffset);

	/**
	 * Get a byte address from this address space.  Don't allow overlay spaces
	 * to remap the address into a base space when the address is not
	 * contained in the bounds of the overlay region.
	 * 
	 * @param byteOffset the byte offset for the new address.
	 * @return an address if the offset is valid.
	 * 
	 * @throws AddressOutOfBoundsException if the offset is less than 0 or greater
	 * than the max offset allowed for this space.
	 */
	Address getAddressInThisSpaceOnly(long byteOffset) throws AddressOutOfBoundsException;

	/**
	 * Truncate the specified byte offset within this space to produce a valid offset.
	 * @param byteOffset any byte offset
	 * @return truncated byte offset
	 */
	long truncateOffset(long byteOffset);

	/**
	 * Truncate the specified addressable unit/word offset within this space to produce a 
	 * valid offset.
	 * @param wordOffset any addressable unit/word offset
	 * @return truncated word offset
	 */
	long truncateAddressableWordOffset(long wordOffset);

	/**
	 * Get an address that is relative to this address space.
	 * If this is an overlay space and the address falls within
	 * this space, return an address based in this space.
	 * 
	 * @param addr address possibly falling within this overlay space.
	 * 
	 * @return an address relative to this overlay
	 */
	Address getOverlayAddress(Address addr);

	/**
	 * Calculates the displacement between addr1 and addr2 (addr1 - addr2)
	 *
	 * @param addr1 the address to subtract from.
	 * @param addr2 the address to subtract.
	 * @return the difference. (<code>addr1.offset - addr2.offset</code>).
	 *
	 * @throws IllegalArgumentException if the two addresses are not in the
	 * same address space.
	 */
	public long subtract(Address addr1, Address addr2);

	/**
	 * Creates a new address by subtracting displacement from addr's offset.
	 * @param addr the original address. The new address will wrap in a manner
	 * that depends on the address space. For a generic address space this will
	 * wrap at the extents of the address space. For a segmented address space
	 * it will wrap at the extents of the segment.
	 * @param displacement  the displacement to subtract.
	 * @return a new address created by subtracting the displacement from addr.offset.
	 */
	public Address subtractWrap(Address addr, long displacement);

	/**
	 * Creates a new address by subtracting the displacement from the given 
	 * address. If the offset is greater than the max offset of the address space, the high
	 * order bits are masked off, making the address wrap.  For non-segmented addresses this
	 * will be the same as subtractWrap().  For segmented addresses, the address will wrap when
	 * the 20 bit (oxfffff) offset is exceeded, as opposed to when the segment offset is exceeded.
	 * @param addr the address to subtract the displacement from.
	 * @param displacement  the displacement to subtract.
	 * @return The new Address formed by subtracting the displacement from the specified address.
	 */
	Address subtractWrapSpace(Address addr, long displacement);

	/**
	 * Creates a new address by subtracting displacement from addr's offset.
	 * The new offset will NOT wrap!  
	 * @param addr the original address
	 * @param displacement  the displacement to subtract.
	 * @return The new address created by subtracting displacement from addr.offset.
	 * @throws AddressOverflowException if the subtraction would cause a wrap,
	 */
	public Address subtractNoWrap(Address addr, long displacement) throws AddressOverflowException;

	/**
	 * Creates a new address (possibly in a new space) by subtracting the given 
	 * displacement from the given address.
	 * @param addr original address being subtracted from
	 * @param displacement amount to subtract
	 * @return the new address
	 * @throws AddressOutOfBoundsException if the result does not correspond to any address.
	 */
	public Address subtract(Address addr, long displacement);

	/**
	 * Creates a new address by adding displacement to the given address. The
	 * resulting address may wrap. The new address will wrap in a manner that
	 * depends on the address space. For a generic address space this will wrap
	 * at the extents of the address space. For a segmented address space it
	 * will wrap at the extents of the segment.
	 * @param addr the original address.
	 * @param displacement  the displacement to add.
	 * @return the new address created by adding displacement to addr.offset.
	 */
	public Address addWrap(Address addr, long displacement);

	/**
	 * Creates a new address by adding the displacement to the given 
	 * address. If the offset is greater than the max offset of the address space, the high
	 * order bits are masked off, making the address wrap.  For non-segmented addresses this
	 * will be the same as addWrap().  For segmented addresses, the address will wrap when
	 * the 20 bit (oxfffff) offset is exceeded, as opposed to when the segment offset is exceeded.
	 * @param addr the address to add the displacement to.
	 * @param displacement  the displacement to add.
	 * @return The new Address formed by adding the displacement to the specified addresst.
	 */
	Address addWrapSpace(Address addr, long displacement);

	/**
	 * Creates a new address by adding displacement to the given address. The
	 * new address will NOT wrap!  
	 * @param addr the original address.
	 * @param displacement  the displacement to add.
	 * @return The new address created by adding displacement to addr.offset.
	 * @throws AddressOverflowException if the addition would cause a wrap,
	 */
	public Address addNoWrap(Address addr, long displacement) throws AddressOverflowException;

	/**
	 * Creates a new address by adding displacement to the given address. The
	 * new address will NOT wrap!  
	 * @param addr the original address.
	 * @param displacement  the displacement to add.
	 * @return The new address created by adding displacement to addr.offset.
	 * @throws AddressOverflowException if the addition would cause a wrap,
	 */
	public Address addNoWrap(GenericAddress addr, BigInteger displacement)
			throws AddressOverflowException;

	/**
	 * Creates a new address (possibly in a new space) by adding the given 
	 * displacement from the given address.
	 * @param addr original address being subtracted from
	 * @param displacement amount to subtract
	 * @return the new address
	 * @throws AddressOutOfBoundsException if the result does not correspond to any address.
	 */
	public Address add(Address addr, long displacement) throws AddressOutOfBoundsException;

	/**
	 * Check the specified address range for validity within this space.
	 * Segmented spaces will restrict a range to a single segment.
	 * @param byteOffset
	 * @param length
	 * @return true if range is valid for this space
	 */
	public boolean isValidRange(long byteOffset, long length);

	/**
	 * Tests whether addr2 immediately follows addr1.
	 * @param addr1 the first address.
	 * @param addr2 the second address.
	 */
	public boolean isSuccessor(Address addr1, Address addr2);

	/**
	 * Get the max address allowed for this AddressSpace.
	 */
	public Address getMaxAddress();

	/** 
	 * Get the min address allowed for this AddressSpace
	 */
	public Address getMinAddress();

	/**
	 * Returns the physical space associated with an address space.  There
	 * is always exactly one physical space associated with an address
	 * space (it may be its own physical space).
	 * @return the associated physical space.
	 */
	public AddressSpace getPhysicalSpace();

	/**
	 * Tests if the offset if valid. If the space is signed, then it sign extends
	 * the offset. 
	 * @param offset the offset to test and/or sign extend
	 * @return the valid positive offset or appropriate sign extended offset.
	 * @throws AddressOutOfBoundsException if offset is invalid
	 */
	public long makeValidOffset(long offset) throws AddressOutOfBoundsException;

	/**
	 * Returns true if this space represents a memory address.  NOTE: It is important to 
	 * make the distinction between Loaded and Non-Loaded memory addresses.  Program importers
	 * may create memory blocks associated with Non-Loaded file content which are not associated
	 * with processor defined memory regions.  While Loaded file content is placed into
	 * memory blocks which are associated with specific memory address spaces defined
	 * by the processor language specification.
	 * @see #isLoadedMemorySpace()
	 * @see #isNonLoadedMemorySpace() 
	 */
	public boolean isMemorySpace();

	/**
	 * Returns true if this space represents represents a Loaded Memory
	 * region (e.g., processor RAM).
	 */
	public boolean isLoadedMemorySpace();

	/**
	 * Returns true if this space represents represents a Non-Loaded storage region
	 * for retaining non-loaded file data (e.g., OTHER)
	 */
	public boolean isNonLoadedMemorySpace();

	/**
	 * Returns true if this space represents a register location
	 */
	public boolean isRegisterSpace();

	/**
	 * Returns true if this space represents a variable location
	 */
	public boolean isVariableSpace();

	/**
	 * Returns true if this space represents a stack location
	 */
	public boolean isStackSpace();

	/**
	 * Returns true if this space represents a location in the HASH space. 
	 */
	public boolean isHashSpace();

	/**
	 * Returns true if this space in the EXTERNAL_SPACE
	 */
	public boolean isExternalSpace();

	/**
	 * Returns true if this space in the unique space
	 */
	public boolean isUniqueSpace();

	/**
	 * Returns true if this space in the constant space
	 */
	public boolean isConstantSpace();

	/**
	 * Returns true if this space has registers that are mapped into it.
	 * This means that registers could actually have pointers to them.
	 * 
	 * @return true if this space has any registers mapped in it.
	 */
	boolean hasMappedRegisters();

	/**
	 * Returns true if the address should display its addressSpace name.
	 */
	boolean showSpaceName();

	/**
	 * Returns true if this addressSpace is an OverlayAddressSpace
	 */
	boolean isOverlaySpace();

	/**
	 * Returns true if space uses signed offset
	 */
	boolean hasSignedOffset();

}
