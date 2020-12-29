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

import org.apache.commons.lang3.StringUtils;

import ghidra.util.MathUtilities;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.AssertException;

abstract class AbstractAddressSpace implements AddressSpace {

	protected String name;
	protected int size; // number of address bits
	protected int unitSize = 1; // number of data bytes at each location
	protected int type;
	protected long spaceSize = 0; // number of address locations (2^size * unitSize) - is always even number (spaceSize=0 when all 64-bits of address offset are used)
	protected boolean signed;
	protected long minOffset;
	protected long maxOffset;
	protected Address minAddress;
	protected Address maxAddress;
	private int hashcode;
	protected int spaceID;
	private boolean showSpaceName; // show space name when displaying an address	
	private boolean hasMemoryMappedRegisters = false;

	private long wordAddressMask = -1;

	/**
	 * Constructs a new address space with the given name, bit size, type and unique value.
	 * @param name the name of the space.
	 * @param size the number of bits required to represent the largest address 
	 * the space.
	 * @param unitSize number of bytes contained at each addressable location (i.e., word-size in bytes)
	 * @param type the type of the space
	 * @param unique the unique id for this space.
	 */
	protected AbstractAddressSpace(String name, int size, int unitSize, int type, int unique) {

		showSpaceName = (type != TYPE_RAM) || isOverlaySpace();

		if (type == TYPE_NONE) {
			this.name = name;
			this.type = TYPE_NONE;
			minAddress = maxAddress = getUncheckedAddress(0);
			spaceID = -1;
			hashcode = name.hashCode() + type;
			return;
		}

		if (unique < 0 || unique > Short.MAX_VALUE) {
			throw new IllegalArgumentException(
				"Unique space id must be between 0 and " + Short.MAX_VALUE + " inclusive");
		}
		this.name = name;
		this.size = size;
		this.unitSize = unitSize;
		this.type = type;

		if ((bitsConsumedByUnitSize(unitSize) + size) > 64) {
			throw new IllegalArgumentException(
				"Unsupport address space size (2^size * wordsize > 2^64)");
		}
		if (size != 64) {
			spaceSize = ((long) unitSize) << size; // (spaceSize=0 for 64-bit space)
			wordAddressMask = (1L << size) - 1;
		}
		signed = (type == AddressSpace.TYPE_CONSTANT || type == AddressSpace.TYPE_STACK);

		if (signed) {
			maxOffset = (spaceSize - 1) >>> 1;
			minOffset = -maxOffset - 1;
		}
		else {
			maxOffset = spaceSize - 1;
			minOffset = 0;
		}
		maxAddress = getUncheckedAddress(maxOffset);
		minAddress = getUncheckedAddress(minOffset);

		// Incorporation of size component if for backward compatibility only
		int logsize = 7;
		switch (size) {
			case 8:
				logsize = 0;
				break;
			case 16:
				logsize = 1;
				break;
			case 32:
				logsize = 2;
				break;
			case 64:
				logsize = 3;
				break;
		}

		// space id includes space and size info.
		this.spaceID = (unique << ID_UNIQUE_SHIFT) | (logsize << ID_SIZE_SHIFT) | type;

		hashcode = name.hashCode() + type;
	}

	private int bitsConsumedByUnitSize(int unitSize) {
		if (unitSize < 1 || unitSize > 8) {
			throw new IllegalArgumentException("Unsupported unit size: " + unitSize);
		}
		int cnt = 0;
		for (int test = unitSize - 1; test != 0; test >>= 1) {
			++cnt;
		}
		return cnt;
	}

	@Override
	public boolean hasSignedOffset() {
		return signed;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public int getSize() {
		return size;
	}

	@Override
	public int getAddressableUnitSize() {
		return unitSize;
	}

	@Override
	public long getAddressableWordOffset(long byteOffset) {
		boolean isNegative = false;
		if (signed && byteOffset < 0) {
			byteOffset = -byteOffset;
			isNegative = true;
		}

		long offset = getUnsignedWordOffset(byteOffset, unitSize);
		if (isNegative) {
			offset = -offset;
		}
		return offset;
	}

	private static long getUnsignedWordOffset(long byteOffset, int wordSize) {
		switch (wordSize) {
			case 1:
				return byteOffset;
			case 2:
				return byteOffset >>> 1;
			case 4:
				return byteOffset >>> 2;
			case 8:
				return byteOffset >>> 3;
		}
		return MathUtilities.unsignedDivide(byteOffset, wordSize);
	}

	@Override
	public int getPointerSize() {
		int ptrSize = size / 8;
		if (size % 8 != 0) {
			++ptrSize;
		}
		return ptrSize;
	}

	@Override
	public int getType() {
		return type;
	}

	/**
	 * Returns the unique id value for this space.
	 */
	@Override
	public int getUnique() {
		return spaceID >> ID_UNIQUE_SHIFT;
	}

	@Override
	public Address getAddress(String addrString) throws AddressFormatException {
		return getAddress(addrString, true);
	}

	@Override
	public Address getAddress(String addrString, boolean caseSensitive)
			throws AddressFormatException {
		String offStr = addrString;

		int colonPos = addrString.lastIndexOf(':');

		if (colonPos >= 0) {
			String addrSpaceStr = addrString.substring(0, colonPos);
			if (!StringUtils.equals(name, addrSpaceStr)) {
				return null;
			}
			offStr = addrString.substring(colonPos + 1);
		}

		try {
			long off = parseString(offStr);
			return getAddress(off);
		}
		catch (NumberFormatException e) {
			throw new AddressFormatException(
				addrString + " contains invalid address hex offset");
		}
		catch (AddressOutOfBoundsException e) {
			throw new AddressFormatException(e.getMessage());
		}
	}

	private long parseString(String addr) throws NumberFormatException, AddressFormatException {
		if (addr.startsWith("0x") || addr.startsWith("0X")) {
			addr = addr.substring(2);
		}

		long mod = 0;
		if (unitSize > 1) {
			int ix = addr.indexOf('.');
			if (ix > 0) {
				String unitOffset = addr.substring(ix + 1);
				BigInteger bi = new BigInteger(unitOffset, 16);
				mod = bi.longValue();
				if (bi.bitLength() > 8 || mod >= unitSize) {
					throw new AddressFormatException("invalid address unit offset: ." + unitOffset);
				}
				addr = addr.substring(0, ix);
			}
		}

		BigInteger bi = new BigInteger(addr, 16);
		if (bi.bitLength() > 64) {
			throw new AddressFormatException("unsupported address offset: " + addr);
		}
		return (unitSize * bi.longValue()) + mod;
	}

	@Override
	public Address getAddress(long offset, boolean isAddressableWordOffset)
			throws AddressOutOfBoundsException {
		long byteOffset = isAddressableWordOffset ? (offset * unitSize) : offset;
		return getAddress(byteOffset);
	}

	@Override
	public Address getTruncatedAddress(long offset, boolean isAddressableWordOffset) {
		long truncatedOffset = isAddressableWordOffset ? truncateAddressableWordOffset(offset)
				: truncateOffset(offset);
		try {
			return getAddress(truncatedOffset, isAddressableWordOffset);
		}
		catch (AddressOutOfBoundsException e) {
			throw new AssertException(e); // should not happen when offset is truncated
		}
	}

	@Override
	public long subtract(Address addr1, Address addr2) {
		AddressSpace space1 = addr1.getAddressSpace();
		AddressSpace space2 = addr2.getAddressSpace();
		if (!space1.equals(space2)) {
			// if the two spaces are actually based in the same space, calculate the offset
			int base1 = space1.isOverlaySpace() ? ((OverlayAddressSpace) space1).getBaseSpaceID()
					: space1.getSpaceID();
			int base2 = space2.isOverlaySpace() ? ((OverlayAddressSpace) space2).getBaseSpaceID()
					: space2.getSpaceID();
			if (base1 != base2) {
				throw new IllegalArgumentException("Address are in different spaces " +
					addr1.getAddressSpace().getName() + " != " + addr2.getAddressSpace().getName());
			}
		}
		return addr1.getOffset() - addr2.getOffset();
	}

	@Override
	public Address subtractWrap(Address addr, long displacement) {
		testAddressSpace(addr);
		return getUncheckedAddress(truncateOffset(addr.getOffset() - displacement));
	}

	@Override
	public Address subtractWrapSpace(Address addr, long displacement) {
		return subtractWrap(addr, displacement);
	}

	@Override
	public Address subtractNoWrap(Address addr, long displacement) throws AddressOverflowException {
		if (displacement < 0) {
			if (displacement == Long.MIN_VALUE) {
				throw new AddressOverflowException("Address Overflow in subtract: " + addr +
					" - 0x" + Long.toHexString(displacement));
			}
			return addNoWrap(addr, -displacement);
		}

		testAddressSpace(addr);
		if (displacement > spaceSize && spaceSize != 0) {
			throw new AddressOverflowException(
				"Address Overflow in subtract: " + addr + " - 0x" + Long.toHexString(displacement));
		}
		long addrOff = addr.getOffset();
		long maxOff = maxAddress.getOffset();
		long minOff = minAddress.getOffset();
		long result = addrOff - displacement;
		if (maxOff < 0) { // 64 bit unsigned
			if (addrOff >= 0 && result < 0) {
				throw new AddressOverflowException("Address Overflow in subtract: " + addr +
					" - 0x" + Long.toHexString(displacement));
			}
			else if ((addrOff < 0 && result < 0) || (addrOff >= 0 && result >= 0)) {
				if (result > addrOff) {
					throw new AddressOverflowException("Address Overflow in subtract: " + addr +
						" - 0x" + Long.toHexString(displacement));
				}
			}
		}
		else {
			if (result > addrOff || result < minOff) {
				throw new AddressOverflowException("Address Overflow in subtract: " + addr +
					" - 0x" + Long.toHexString(displacement));
			}
		}
		return getUncheckedAddress(result);
	}

	@Override
	public Address subtract(Address addr, long displacement) {
		try {
			return subtractNoWrap(addr, displacement);
		}
		catch (AddressOverflowException e) {
			throw new AddressOutOfBoundsException(e.getMessage());
		}
	}

	@Override
	public Address addWrap(Address addr, long displacement) {
		testAddressSpace(addr);
		return getUncheckedAddress(truncateOffset(addr.getOffset() + displacement));
	}

	@Override
	public Address addWrapSpace(Address addr, long displacement) {
		return addWrap(addr, displacement);
	}

	@Override
	public Address addNoWrap(Address addr, long displacement) throws AddressOverflowException {

		if (displacement == 0) {
			return addr;
		}
		if (displacement < 0) {
			return subtractNoWrap(addr, -displacement);
		}

		testAddressSpace(addr);
		if (displacement > spaceSize && spaceSize != 0) {
			throw new AddressOverflowException(
				"Address Overflow in add: " + addr + " + 0x" + Long.toHexString(displacement));
		}
		long addrOff = addr.getOffset();
		long maxOff = maxAddress.getOffset();
		long result = addrOff + displacement;
		if (maxOff < 0) { // 64 bit unsigned
			if (addrOff < 0 && result >= 0) {
				throw new AddressOverflowException(
					"Address Overflow in add: " + addr + " + 0x" + Long.toHexString(displacement));
			}
			else if ((addrOff < 0 && result < 0) || (addrOff >= 0 && result >= 0)) {
				if (result < addrOff) {
					throw new AddressOverflowException("Address Overflow in add: " + addr +
						" + 0x" + Long.toHexString(displacement));
				}
			}
		}
		else {
			if (result < addrOff || result > maxOff) {
				throw new AddressOverflowException(
					"Address Overflow in add: " + addr + " + 0x" + Long.toHexString(displacement));
			}
		}

		return getUncheckedAddress(result);
	}

	@Override
	public Address addNoWrap(GenericAddress addr, BigInteger displacement)
			throws AddressOverflowException {

		if (displacement.equals(BigInteger.ZERO)) {
			return addr;
		}
		testAddressSpace(addr);
		BigInteger addrOff = addr.getOffsetAsBigInteger();
		BigInteger maxOff = maxAddress.getOffsetAsBigInteger();
		BigInteger minOff = minAddress.getOffsetAsBigInteger();
		BigInteger newOffset = addrOff.add(displacement);
		if (newOffset.compareTo(minOff) < 0 || newOffset.compareTo(maxOff) > 0) {
			throw new AddressOverflowException(
				"Address Overflow in add: " + addr + " + " + displacement);
		}

		long resultOffset = NumericUtilities.bigIntegerToUnsignedLong(newOffset);
		return getUncheckedAddress(resultOffset);
	}

	@Override
	public Address add(Address addr, long displacement) throws AddressOutOfBoundsException {
		try {
			return addNoWrap(addr, displacement);
		}
		catch (AddressOverflowException e) {
			throw new AddressOutOfBoundsException(e.getMessage());
		}
	}

	@Override
	public boolean isValidRange(long byteOffset, long length) {
		Address start;
		try {
			start = getAddress(byteOffset);
		}
		catch (Exception e1) {
			return false;
		}
		if (length == 0) {
			return false;
		}
		try {
			addNoWrap(start, length - 1);
		}
		catch (AddressOverflowException e) {
			return false;
		}
		return true;
	}

	@Override
	public boolean isSuccessor(Address addr1, Address addr2) {
		if (!addr1.getAddressSpace().equals(addr2.getAddressSpace())) {
			return false;
		}

		if (maxAddress.getOffset() == addr1.getOffset()) {
			return false;
		}
		return addr1.getOffset() == addr2.getOffset() - 1;
	}

	@Override
	public Address getMaxAddress() {
		return maxAddress;
	}

	@Override
	public Address getMinAddress() {
		return minAddress;
	}

	private int compareAsOverlaySpace(AddressSpace overlaySpace) {
		int baseCompare = ((OverlayAddressSpace) this).getBaseSpaceID() -
			((OverlayAddressSpace) overlaySpace).getBaseSpaceID();
		if (baseCompare == 0) {
			long otherMinOffset = overlaySpace.getMinAddress().getOffset();
			if (minOffset == otherMinOffset) {
				return name.compareTo(overlaySpace.getName());
			}
			return (minOffset < otherMinOffset) ? -1 : 1;
		}
		return baseCompare;
	}

	@Override
	public int compareTo(AddressSpace space) {
		if (space == this) {
			return 0;
		}
		if (isOverlaySpace()) {
			if (space.isOverlaySpace()) {
				// Both spaces are overlay spaces
				return compareAsOverlaySpace(space);
			}
			// I'm an overlay, other space is NOT an overlay
			return 1;
		}
		else if (space.isOverlaySpace()) {
			// I'm NOT an overlay, other space is an overlay
			return -1;
		}
		if (hashcode == space.hashCode() &&
			// hashcode factors name and type
			type == space.getType() && name.equals(space.getName()) &&
			getClass().equals(space.getClass())) {
// TODO: This could be bad - should really only be 0 if same instance - although this could have other implications
// Does not seem to be good way of factoring ID-based ordering with equality
			// This is not intended to handle complete mixing of address spaces
			// from multiple sources (i.e., language provider / address factory).
			// It is intended to handle searching for a single address from one
			// source within a list/set of addresses from a second source.
			return 0;
		}
		int c = getSpaceID() - space.getSpaceID();
		if (c == 0) {
			c = getClass().getName().compareTo(space.getClass().getName());
		}
		return c;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		if (hashcode != obj.hashCode()) {
			return false;
		}

		AddressSpace s = (AddressSpace) obj;

//        return spaceID == s.getUniqueSpaceID() && 
//			   type == s.getType() &&
////        	   name.equals(s.getName) &&  // does the name really matter?
//        	   size == s.getSize();		

		return type == s.getType() && name.equals(s.getName()) && size == s.getSize();
	}

	@Override
	public int hashCode() {
		return hashcode;
	}

	@Override
	public int getSpaceID() {
		return spaceID;
	}

	protected void testAddressSpace(Address addr) {
		if (!this.equals(addr.getAddressSpace())) {
			throw new IllegalArgumentException("Address space for " + addr + " (" +
				addr.getAddressSpace().getName() + ") does not match " + name);
		}
	}

	@Override
	public String toString() {
		return name + ":";
	}

	@Override
	public boolean showSpaceName() {
		return showSpaceName;
	}

	/**
	 * Instantiates an address within this space.
	 * No offset validation should be performed.
	 * @param offset
	 */
	protected abstract Address getUncheckedAddress(long offset);

	/**
	 * No overlay translation necessary, this is a base addressSpace.
	 * 
	 *  (non-Javadoc)
	 * @see ghidra.program.model.address.AddressSpace#getOverlayAddress(ghidra.program.model.address.Address)
	 */
	@Override
	public Address getOverlayAddress(Address addr) {
		return addr;
	}

	@Override
	public long makeValidOffset(long offset) throws AddressOutOfBoundsException {
		if (size == 64 || spaceSize == 0) {
			return offset;
		}
		if ((offset >= minOffset && offset <= maxOffset)) {
			return offset;
		}
		if (signed) {
			if (offset > maxOffset && offset < spaceSize) {
				// sign extend negative offset
				return offset - spaceSize;
			}
		}
		else {
			if (offset < 0 && offset >= -maxOffset - 1) {
				// recover from accidental sign extension
				return offset + spaceSize;
			}
		}
		String max = Long.toHexString(maxOffset);
		String min = Long.toHexString(minOffset);
		throw new AddressOutOfBoundsException("Offset must be between 0x" + min + " and 0x" + max +
			", got 0x" + Long.toHexString(offset) + " instead!");
	}

	@Override
	public long truncateOffset(long offset) {
		if ((offset >= minOffset && offset <= maxOffset) || spaceSize == 0) {
			return offset;
		}
		if (signed) {
			offset = (offset + maxOffset + 1) % spaceSize;
			if (offset < 0) {
				offset += spaceSize;
			}
			return offset - maxOffset - 1;
		}
		// TODO: this could be a problem for large signed offset values within an unsigned space
		offset = offset % spaceSize;
		if (offset < 0) {
			offset += spaceSize;
		}
		return offset;
	}

	@Override
	public long truncateAddressableWordOffset(long wordOffset) {
		return wordOffset & wordAddressMask;
	}

	@Override
	public boolean isMemorySpace() {
		return type == TYPE_RAM || type == TYPE_CODE || type == TYPE_OTHER;
	}

	@Override
	public boolean isLoadedMemorySpace() {
		return type == TYPE_RAM || type == TYPE_CODE;
	}

	@Override
	public boolean isNonLoadedMemorySpace() {
		return type == TYPE_OTHER;
	}

	@Override
	public boolean isHashSpace() {
		return this == HASH_SPACE;
	}

	@Override
	public boolean isRegisterSpace() {
		return type == TYPE_REGISTER;
	}

	@Override
	public boolean isStackSpace() {
		return type == TYPE_STACK;
	}

	@Override
	public boolean isUniqueSpace() {
		return type == TYPE_UNIQUE;
	}

	@Override
	public boolean isConstantSpace() {
		return type == TYPE_CONSTANT;
	}

	@Override
	public boolean isVariableSpace() {
		return type == TYPE_VARIABLE;
	}

	@Override
	public boolean isExternalSpace() {
		return type == TYPE_EXTERNAL;
	}

	@Override
	public boolean isOverlaySpace() {
		return false;
	}

	public void setShowSpaceName(boolean b) {
		showSpaceName = b;
	}

	@Override
	public boolean hasMappedRegisters() {
		return hasMemoryMappedRegisters;
	}

	/**
	 * Tag this memory space as having memory mapped registers
	 * 
	 * @param hasRegisters true if it has registers, false otherwise
	 */
	public void setHasMappedRegisters(boolean hasRegisters) {
		hasMemoryMappedRegisters = hasRegisters;
	}

	@Override
	public AddressSpace getPhysicalSpace() {
		return this;
	}

}
