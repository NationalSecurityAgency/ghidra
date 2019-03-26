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


/**
 * Address class for dealing with intel 20 bit segmented addresses.
 */
public class SegmentedAddress extends GenericAddress {

	private static final long serialVersionUID = 0;
	public static final int OFFSET_SIZE = 16;
	public static final int SEGMENT_SIZE = 16;

	private final SegmentedAddressSpace addrSpace;
	private final int segment;

	/**
	 * Constructor for SegmentedAddress.
	 * Offset is not validated against address space.
	 * @param addrSpace address space for this address
	 * @param offset offset into the space
	 */
	SegmentedAddress(long offset, SegmentedAddressSpace addrSpace) {
		super(adjustOffset(offset), addrSpace);
		this.addrSpace = addrSpace;
		if (offset > 0xFFFFF) {
			this.segment = 0xFFFF;
		} else {
			this.segment = (int) ((offset >> 4) & 0xf000);
		}
	}

	/**
	 * Constructor for SegmentedAddress.
	 * @param addrSpace address space for this address
	 * @param segmentOffset offset into the segment
	 * @param overlayId overlay number
	 * @param segment segment number
	 */
	SegmentedAddress(SegmentedAddressSpace addrSpace, int segment, int segmentOffset)
			throws AddressOutOfBoundsException {
		super(addrSpace, (segment << 4) + segmentOffset);
		this.addrSpace = addrSpace;
		if (offset > 0xFFFFF) {
			this.segment = 0xFFFF;
		} else {
			this.segment = segment;
		}
	}

	/**
	 * Constructor for SegmentedAddress.
	 * @param addrSpace address space for this address
	 * @param offset offset into the space
	 */
	SegmentedAddress(SegmentedAddressSpace addrSpace, long offset)
			throws AddressOutOfBoundsException {
		super(addrSpace, adjustOffset(offset));
		this.addrSpace = addrSpace;
		if (offset > 0xFFFFF) {
			this.segment = 0xFFFF;
		} else {
			this.segment = (int) ((offset >> 4) & 0xf000);
		}
	}

	private static long adjustOffset(long offset) {
		// Decompiler treats segmented space as a 32-bit space and may produce an address offset
		// of 0xffffffff for a first use offset (= 0 minus 1).
		if (offset == 0x0ffffffffL) {
			offset = 0x0fffffL;
		}
		return offset;
	}

	/**
	 * Returns the segment value
	 * @return int the segment value
	 */
	public int getSegment() {
		return segment;
	}

	/**
	 * Returns the offset within the segment.
	 */
	public int getSegmentOffset() {
		return (int) (offset - (segment << 4));
	}

	/**
	 * Returns a new address that is equivalent to this address using
	 * the given segment number.
	 * @param seg the seqment value to normalize to.
	 */
	public SegmentedAddress normalize(int seg) {
		if ((seg << 4) > offset) {
			return this;
		}
		int off = (int) (offset - (seg << 4));
		if (off > 0xffff) {
			return this;
		}
		return new SegmentedAddress(addrSpace, seg, off);
	}

	/**
	 * Return a new segmented address. An attempt is made to normalize to this addresses segment.
	 * @see ghidra.program.model.address.Address#getNewAddress(long)
	 */
	@Override
	public Address getNewAddress(long byteOffset) {
		SegmentedAddress segAddr = addrSpace.getAddress(byteOffset);
		return segAddr.normalize(segment);
	}

	@Override
	public Address getNewAddress(long addrOffset, boolean isAddressableWordOffset)
			throws AddressOutOfBoundsException {
		return getNewAddress(addrOffset);
	}

	@Override
	public Address getNewTruncatedAddress(long addrOffset, boolean isAddressableWordOffset)
			throws AddressOutOfBoundsException {
		return getNewAddress(addrSpace.truncateOffset(addrOffset));
	}

	/**
	 * Returns the String for the given value
	 * @param value the value to convert to a string.
	 * @return String the converted value string.
	 */
	private String getString(long value) {
		String str = Long.toHexString(value);
		return zeros.substring(0, 4 - str.length()) + str;
	}

	/**
	 * @see ghidra.program.model.address.Address#toString(String)
	 */
	@Override
	public String toString(String prefix) {
		return prefix + getString(segment) + SEPARATOR_CHAR + getString(getSegmentOffset());
	}

	/**
	 * @see ghidra.program.model.address.Address#getPhysicalAddress()
	 */
	@Override
	public Address getPhysicalAddress() {
		return this;  // A segmented address is already a physical address.
	}

	@Override
	public String toString(boolean showAddressSpace, int minNumDigits) {
		String addr = getString(segment) + SEPARATOR_CHAR + getString(getSegmentOffset());
		if (showAddressSpace) {
			addr = addrSpace.getName() + SEPARATOR_CHAR + addr;
		}
		return addr;
	}

	/**
	 * @see ghidra.program.model.address.GenericAddress#next()
	 */
	/*
	@Override
	public Address next() {
		if ((offset & SegmentedAddressSpace.MASK) == SegmentedAddressSpace.MASK) {
			return null;
		}
		long newOffset = (offset + 1) & SegmentedAddressSpace.MASK;
		return new SegmentedAddress(addrSpace, newOffset).normalize(segment);
	}
	*/

	/**
	 * @see ghidra.program.model.address.GenericAddress#previous()
	 */
	/*
	@Override
	public Address previous() {
		if ((offset & SegmentedAddressSpace.MASK) == 0) {
			return null;
		}
		long newOffset = (offset - 1) & SegmentedAddressSpace.MASK;
		return new SegmentedAddress(addrSpace, newOffset).normalize(segment);
	}
	*/

}
