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
 * Address class for dealing with (intel) segmented addresses.  The class itself is agnostic
 * about the mapping from segmented encoding to flat address offset, it uses the
 * SegmentedAddressSpace to perform this mapping. So the same class can be used to represent
 * either a real-mode address or a protected-mode address.  The class uses the underlying
 * offset field to hold the flat encoding.
 */
public class SegmentedAddress extends GenericAddress {

	private final int segment;		// The specific segment value associated with this address

	/**
	 * Constructor for SegmentedAddress.
	 * Offset is not validated against address space.
	 * @param addrSpace is the address space for this address
	 * @param flat is the flat offset into the space
	 */
	SegmentedAddress(long flat, SegmentedAddressSpace addrSpace) {
		super(adjustOffset(flat, addrSpace), addrSpace);
		segment = addrSpace.getDefaultSegmentFromFlat(flat);
	}

	/**
	 * Constructor for SegmentedAddress.
	 * @param addrSpace is the address space for this address
	 * @param segment is the segment number
	 * @param segmentOffset is the offset into the segment
	 * @throws AddressOutOfBoundsException if the  address does not fit in the space
	 */
	SegmentedAddress(SegmentedAddressSpace addrSpace, int segment, int segmentOffset)
			throws AddressOutOfBoundsException {
		super(addrSpace, addrSpace.getFlatOffset(segment, segmentOffset));
		this.segment = segment;
	}

	/**
	 * Constructor for SegmentedAddress.
	 * @param addrSpace address space for this address
	 * @param flat is the flat offset into the space
	 * @throws AddressOutOfBoundsException if the flat address does not fit in the space
	 */
	SegmentedAddress(SegmentedAddressSpace addrSpace, long flat)
			throws AddressOutOfBoundsException {
		super(addrSpace, adjustOffset(flat, addrSpace));
		segment = addrSpace.getDefaultSegmentFromFlat(flat);
	}

	private static long adjustOffset(long flat, SegmentedAddressSpace addrSpace) {
		int seg = addrSpace.getDefaultSegmentFromFlat(flat);
		long offset = addrSpace.getDefaultOffsetFromFlat(flat);
		return addrSpace.getFlatOffset(seg, offset);
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
	 * @return the offset value
	 */
	public int getSegmentOffset() {
		return (int) ((SegmentedAddressSpace) addrSpace).getOffsetFromFlat(offset, segment);
	}

	/**
	 * Returns a new address that is equivalent to this address using
	 * the given segment number.
	 * @param seg the seqment value to normalize to.
	 * @return the new address
	 */
	public SegmentedAddress normalize(int seg) {
		SegmentedAddress res = ((SegmentedAddressSpace) addrSpace).getAddressInSegment(offset, seg);
		if (res == null) {
			return this;
		}
		return res;
	}

	/**
	 * Return a new segmented address. An attempt is made to normalize to this addresses segment.
	 * @see ghidra.program.model.address.Address#getNewAddress(long)
	 */
	@Override
	public Address getNewAddress(long byteOffset) {
		SegmentedAddressSpace segSpace = (SegmentedAddressSpace) addrSpace;
		SegmentedAddress res = segSpace.getAddressInSegment(byteOffset, segment);
		if (res == null) {
			return segSpace.getAddress(byteOffset);
		}
		return res;
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
}
