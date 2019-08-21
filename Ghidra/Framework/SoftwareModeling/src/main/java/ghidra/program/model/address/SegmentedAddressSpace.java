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

import org.apache.commons.lang3.StringUtils;

import ghidra.util.NumericUtilities;

/**
 * Address Space for dealing with Intel 20 bit segmented addresses.
 */
public class SegmentedAddressSpace extends GenericAddressSpace {

	private final static int SIZE = 21;

	/**
	 * Constructs a new Segmented AddressSpace.
	 * @param name is the name of the space
	 * @param unique is the unique id for the space.
	 */
	public SegmentedAddressSpace(String name, int unique) {
		super(name, SIZE, TYPE_RAM, unique);
		maxOffset = 0x10FFEF;
		spaceSize = maxOffset + 1;
		maxAddress = getUncheckedAddress(maxOffset);
	}

	/**
	 * Given a 16-bit segment and an offset, produce the flat address offset
	 * @param segment is the segment value
	 * @param offset is the 16-bit offset into the segment
	 * @return the encoded flat offset
	 */
	protected long getFlatOffset(int segment, long offset) {
		long res = segment;
		res <<= 4;
		res += offset;
		return res;
	}

	/**
	 * Given a flat address offset, extract the 16-bit segment portion
	 * @param flat is the flat offset
	 * @return the segment value
	 */
	protected int getSegmentFromFlat(long flat) {
		if (flat > 0xFFFFFL) {
			return 0xFFFF;
		}
		return (int) ((flat >> 4) & 0xF000);
	}

	/**
	 * Given a flat address offset, extract the offset portion
	 * @param flat is the flat offset
	 * @return the offset value
	 */
	protected long getOffsetFromFlat(long flat) {
		if (flat > 0xFFFFFL) {
			return flat - 0xFFFF0;
		}
		return flat & 0xFFFFL;
	}

	/**
	 * Given a flat address offset and a preferred segment, try
	 * to create an address that maps to the offset and is in the segment. For
	 * architectures like x86 real-mode, multiple address encodings can map to
	 * the same flat address offset.  This method tries to select between the different
	 * encodings.  If the flat offset cannot be encoded with the preferred segment,
	 * null is returned.
	 * 
	 * @param flat is the flat offset
	 * @param preferredSegment is the 16-bit preferred segment value
	 * @return the segment encoded address or null
	 */
	protected SegmentedAddress getAddressInSegment(long flat, int preferredSegment) {
		if ((preferredSegment << 4) <= flat) {
			int off = (int) (flat - (preferredSegment << 4));
			if (off <= 0xffff) {
				return new SegmentedAddress(this, preferredSegment, off);
			}
		}
		return null;
	}

	/**
	 * 
	 * @see ghidra.program.model.address.AddressSpace#getAddress(java.lang.String)
	 */
	@Override
	public Address getAddress(String addrString) throws AddressFormatException {
		return getAddress(addrString, true);
	}

	@Override
	public Address getAddress(String addrString, boolean caseSensitive)
			throws AddressFormatException {

		int colonPos = addrString.indexOf(':');

		if (colonPos >= 0) {
			String addrSpaceStr = addrString.substring(0, colonPos);
			String offStr = addrString.substring(colonPos + 1);
			if (StringUtils.equals(getName(), addrSpaceStr)) {
				colonPos = offStr.indexOf(':');
				if (colonPos >= 0) {
					String segString = offStr.substring(0, colonPos);
					offStr = offStr.substring(colonPos + 1);
					return parseSegmented(segString, offStr);
				}
				return parseNonSegmented(offStr);
			}
			return parseSegmented(addrSpaceStr, offStr);
		}

		return parseNonSegmented(addrString);

	}

	/**
	 * 
	 * @see ghidra.program.model.address.AddressSpace#subtract(ghidra.program.model.address.Address,
	 *      long)
	 */
	@Override
	public Address subtract(Address addr, long displacement) {

		if (displacement < 0) {
			return add(addr, -displacement);
		}

		testAddressSpace(addr);
		if (displacement > spaceSize) {
			throw new AddressOutOfBoundsException(
				"Address Overflow in subtract: " + addr + " + " + displacement);
		}
		long off = addr.getOffset() - displacement;
		if (off >= 0) {
			SegmentedAddress saddr = (SegmentedAddress) addr;
			Address resaddr = getAddressInSegment(off, saddr.getSegment());
			if (resaddr == null) {	// Could not map into desired segment
				resaddr = new SegmentedAddress(this, off);	// just use default
			}
			return resaddr;
		}
		throw new AddressOutOfBoundsException(
			"Address Overflow in subtract: " + addr + " + " + displacement);
	}

	/**
	 * 
	 * @see ghidra.program.model.address.AddressSpace#add(ghidra.program.model.address.Address,
	 *      long)
	 */
	@Override
	public Address add(Address addr, long displacement) {

		if (displacement < 0) {
			return subtract(addr, -displacement);
		}

		testAddressSpace(addr);
		if (displacement > spaceSize) {
			throw new AddressOutOfBoundsException(
				"Address Overflow in add: " + addr + " + " + displacement);
		}
		long off = addr.getOffset() + displacement;
		//if ((off & MASK) == off) {
		if (off >= 0 && off <= maxOffset) {
			SegmentedAddress saddr = (SegmentedAddress) addr;
			Address resaddr = getAddressInSegment(off, saddr.getSegment());
			if (resaddr == null) {	// Could not map into desired segment
				resaddr = new SegmentedAddress(this, off);	// just use default
			}
			return resaddr;
		}
		throw new AddressOutOfBoundsException(
			"Address Overflow in add: " + addr + " + " + displacement);
	}

	private long parseString(String addr) {
		if (addr.startsWith("0x") || addr.startsWith("0X")) {
			return NumericUtilities.parseHexLong(addr.substring(2));
		}
		return NumericUtilities.parseHexLong(addr);
	}

	private SegmentedAddress parseNonSegmented(String offStr) throws AddressFormatException {

		try {
			long off = (int) parseString(offStr);
			return new SegmentedAddress(this, off);
		}
		catch (NumberFormatException e) {
			throw new AddressFormatException("Cannot parse (" + offStr + ") as a number.");
		}
		catch (AddressOutOfBoundsException e) {
			throw new AddressFormatException(e.getMessage());
		}
	}

	private SegmentedAddress parseSegmented(String segStr, String offStr)
			throws AddressFormatException {
		int seg = -1;
		try {
			seg = (int) parseString(segStr);
		}
		catch (NumberFormatException e) {
			return null;
		}

		int off = -1;
		try {
			off = (int) parseString(offStr);
		}
		catch (NumberFormatException e) {
			throw new AddressFormatException(
				"Cannot parse (" + segStr + ':' + offStr + ") as a number.");
		}

		try {
			return getAddress(seg, off);
		}
		catch (AddressOutOfBoundsException e) {
			throw new AddressFormatException(e.getMessage());
		}
	}

	/**
	 * @see ghidra.program.model.address.AddressSpace#getAddress(long)
	 */
	@Override
	public SegmentedAddress getAddress(long byteOffset) {
		return new SegmentedAddress(this, byteOffset);
	}

	/**
	 * @see ghidra.program.model.address.AddressSpace#getAddressInThisSpaceOnly(long)
	 */
	@Override
	public SegmentedAddress getAddressInThisSpaceOnly(long byteOffset) {
		return new SegmentedAddress(this, byteOffset);
	}

	/**
	 * @see ghidra.program.model.address.AbstractAddressSpace#getUncheckedAddress(long)
	 */
	@Override
	protected SegmentedAddress getUncheckedAddress(long byteOffset) {
		return new SegmentedAddress(byteOffset, this);
	}

	/**
	 * Generates a segmented address with the given segment, offset, and overlay id.
	 * @param segment        the segment
	 * @param segmentOffset  the offset in the segment
	 * @return SegmentedAddress the newly created segmented address.
	 */
	public SegmentedAddress getAddress(int segment, int segmentOffset) {
		if (segmentOffset > 0xffff) {
			throw new AddressOutOfBoundsException("Offset is too large.");
		}
		if (segment > 0xffff) {
			throw new AddressOutOfBoundsException("Segment is too large.");
		}
		return new SegmentedAddress(this, segment, segmentOffset);
	}

	/**
	 * 
	 * @see ghidra.program.model.address.AddressSpace#getPhysicalSpace()
	 */
	@Override
	public SegmentedAddressSpace getPhysicalSpace() {
		return this;
	}

	/**
	 * @see ghidra.program.model.address.AddressSpace#getPointerSize()
	 */
	@Override
	public int getPointerSize() {
		return 2;
	}
}
