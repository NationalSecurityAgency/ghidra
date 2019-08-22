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
 * Address Space for dealing with (intel) segmented address spaces.
 * It understands the mapping between the segmented encoding (seg:offset) and
 * the flat address encoding necessary to produce an Address object that can be
 * used by other analyses.  This mapping is inherent in protected methods:
 *   - getDefaultOffsetFromFlat
 *   - getDefaultSegmentFromFlat
 *   - getFlatOffset
 *   - getOffsetFromFlat
 *   - getAddressInSegment
 * 
 * These 5 methods can be overridden to get a different mapping. This base class is
 * set up to map as for x86 16-bit real-mode.
 */
public class SegmentedAddressSpace extends GenericAddressSpace {

	private final static int REALMODE_SIZE = 21;
	private final static long REALMODE_MAXOFFSET = 0x10FFEF;

	/**
	 * Constructor for larger size address spaces (than the real-mode space)
	 * @param name is the name of the space
	 * @param size is the number of bits in a (flat) address
	 * @param unique is the unique id for the space
	 */
	protected SegmentedAddressSpace(String name, int size, int unique) {
		super(name, size, TYPE_RAM, unique);
//		maxAddress = getUncheckedAddress(maxOffset);
		// Constructors for derived classes that call this will
		// need to reconstruct maxAddress themselves.
	}

	/**
	 * Constructs a new Segmented AddressSpace for x86 real-mode, with 21-bit addresses.
	 * @param name is the name of the space
	 * @param unique is the unique id for the space.
	 */
	public SegmentedAddressSpace(String name, int unique) {
		super(name, REALMODE_SIZE, TYPE_RAM, unique);
		maxOffset = REALMODE_MAXOFFSET;
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
	 * Given a flat address offset, extract the default 16-bit segment portion
	 * @param flat is the flat offset
	 * @return the segment value
	 */
	protected int getDefaultSegmentFromFlat(long flat) {
		if (flat > 0xFFFFFL) {
			return 0xFFFF;
		}
		return (int) ((flat >> 4) & 0xF000);
	}

	/**
	 * Given a flat address offset, extract the offset portion assuming the
	 * default segment.
	 * @param flat is the flat offset
	 * @return the offset value
	 */
	protected long getDefaultOffsetFromFlat(long flat) {
		if (flat > 0xFFFFFL) {
			return flat - 0xFFFF0;
		}
		return flat & 0xFFFFL;
	}

	/**
	 * Given a flat address offset, extract a segment offset assuming a
	 * specific segment value.
	 * @param flat is the flat offset
	 * @param segment is the specific segment value
	 * @return the segment offset
	 */
	protected long getOffsetFromFlat(long flat, int segment) {
		return flat - (segment << 4);
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
	 * Get the segment index for the first segment whose start address
	 * comes after the given address
	 * @param addr is the given address
	 * @return the segment index
	 */
	public int getNextOpenSegment(Address addr) {
		int res = (int) addr.getOffset();	// The "flat" offset (presumably real-mode encoded)
		res = (res >> 4) + 1;
		return res;
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
